//! Fencing, expiry and retention for the single-authority SQLite service.
use super::*;
use std::{
    fs::{File, OpenOptions},
    path::Path,
    time::Duration,
};

fn private_file(path: &Path) -> std::io::Result<File> {
    let mut open = OpenOptions::new();
    open.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.mode(0o600);
    }
    open.open(path)
}

pub(super) fn lock_database(path: &Path) -> std::result::Result<File, Box<dyn Error>> {
    let lock = private_file(&path.with_added_extension("broker.lock"))?;
    lock.try_lock()
        .map_err(|_| "another Broker owns this database")?;
    private_file(path)?;
    Ok(lock)
}

pub(super) fn fence_boot(
    store: &mut SqliteApprovalStore,
    integrator: &str,
    origin: &Origin,
    recover: bool,
) -> Result<()> {
    let tx = store
        .connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    tx.execute(
        "INSERT OR IGNORE INTO deployment(singleton,integrator,verified_origin) VALUES(1,?1,?2)",
        params![integrator, origin.to_string()],
    )?;
    let bound: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM deployment WHERE singleton=1 AND integrator=?1 AND verified_origin=?2)",
        params![integrator,origin.to_string()],|r|r.get(0))?;
    if !bound {
        return Err(Fault::Denied);
    }
    let at = clock_ms()? / 1000;
    let affected = tx
        .prepare("SELECT id FROM approval WHERE integrator=?1 AND state IN ('approved','pending')")?
        .query_map([integrator], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for id in affected {
        tx.execute("UPDATE approval SET state='cancelled' WHERE id=?1", [&id])?;
        crate::sqlite::record_event(
            &tx,
            Uuid::parse_str(&id).map_err(|_| Fault::Storage)?,
            None,
            "restart",
            at as i64,
        )?;
    }
    if recover {
        // Saved media can predate a device revocation. Forego every saved
        // pairing and require fresh enrollment after administrator review.
        tx.execute("DELETE FROM enrollment WHERE integrator=?1", [integrator])?;
        tx.execute("DELETE FROM device WHERE integrator=?1", [integrator])?;
        tx.execute(
            "UPDATE workload_binding SET retired=1 WHERE integrator=?1",
            [integrator],
        )?;
        tx.execute("DELETE FROM push_subscription", [])?;
        tx.execute(
            "INSERT OR IGNORE INTO emergency_stop(integrator) VALUES (?1)",
            [integrator],
        )?;
        tx.execute(
            "INSERT INTO security_event(id,integrator,kind,actor,occurred_at_ms)
            VALUES(?1,?2,'backup_recovered','administrator',?3)",
            params![fresh().as_str(), integrator, clock_ms()? as i64],
        )?;
    }
    tx.commit()?;
    Ok(())
}

pub(super) fn start(state: &Arc<Mutex<Authority>>) {
    let weak = Arc::downgrade(state);
    tokio::spawn(async move {
        let mut clock = tokio::time::interval(Duration::from_secs(15));
        clock.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            clock.tick().await;
            let Some(state) = weak.upgrade() else { break };
            // Failed transactions roll back. Every authority path checks its
            // own deadlines, including while this maintenance task is delayed.
            let _ = tokio::task::spawn_blocking(move || -> Result<()> {
                let mut a = state.lock().map_err(|_| Fault::Storage)?;
                let at = clock_ms()?;
                a.prune(at);
                let integrator = a.integrator.clone();
                let days = a.audit_retention_days;
                clean(&mut a.store, integrator.as_str(), (at / 1000) as i64, days)
            })
            .await;
        }
    });
}

fn clean(
    store: &mut SqliteApprovalStore,
    integrator: &str,
    at: i64,
    days: NonZeroU32,
) -> Result<()> {
    let tx = store
        .connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let cutoff = at - i64::from(days.get()) * 86_400;
    let expired = tx.prepare("SELECT id FROM approval a WHERE integrator=?1 AND (
        (state='pending' AND pending_until<=?2) OR
        (state='approved' AND EXISTS(SELECT 1 FROM approved_grant g WHERE g.approval=a.id AND g.expires_at<=?2))
        ) LIMIT 512")?.query_map(params![integrator,at], |r| r.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
    for id in expired {
        tx.execute("UPDATE approval SET state='expired' WHERE id=?1", [&id])?;
        crate::sqlite::record_event(
            &tx,
            Uuid::parse_str(&id).map_err(|_| Fault::Storage)?,
            None,
            "expired",
            at,
        )?;
    }
    tx.execute(
        "DELETE FROM outbox WHERE event_id IN (SELECT e.event_id FROM audit e JOIN approval a
         ON a.id=e.approval WHERE a.integrator=?1 AND e.occurred_at<?2)",
        params![integrator, cutoff],
    )?;
    tx.execute("DELETE FROM audit WHERE approval IN (SELECT id FROM approval WHERE integrator=?1) AND occurred_at<?2",params![integrator,cutoff])?;
    tx.execute(
        "DELETE FROM security_event WHERE integrator=?1 AND occurred_at_ms<?2",
        params![integrator, cutoff.saturating_mul(1000)],
    )?;
    tx.execute(
        "DELETE FROM credential_use WHERE integrator=?1 AND observed_at_ms<?2",
        params![integrator, cutoff.saturating_mul(1000)],
    )?;
    // Keep active records and recent client retry information. A terminal
    // approval with no audit rows left only needs its scope and suppression.
    let aged = "SELECT a.id FROM approval a WHERE a.integrator=?1 AND a.state NOT IN ('pending','approved')
        AND a.pending_until<?2 AND NOT EXISTS (SELECT 1 FROM audit e WHERE e.approval=a.id)";
    for statement in [
        format!("DELETE FROM renewal WHERE request IN ({aged})"),
        format!("DELETE FROM decision WHERE offer IN (SELECT id FROM offer WHERE approval IN ({aged}))"),
        format!("DELETE FROM approved_grant WHERE approval IN ({aged})"),
        format!("DELETE FROM offer WHERE approval IN ({aged}) AND NOT EXISTS (SELECT 1 FROM audit WHERE actor_offer=offer.id)"),
        format!("DELETE FROM push_attempt WHERE approval IN ({aged})"),
        format!("DELETE FROM approval WHERE id IN ({aged}) AND NOT EXISTS(SELECT 1 FROM renewal WHERE predecessor=approval.id)
            AND NOT EXISTS(SELECT 1 FROM offer WHERE offer.approval=approval.id) AND
            (current=0 OR NOT EXISTS(SELECT 1 FROM workload_binding w WHERE w.integrator=approval.integrator
                AND w.owner=approval.owner AND w.context=approval.context AND w.instance=approval.workload
                AND w.generation=approval.workload_generation AND w.retired=0)
             OR EXISTS(SELECT 1 FROM closed_context c WHERE c.integrator=approval.integrator
                AND c.owner=approval.owner AND c.context=approval.context))")
    ] {
        tx.execute(&statement, params![integrator,cutoff])?;
    }
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ApprovalState, Trigger};
    use countersign_protocol::{ApprovalMode, DestinationEntry};

    #[test]
    fn backup_fencing_and_cleanup_preserve_only_live_suppression() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        let file_lock = lock_database(&path).unwrap();
        assert!(lock_database(&path).is_err());
        let mut db = SqliteApprovalStore::open(&path).unwrap();
        let owner = Owner {
            integrator: "site".into(),
            user: "user".into(),
        };
        let w = Workload {
            owner: owner.clone(),
            context: "job".into(),
            instance: "w".into(),
            generation: 1,
        };
        let host = Origin::parse("service.test:443").unwrap();
        let policy = DestinationPolicy::new(vec![
            DestinationEntry::new("protected", 1, "service.test:443", ApprovalMode::ExactHost)
                .unwrap(),
        ])
        .unwrap();
        db.connection
            .execute(
                "INSERT INTO workload_binding VALUES('site','user','job','w',1,0)",
                [],
            )
            .unwrap();
        let id = db
            .request(&w, &policy, &host, NonZeroU32::MIN, Trigger::Traffic)
            .unwrap()
            .id;
        let actor = db.authenticate_device(&owner, "pairing", "key").unwrap();
        let offer = db.offer(&actor, id).unwrap();
        db.connection
            .execute(
                "INSERT INTO enrollment VALUES('pairing','user','site','key',zeroblob(65))",
                [],
            )
            .unwrap();
        fence_boot(&mut db, "site", &host, false).unwrap();
        assert!(db.offer(&actor, id).is_err());
        assert!(fence_boot(&mut db, "other-site", &host, false).is_err());
        let replay = db
            .request(&w, &policy, &host, NonZeroU32::MIN, Trigger::Traffic)
            .unwrap();
        assert_eq!(replay.id, id);
        assert_eq!(replay.state, ApprovalState::Cancelled);
        let later = (clock_ms().unwrap() / 1000) as i64 + 10 * 86_400;
        clean(&mut db, "site", later, NonZeroU32::MIN).unwrap();
        let n = |sql: &str| {
            db.connection
                .query_row(sql, [], |r| r.get::<_, i64>(0))
                .unwrap()
        };
        assert_eq!(n("SELECT count(*) FROM audit"), 0);
        assert_eq!(n("SELECT count(*) FROM outbox"), 0);
        assert_eq!(n("SELECT count(*) FROM offer"), 0);
        assert_eq!(n("SELECT count(*) FROM approval"), 1);
        assert_ne!(offer.id, id);

        fence_boot(&mut db, "site", &host, true).unwrap();
        clean(&mut db, "site", later, NonZeroU32::MIN).unwrap();
        for table in ["device", "enrollment", "approval"] {
            assert_eq!(
                db.connection
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                        .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
        assert!(
            db.connection
                .query_row("SELECT retired FROM workload_binding", [], |r| r
                    .get::<_, bool>(0))
                .unwrap()
        );
        assert!(
            db.connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM emergency_stop WHERE integrator='site')",
                    [],
                    |r| r.get::<_, bool>(0)
                )
                .unwrap()
        );
        drop(file_lock);
        assert!(lock_database(&path).is_ok());
    }
}
