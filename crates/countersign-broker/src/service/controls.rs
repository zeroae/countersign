use super::*;
use axum::{Json, extract::State, http::HeaderMap};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CloseContext {
    user: w::Id,
    context: w::Id,
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Control {
    Account {
        user: w::Id,
        blocked: bool,
    },
    Destination {
        user: w::Id,
        entry: w::Id,
        denied: bool,
    },
    Issuer {
        stopped: bool,
    },
    Emergency {
        stopped: bool,
    },
}

#[derive(Default)]
struct Filter<'a> {
    user: Option<&'a str>,
    context: Option<&'a str>,
    entry: Option<&'a str>,
    pairing: Option<&'a str>,
    workload: Option<(&'a str, i64)>,
}

fn retire(
    tx: &rusqlite::Transaction<'_>,
    integrator: &str,
    filter: Filter<'_>,
    kind: &str,
) -> Result<Vec<String>> {
    let mut query=tx.prepare("SELECT a.id FROM approval a WHERE integrator=?1 AND state IN ('pending','approved')
        AND (?2 IS NULL OR owner=?2) AND (?3 IS NULL OR context=?3) AND (?4 IS NULL OR entry_id=?4)
        AND (?6 IS NULL OR (workload=?6 AND workload_generation=?7))
        AND (?5 IS NULL OR EXISTS(SELECT 1 FROM approved_grant g JOIN offer o ON o.id=g.offer WHERE g.approval=a.id AND o.pairing=?5))")?;
    let affected = query
        .query_map(
            params![
                integrator,
                filter.user,
                filter.context,
                filter.entry,
                filter.pairing,
                filter.workload.map(|w| w.0),
                filter.workload.map(|w| w.1)
            ],
            |r| r.get::<_, String>(0),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for id in &affected {
        tx.execute("UPDATE approval SET state='cancelled' WHERE id=?1", [id])?;
        let event = Uuid::new_v4().to_string();
        tx.execute(
            "INSERT INTO audit(event_id,approval,kind,occurred_at) VALUES (?1,?2,?3,unixepoch())",
            params![event, id, kind],
        )?;
        tx.execute(
            "INSERT INTO outbox(event_id,approval) VALUES(?1,?2)",
            params![event, id],
        )?;
    }
    Ok(affected)
}
pub(super) fn withdraw(a: &mut Authority, owner: &Owner, affected: Vec<Uuid>) {
    clear_live(a, &affected.iter().map(Uuid::to_string).collect::<Vec<_>>());
    for id in affected {
        a.notify(&owner.user, wire_id(id));
    }
}
pub(super) fn clear_live(a: &mut Authority, affected: &[String]) {
    let ids: std::collections::HashSet<_> = affected.iter().map(String::as_str).collect();
    a.grants.retain(|_, g| {
        if !ids.contains(g.activation.approval.as_str()) {
            return true;
        }
        if let Some(peer) = a.peers.get(g.activation.grant.device.pairing.as_str()) {
            let _ = send(
                peer,
                fresh(),
                w::BrokerToCompanion::Retire(g.activation.grant.clone()),
            );
        }
        false
    });
    a.waiting
        .retain(|_, v| a.grants.contains_key(v.op.grant.grant.as_str()));
}
pub(super) fn retire_generation(
    tx: &rusqlite::Transaction<'_>,
    binding: &w::WorkloadBinding,
    generation: i64,
) -> Result<Vec<String>> {
    retire(
        tx,
        binding.integrator.as_str(),
        Filter {
            user: Some(binding.user.as_str()),
            context: Some(binding.context.as_str()),
            workload: Some((binding.workload.as_str(), generation)),
            ..Default::default()
        },
        "workload_retired",
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RetireWorkload {
    binding: w::WorkloadBinding,
}

pub(super) async fn retire_workload(
    State(s): State<Service>,
    h: HeaderMap,
    Json(req): Json<RetireWorkload>,
) -> Result<StatusCode> {
    backend::auth(&s, &h)?;
    s.apply(move |a| {
        let b=req.binding;
        if b.integrator!=a.integrator { return Err(Fault::Denied); }
        let generation=i64::try_from(b.workload_generation.get()).map_err(|_|Fault::Invalid)?;
        let tx=a.store.connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let n=tx.execute("UPDATE workload_binding SET retired=1 WHERE integrator=?1 AND owner=?2 AND context=?3 AND instance=?4 AND generation=?5",
            params![b.integrator.as_str(),b.user.as_str(),b.context.as_str(),b.workload.as_str(),generation])?;
        if n!=1 { return Err(Fault::Unavailable); }
        let ids=retire_generation(&tx, &b, generation)?;
        tx.commit()?;
        clear_live(a,&ids);
        Ok(StatusCode::NO_CONTENT)
    }).await
}
pub(super) async fn close_context(
    State(s): State<Service>,
    h: HeaderMap,
    Json(req): Json<CloseContext>,
) -> Result<StatusCode> {
    backend::auth(&s, &h)?;
    s.apply(move |a| {
        let tx = a
            .store
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT OR IGNORE INTO closed_context VALUES (?1,?2,?3)",
            params![
                a.integrator.as_str(),
                req.user.as_str(),
                req.context.as_str()
            ],
        )?;
        let affected = retire(
            &tx,
            a.integrator.as_str(),
            Filter {
                user: Some(req.user.as_str()),
                context: Some(req.context.as_str()),
                ..Default::default()
            },
            "context_closed",
        )?;
        tx.commit()?;
        clear_live(a, &affected);
        Ok(StatusCode::NO_CONTENT)
    })
    .await
}
pub(super) async fn admin(
    State(s): State<Service>,
    h: HeaderMap,
    Json(control): Json<Control>,
) -> Result<StatusCode> {
    if !s
        .credentials
        .admin_authorized(backend::bearer(&h)?.as_bytes())
    {
        return Err(Fault::Unauthenticated);
    }
    s.apply(move |a| {
        if let Control::Destination {entry,..} = &control
            && !a.policy.entries().iter().any(|e|e.id()==entry.as_str()) {
            return Err(Fault::Invalid);
        }
        let tx = a.store.connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let integrator = a.integrator.as_str();
        let (filter, kind) = match &control {
            Control::Account { user, blocked } => {
                let args = params![integrator, user.as_str()];
                if *blocked {
                    tx.execute("INSERT OR IGNORE INTO suspended_user VALUES(?1,?2)",args)?;
                } else {
                    tx.execute("DELETE FROM suspended_user WHERE integrator=?1 AND owner=?2",args)?;
                }
                (Filter {user:Some(user.as_str()),..Default::default()},if *blocked{"account_blocked"}else{"account_enabled"})
            }
            Control::Destination { user, entry, denied } => {
                let args = params![integrator,user.as_str(),entry.as_str()];
                if *denied {
                    tx.execute("INSERT OR IGNORE INTO denied_destination VALUES(?1,?2,?3)",args)?;
                } else {
                    tx.execute("DELETE FROM denied_destination WHERE integrator=?1 AND owner=?2 AND entry_id=?3",args)?;
                }
                (Filter{user:Some(user.as_str()),entry:Some(entry.as_str()),..Default::default()}, if *denied{"destination_denied"}else{"destination_permitted"})
            }
            Control::Issuer { stopped } => {
                if *stopped {
                    tx.execute("INSERT OR IGNORE INTO issuer_stop VALUES(?1)", [integrator])?;
                } else {
                    tx.execute("DELETE FROM issuer_stop WHERE integrator=?1", [integrator])?;
                }
                (Filter::default(),if *stopped{"issuer_stopped"}else{"issuer_enabled"})
            }
            Control::Emergency { stopped } => {
                if *stopped {
                    tx.execute("INSERT OR IGNORE INTO emergency_stop VALUES(?1)",[integrator])?;
                } else {
                    tx.execute("DELETE FROM emergency_stop WHERE integrator=?1",[integrator])?;
                }
                (Filter::default(),if *stopped{"emergency_stop"}else{"emergency_cleared"})
            }
        };
        tx.execute("INSERT INTO security_event(id,integrator,owner,kind,actor,target,occurred_at_ms) VALUES(?1,?2,?3,?4,'admin',?5,?6)",
            params![Uuid::new_v4().to_string(),integrator,filter.user,kind,filter.entry,clock_ms()? as i64])?;
        let withdraw = match control {
            Control::Account{blocked, ..} => blocked,
            Control::Destination{denied,..} => denied,
            Control::Issuer{stopped}|Control::Emergency{stopped} => stopped,
        };
        let affected = if withdraw { retire(&tx, integrator,filter,kind)? } else { Vec::new() };
        tx.commit()?;
        clear_live(a,&affected);
        Ok(StatusCode::NO_CONTENT)
    }).await
}

fn device_list(a: &Authority, user: &str) -> Result<w::Devices> {
    let mut stmt=a.store.connection.prepare("SELECT e.pairing,e.key_id,d.generation,p.connected_at,p.address FROM enrollment e
        JOIN device d ON d.integrator=e.integrator AND d.owner=e.user_id AND d.pairing=e.pairing AND d.key_id=e.key_id
        JOIN presence p ON p.pairing=e.pairing WHERE e.integrator=?1 AND e.user_id=?2 ORDER BY e.pairing")?;
    let devices = stmt
        .query_map(params![a.integrator.as_str(), user], |r| {
            let pairing: String = r.get(0)?;
            let key: String = r.get(1)?;
            let generation: i64 = r.get(2)?;
            Ok(w::DevicePresence {
                connected: a.peers.contains_key(&pairing),
                binding: w::DeviceBinding {
                    pairing: w::Id::new(pairing).map_err(|_| rusqlite::Error::InvalidQuery)?,
                    key: w::Id::new(key).map_err(|_| rusqlite::Error::InvalidQuery)?,
                    channel_generation: NonZeroU64::new(generation as u64)
                        .ok_or(rusqlite::Error::InvalidQuery)?,
                },
                connected_at_ms: r.get::<_, i64>(3)? as u64,
                observed_address: r.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(w::Devices { devices })
}
pub(super) fn devices(a: &Authority, who: &w::DeviceBinding) -> Result<w::Devices> {
    let peer = a
        .peers
        .get(who.pairing.as_str())
        .filter(|p| p.binding == *who)
        .ok_or(Fault::Denied)?;
    device_list(a, &peer.session.owner.user)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Account {
    user: w::Id,
}
pub(super) async fn list_devices(
    State(s): State<Service>,
    h: HeaderMap,
    Json(req): Json<Account>,
) -> Result<Json<w::Devices>> {
    backend::auth(&s, &h)?;
    s.apply(move |a| Ok(Json(device_list(a, req.user.as_str())?)))
        .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Unpair {
    user: w::Id,
    targets: Vec<w::DeviceBinding>,
}
pub(super) async fn forget_api(
    State(s): State<Service>,
    h: HeaderMap,
    Json(req): Json<Unpair>,
) -> Result<Json<w::Devices>> {
    backend::auth(&s, &h)?;
    s.apply(move |a| {
        Ok(Json(forget(
            a,
            req.user.as_str(),
            None,
            w::ForgetDevices {
                targets: req.targets,
                all_others: false,
            },
        )?))
    })
    .await
}
pub(super) fn forget(
    a: &mut Authority,
    user: &str,
    who: Option<&w::DeviceBinding>,
    request: w::ForgetDevices,
) -> Result<w::Devices> {
    let available = device_list(a, user)?;
    if request.targets.is_empty() || request.targets.len() > 64 {
        return Err(Fault::Invalid);
    }
    let mut names = std::collections::HashSet::new();
    for t in &request.targets {
        if who == Some(t)
            || !available.devices.iter().any(|d| d.binding == *t)
            || !names.insert(t.pairing.as_str())
        {
            return Err(Fault::Denied);
        }
    }
    if request.all_others
        && available
            .devices
            .iter()
            .any(|d| Some(&d.binding) != who && !names.contains(d.binding.pairing.as_str()))
    {
        return Err(Fault::Resolved);
    }
    let mut affected = Vec::new();
    let event = fresh();
    let actor_address = available
        .devices
        .iter()
        .find(|d| Some(&d.binding) == who)
        .and_then(|d| d.observed_address.as_deref());
    let tx = a
        .store
        .connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    for t in &request.targets {
        affected.extend(retire(
            &tx,
            a.integrator.as_str(),
            Filter {
                user: Some(user),
                pairing: Some(t.pairing.as_str()),
                ..Default::default()
            },
            "pairing_forgotten",
        )?);
        let n=tx.execute("DELETE FROM enrollment WHERE pairing=?1 AND key_id=?2 AND integrator=?3 AND user_id=?4
           AND EXISTS(SELECT 1 FROM device WHERE integrator=?3 AND owner=?4 AND pairing=?1 AND key_id=?2 AND generation=?5)",
           params![t.pairing.as_str(),t.key.as_str(),a.integrator.as_str(),user,t.channel_generation.get() as i64])?;
        if n != 1 {
            return Err(Fault::Resolved);
        }
        tx.execute(
            "DELETE FROM device WHERE integrator=?1 AND owner=?2 AND pairing=?3",
            params![a.integrator.as_str(), user, t.pairing.as_str()],
        )?;
    }
    persist_notice(
        &tx,
        a.integrator.as_str(),
        user,
        &w::SecurityEvent {
            id: event.clone(),
            kind: "devices_forgotten".into(),
            actor: who.cloned(),
            targets: request.targets.clone(),
            occurred_at_ms: clock_ms()?,
            observed_address: actor_address.map(str::to_owned),
        },
    )?;
    tx.commit()?;
    clear_live(a, &affected);
    a.notify(user, event);
    for t in &request.targets {
        a.peers.remove(t.pairing.as_str());
        a.waiting
            .retain(|_, op| op.op.grant.device.pairing != t.pairing);
    }
    device_list(a, user)
}
fn persist_notice(
    c: &rusqlite::Connection,
    integrator: &str,
    user: &str,
    e: &w::SecurityEvent,
) -> Result<()> {
    let actor = e
        .actor
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|_| Fault::Invalid)?;
    c.execute("INSERT INTO security_event(id,integrator,owner,kind,actor,target,observed_address,occurred_at_ms)
      VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
      params![e.id.as_str(),integrator,user,e.kind,actor,serde_json::to_string(&e.targets).map_err(|_|Fault::Invalid)?,e.observed_address,
         e.occurred_at_ms as i64])?;
    Ok(())
}
pub(super) fn record_connection(
    tx: &rusqlite::Transaction<'_>,
    owner: &Owner,
    device: &w::DeviceBinding,
    address: Option<String>,
    others: Vec<w::DeviceBinding>,
    paired: bool,
    at: u64,
) -> Result<Option<w::Id>> {
    tx.execute(
        "INSERT INTO presence(pairing,connected_at,address) VALUES(?1,?2,?3)
         ON CONFLICT(pairing) DO UPDATE SET connected_at=excluded.connected_at,address=excluded.address",
        params![device.pairing.as_str(), at as i64, address],
    )?;
    persist_notice(
        tx,
        &owner.integrator,
        &owner.user,
        &w::SecurityEvent {
            id: fresh(),
            kind: if paired { "paired" } else { "reconnected" }.into(),
            actor: Some(device.clone()),
            targets: Vec::new(),
            occurred_at_ms: at,
            observed_address: address.clone(),
        },
    )?;
    if others.is_empty() {
        return Ok(None);
    }
    let id = fresh();
    persist_notice(
        tx,
        &owner.integrator,
        &owner.user,
        &w::SecurityEvent {
            id: id.clone(),
            kind: "concurrent_devices".into(),
            actor: Some(device.clone()),
            targets: others,
            occurred_at_ms: at,
            observed_address: address,
        },
    )?;
    Ok(Some(id))
}
pub(super) fn fetch_event(
    a: &Authority,
    user: &str,
    id: &w::Id,
) -> Result<Option<w::SecurityEvent>> {
    let row=a.store.connection.query_row("SELECT kind,actor,target,observed_address,occurred_at_ms FROM security_event WHERE id=?1
        AND integrator=?2 AND owner=?3 AND kind IN ('concurrent_devices','devices_forgotten','credential_used_on_multiple_devices')",
        params![id.as_str(),a.integrator.as_str(),user],|r|Ok((r.get::<_,String>(0)?,r.get::<_,Option<String>>(1)?,
            r.get::<_,String>(2)?,r.get::<_,Option<String>>(3)?,r.get::<_,i64>(4)?))).optional()?;
    row.map(|(kind, actor, targets, address, at)| {
        Ok(w::SecurityEvent {
            id: id.clone(),
            kind,
            actor: actor
                .map(|s| serde_json::from_str(&s))
                .transpose()
                .map_err(|_| Fault::Storage)?,
            targets: serde_json::from_str(&targets).map_err(|_| Fault::Storage)?,
            occurred_at_ms: at as u64,
            observed_address: address,
        })
    })
    .transpose()
}

pub(super) fn certificate_revoked(a: &mut Authority, b: &w::GrantBinding) -> Result<()> {
    let tx = a
        .store
        .connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let ids=tx.prepare("SELECT a.id FROM approval a JOIN approved_grant g ON g.approval=a.id
        WHERE a.integrator=?1 AND a.entry_id=?2 AND a.entry_version=?3 AND a.state='approved' AND a.current=1
        AND g.certificate=?4")?.query_map(params![b.workload.integrator.as_str(),b.scope.entry_id(),b.scope.entry_version() as i64,b.cert_sha256.as_slice()],
        |r|r.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
    for id in &ids {
        tx.execute("UPDATE approval SET state='cancelled' WHERE id=?1", [id])?;
        let event = fresh();
        tx.execute("INSERT INTO audit(event_id,approval,kind,occurred_at) VALUES (?1,?2,'certificate_revoked',unixepoch())",params![event.as_str(),id])?;
        tx.execute(
            "INSERT INTO outbox(event_id,approval) VALUES (?1,?2)",
            params![event.as_str(), id],
        )?;
    }
    tx.commit()?;
    clear_live(a, &ids);
    Ok(())
}

pub(super) fn signature_observed(a: &mut Authority, b: &w::GrantBinding) -> Result<()> {
    let at = clock_ms()?;
    let user = b.workload.user.as_str();
    let tx = a
        .store
        .connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let args = params![
        a.integrator.as_str(),
        user,
        b.cert_sha256.as_slice(),
        b.device.pairing.as_str(),
        b.device.key.as_str(),
        b.device.channel_generation.get() as i64,
        at as i64
    ];
    let changed = tx.execute(
        "INSERT OR IGNORE INTO credential_use VALUES (?1,?2,?3,?4,?5,?6,?7)",
        args,
    )?;
    if changed == 0 {
        tx.execute("UPDATE credential_use SET generation=?6,observed_at_ms=?7 WHERE integrator=?1 AND owner=?2
            AND fingerprint=?3 AND pairing=?4 AND key_id=?5",args)?;
        tx.commit()?;
        return Ok(());
    }
    let others = tx
        .prepare(
            "SELECT pairing,key_id,generation FROM credential_use WHERE integrator=?1 AND owner=?2
        AND fingerprint=?3 AND pairing<>?4 ORDER BY observed_at_ms DESC LIMIT 64",
        )?
        .query_map(
            params![
                a.integrator.as_str(),
                user,
                b.cert_sha256.as_slice(),
                b.device.pairing.as_str()
            ],
            |r| {
                let id = |name: &str| {
                    w::Id::new(r.get::<_, String>(name)?).map_err(|_| rusqlite::Error::InvalidQuery)
                };
                Ok(w::DeviceBinding {
                    pairing: id("pairing")?,
                    key: id("key_id")?,
                    channel_generation: NonZeroU64::new(r.get::<_, i64>("generation")? as u64)
                        .ok_or(rusqlite::Error::InvalidQuery)?,
                })
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let id = fresh();
    if !others.is_empty() {
        let address = tx
            .query_row(
                "SELECT address FROM presence WHERE pairing=?1",
                [b.device.pairing.as_str()],
                |r| r.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        persist_notice(
            &tx,
            a.integrator.as_str(),
            user,
            &w::SecurityEvent {
                id: id.clone(),
                kind: "credential_used_on_multiple_devices".into(),
                actor: Some(b.device.clone()),
                targets: others,
                observed_address: address,
                occurred_at_ms: at,
            },
        )?;
        tx.commit()?;
        a.notify(user, id);
    } else {
        tx.commit()?;
    }
    Ok(())
}
