use crate::*;
use rusqlite::{Connection, OptionalExtension, Row, Transaction, TransactionBehavior, params};
use std::{path::Path, time::Duration};

const PENDING_SECONDS: i64 = 600;

pub struct SqliteApprovalStore {
    pub(crate) connection: Connection,
}

impl SqliteApprovalStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.pragma_update(None, "secure_delete", true)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version > 1 {
            return Err(StoreError::InvalidInput);
        }
        tx.execute_batch(include_str!("schema.sql"))?;
        if version == 0 {
            // Earlier preview databases stored socket evidence without
            // sequence numbers. Preserve the historical record but fence
            // these enforcers before accepting any renewal.
            let has_sequence:bool=tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('enforcer_issue') WHERE name='sequence')",
                [], |r|r.get(0),
            )?;
            if !has_sequence {
                tx.execute_batch("ALTER TABLE enforcer_issue ADD COLUMN generation INTEGER NOT NULL DEFAULT 1;
                     ALTER TABLE enforcer_issue ADD COLUMN sequence INTEGER NOT NULL DEFAULT 0;
                     ALTER TABLE enforcer_issue ADD COLUMN closed INTEGER NOT NULL DEFAULT 0 CHECK(closed IN (0,1));
                     UPDATE enforcer_issue SET closed=1,expires_at_ms=0;")?;
            }
            tx.pragma_update(None, "user_version", 1)?;
        }
        tx.commit()?;
        Ok(Self { connection })
    }
}

pub(crate) fn advance_device(
    connection: &Connection,
    owner: &Owner,
    pairing: &str,
    key: &str,
) -> Result<DeviceSession> {
    if owner.integrator.is_empty() || owner.user.is_empty() || pairing.is_empty() || key.is_empty()
    {
        return Err(StoreError::InvalidInput);
    }
    let generation = connection
        .query_row(
            "INSERT INTO device (integrator, owner, pairing, key_id, generation)
             VALUES (?1, ?2, ?3, ?4, 1)
             ON CONFLICT (integrator, owner, pairing) DO UPDATE SET generation = generation + 1
             WHERE key_id = excluded.key_id RETURNING generation",
            params![owner.integrator, owner.user, pairing, key],
            |r| r.get(0),
        )
        .optional()?
        .ok_or(StoreError::Unavailable)?;
    Ok(DeviceSession {
        owner: owner.clone(),
        pairing: pairing.into(),
        key: key.into(),
        generation,
    })
}

fn check_pending_capacity(tx: &Transaction<'_>, owner: &Owner, at: i64) -> Result<()> {
    let (by_user,total)=tx.query_row("SELECT COALESCE(SUM(integrator=?1 AND owner=?2),0), COUNT(*) FROM approval WHERE state='pending' AND pending_until>?3",
        params![owner.integrator,owner.user,at],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,i64>(1)?)))?;
    if by_user >= 128 || total >= 8192 {
        return Err(StoreError::Capacity);
    }
    Ok(())
}
fn now(tx: &Transaction<'_>) -> Result<i64> {
    Ok(tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?)
}

pub(crate) fn record_event(
    tx: &Transaction<'_>,
    approval: Uuid,
    actor_offer: Option<Uuid>,
    kind: &str,
    at: i64,
) -> Result<()> {
    let event = Uuid::new_v4().to_string();
    let approval = approval.to_string();
    tx.execute(
        "INSERT INTO audit (event_id, approval, actor_offer, kind, occurred_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            event,
            approval,
            actor_offer.map(|v| v.to_string()),
            kind,
            at
        ],
    )?;
    tx.execute(
        "INSERT INTO outbox (event_id, approval) VALUES (?1, ?2)",
        params![event, approval],
    )?;
    Ok(())
}

fn parse_id(row: &Row<'_>, column: &str) -> rusqlite::Result<Uuid> {
    let text: String = row.get(column)?;
    Uuid::parse_str(&text).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn load(tx: &Transaction<'_>, id: Uuid, at: i64) -> Result<Approval> {
    let id_text = id.to_string();
    let expired = tx.execute(
        "UPDATE approval SET state = 'expired' WHERE id = ?1 AND (
             (state = 'pending' AND pending_until <= ?2) OR
             (state = 'approved' AND EXISTS (
                 SELECT 1 FROM approved_grant WHERE approval = ?1 AND expires_at <= ?2)))",
        params![id_text, at],
    )?;
    if expired == 1 {
        record_event(tx, id, None, "expired", at)?;
    }
    Ok(
        tx.query_row("SELECT * FROM approval WHERE id = ?1", [id_text], |r| {
            let max_duration: u32 = r.get("max_duration")?;
            let state = match r.get::<_, String>("state")?.as_str() {
                "pending" => ApprovalState::Pending,
                "approved" => ApprovalState::Approved,
                "denied" => ApprovalState::Denied,
                "cancelled" => ApprovalState::Cancelled,
                "expired" => ApprovalState::Expired,
                "replaced" => ApprovalState::Replaced,
                _ => return Err(rusqlite::Error::InvalidQuery),
            };
            Ok(Approval {
                id,
                state,
                workload: Workload {
                    owner: Owner {
                        integrator: r.get("integrator")?,
                        user: r.get("owner")?,
                    },
                    context: r.get("context")?,
                    instance: r.get("workload")?,
                    generation: r.get::<_, i64>("workload_generation")? as u64,
                },
                entry_id: r.get("entry_id")?,
                entry_version: r.get::<_, i64>("entry_version")? as u64,
                scope: r.get("scope")?,
                initiating_origin: r.get("initiating_origin")?,
                max_duration_seconds: NonZeroU32::new(max_duration)
                    .ok_or(rusqlite::Error::InvalidQuery)?,
                pending_until: r.get("pending_until")?,
            })
        })?,
    )
}

fn require_current_session(tx: &Transaction<'_>, device: &DeviceSession) -> Result<()> {
    let current = tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM device WHERE integrator = ?1 AND owner = ?2
         AND pairing = ?3 AND key_id = ?4 AND generation = ?5)",
        params![
            device.owner.integrator,
            device.owner.user,
            device.pairing,
            device.key,
            device.generation
        ],
        |r| r.get::<_, bool>(0),
    )?;
    if current {
        Ok(())
    } else {
        Err(StoreError::Unavailable)
    }
}

impl SqliteApprovalStore {
    pub(crate) fn check_offer(&mut self, device: &DeviceSession, offer: Uuid) -> Result<Offer> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_current_session(&tx, device)?;
        let id = tx
            .query_row(
                "SELECT a.id FROM offer o JOIN approval a ON a.id=o.approval WHERE o.id=?1 AND
             a.integrator=?2 AND a.owner=?3 AND o.pairing=?4 AND o.key_id=?5 AND o.generation=?6",
                params![
                    offer.to_string(),
                    device.owner.integrator,
                    device.owner.user,
                    device.pairing,
                    device.key,
                    device.generation
                ],
                |r| parse_id(r, "id"),
            )
            .optional()?
            .ok_or(StoreError::Unavailable)?;
        let approval = load(&tx, id, now(&tx)?)?;
        tx.commit()?;
        Ok(Offer {
            id: offer,
            approval,
        })
    }
}

impl ApprovalStore for SqliteApprovalStore {
    fn request(
        &mut self,
        workload: &Workload,
        policy: &DestinationPolicy,
        origin: &Origin,
        max_duration_seconds: NonZeroU32,
        trigger: Trigger,
    ) -> Result<Approval> {
        let owner = &workload.owner;
        if owner.integrator.is_empty()
            || owner.user.is_empty()
            || workload.context.is_empty()
            || workload.instance.is_empty()
            || workload.generation == 0
        {
            return Err(StoreError::InvalidInput);
        }
        let scope = policy.scope_for(origin).ok_or(StoreError::Unavailable)?;
        let pattern = scope.pattern().to_string();
        let version = i64::try_from(scope.entry_version()).map_err(|_| StoreError::InvalidInput)?;
        let generation =
            i64::try_from(workload.generation).map_err(|_| StoreError::InvalidInput)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let at = now(&tx)?;
        let previous = tx
            .query_row(
                "SELECT id FROM approval WHERE current = 1 AND integrator = ?1 AND owner = ?2
             AND context = ?3 AND workload = ?4 AND workload_generation = ?5
             AND entry_id = ?6 AND entry_version = ?7 AND scope = ?8",
                params![
                    owner.integrator,
                    owner.user,
                    workload.context,
                    workload.instance,
                    generation,
                    scope.entry_id(),
                    version,
                    pattern
                ],
                |r| parse_id(r, "id"),
            )
            .optional()?;
        if let Some(id) = previous {
            let approval = load(&tx, id, at)?;
            if trigger == Trigger::Traffic
                || matches!(
                    approval.state,
                    ApprovalState::Pending | ApprovalState::Approved
                )
            {
                tx.commit()?;
                return Ok(approval);
            }
            tx.execute(
                "UPDATE approval SET current = 0 WHERE id = ?1",
                [id.to_string()],
            )?;
        }
        check_pending_capacity(&tx, owner, at)?;
        let id = Uuid::new_v4();
        tx.execute(
            "INSERT INTO approval (id, integrator, owner, context, workload, workload_generation,
                 entry_id, entry_version, scope, initiating_origin, max_duration, pending_until, state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'pending')",
            params![id.to_string(), owner.integrator, owner.user, workload.context, workload.instance,
                generation, scope.entry_id(), version, pattern,
                origin.to_string(), max_duration_seconds.get(), at + PENDING_SECONDS],
        )?;
        record_event(&tx, id, None, "requested", at)?;
        let approval = load(&tx, id, at)?;
        tx.commit()?;
        Ok(approval)
    }

    fn renew(
        &mut self,
        workload: &Workload,
        policy: &DestinationPolicy,
        previous: Uuid,
        max_duration_seconds: NonZeroU32,
    ) -> Result<Approval> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let at = now(&tx)?;
        let owned = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM approval WHERE id=?1 AND integrator=?2 AND owner=?3
            AND context=?4 AND workload=?5 AND workload_generation=?6 AND current=1)",
            params![
                previous.to_string(),
                workload.owner.integrator,
                workload.owner.user,
                workload.context,
                workload.instance,
                i64::try_from(workload.generation).map_err(|_| StoreError::InvalidInput)?
            ],
            |r| r.get::<_, bool>(0),
        )?;
        if !owned {
            return Err(StoreError::Unavailable);
        }
        let old = load(&tx, previous, at)?;
        if old.state != ApprovalState::Approved {
            tx.commit()?;
            return Err(StoreError::Resolved);
        }
        let origin = Origin::parse(&old.initiating_origin).map_err(|_| StoreError::InvalidInput)?;
        let scope = policy.scope_for(&origin).ok_or(StoreError::Unavailable)?;
        if scope.entry_id() != old.entry_id
            || scope.entry_version() != old.entry_version
            || scope.pattern().to_string() != old.scope
        {
            return Err(StoreError::Unavailable);
        }
        if let Some(id) = tx
            .query_row(
                "SELECT request FROM renewal WHERE predecessor=?1",
                [previous.to_string()],
                |r| parse_id(r, "request"),
            )
            .optional()?
        {
            let pending = load(&tx, id, at)?;
            if pending.state == ApprovalState::Pending {
                tx.commit()?;
                return Ok(pending);
            }
            tx.execute("DELETE FROM renewal WHERE request=?1", [id.to_string()])?;
        }
        check_pending_capacity(&tx, &workload.owner, at)?;
        let id = Uuid::new_v4();
        tx.execute("INSERT INTO approval(id,integrator,owner,context,workload,workload_generation,entry_id,entry_version,scope,
              initiating_origin,max_duration,pending_until,state,current)
            SELECT ?1,integrator,owner,context,workload,workload_generation,entry_id,entry_version,scope,
              initiating_origin,?2,?3,'pending',0 FROM approval WHERE id=?4",
            params![id.to_string(),max_duration_seconds.get(),at+PENDING_SECONDS,previous.to_string()])?;
        tx.execute(
            "INSERT INTO renewal(request,predecessor) VALUES(?1,?2)",
            params![id.to_string(), previous.to_string()],
        )?;
        record_event(&tx, id, None, "requested", at)?;
        let pending = load(&tx, id, at)?;
        tx.commit()?;
        Ok(pending)
    }

    fn authenticate_device(
        &mut self,
        owner: &Owner,
        pairing: &str,
        key: &str,
    ) -> Result<DeviceSession> {
        advance_device(&self.connection, owner, pairing, key)
    }

    fn offer(&mut self, device: &DeviceSession, approval: Uuid) -> Result<Offer> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_current_session(&tx, device)?;
        let owned: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM approval WHERE id = ?1 AND integrator = ?2 AND owner = ?3)",
            params![approval.to_string(), device.owner.integrator, device.owner.user],
            |r| r.get(0),
        )?;
        if !owned {
            return Err(StoreError::Unavailable);
        }
        let approval = load(&tx, approval, now(&tx)?)?;
        if approval.state != ApprovalState::Pending {
            tx.commit()?;
            return Err(StoreError::Resolved);
        }
        let offer_id = tx.query_row(
            "INSERT INTO offer (id, approval, pairing, key_id, generation) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (approval, pairing, key_id, generation) DO UPDATE SET approval = excluded.approval
             RETURNING id",
            params![Uuid::new_v4().to_string(), approval.id.to_string(), device.pairing, device.key, device.generation],
            |r| parse_id(r,"id"),
        )?;
        tx.commit()?;
        Ok(Offer {
            id: offer_id,
            approval,
        })
    }

    fn decide(
        &mut self,
        device: &DeviceSession,
        offer: Uuid,
        decision_id: Uuid,
        decision: &Decision,
    ) -> Result<Disposition> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_current_session(&tx, device)?;
        let offer_text = offer.to_string();
        let approval_id = tx
            .query_row(
                "SELECT a.id FROM offer o JOIN approval a ON o.approval = a.id
             WHERE o.id = ?1 AND a.integrator = ?2 AND a.owner = ?3 AND o.pairing = ?4
             AND o.key_id = ?5 AND o.generation = ?6",
                params![
                    offer_text,
                    device.owner.integrator,
                    device.owner.user,
                    device.pairing,
                    device.key,
                    device.generation
                ],
                |r| parse_id(r, "id"),
            )
            .optional()?
            .ok_or(StoreError::Unavailable)?;
        let decision_id = decision_id.to_string();
        let payload = serde_json::to_string(decision).map_err(|_| StoreError::InvalidInput)?;
        let previous = tx
            .query_row(
                "SELECT payload, disposition FROM decision WHERE offer = ?1 AND id = ?2",
                params![offer_text, decision_id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()?;
        if let Some((old_payload, disposition)) = previous {
            if old_payload != payload {
                return Err(StoreError::DecisionConflict);
            }
            return Ok(if disposition == "committed" {
                Disposition::Committed
            } else {
                Disposition::AlreadyResolved
            });
        }
        let at = now(&tx)?;
        let approval = load(&tx, approval_id, at)?;
        let disposition = if approval.state == ApprovalState::Pending {
            let state = match decision {
                Decision::Approve {
                    certificate,
                    duration_seconds,
                } => {
                    if duration_seconds > &approval.max_duration_seconds
                        || certificate.not_after_unix_seconds <= at
                    {
                        return Err(StoreError::InvalidInput);
                    }
                    if let Some(old) = tx
                        .query_row(
                            "SELECT predecessor FROM renewal WHERE request=?1",
                            [approval_id.to_string()],
                            |r| parse_id(r, "predecessor"),
                        )
                        .optional()?
                    {
                        let previous = load(&tx, old, at)?;
                        if previous.state != ApprovalState::Approved {
                            return Err(StoreError::Resolved);
                        }
                        let fenced=tx.execute("UPDATE approval SET state='replaced',current=0 WHERE id=?1 AND current=1 AND state='approved'",[old.to_string()])?;
                        if fenced != 1 {
                            return Err(StoreError::Resolved);
                        }
                        tx.execute(
                            "UPDATE approval SET current=1 WHERE id=?1",
                            [approval_id.to_string()],
                        )?;
                        record_event(&tx, old, Some(offer), "replaced", at)?;
                    }
                    let active=tx.query_row("SELECT count(*) FROM approved_grant g JOIN approval a ON g.approval=a.id
                          WHERE a.integrator=?1 AND a.owner=?2 AND a.state='approved' AND a.current=1 AND g.expires_at>?3",
                          params![device.owner.integrator,device.owner.user,at], |r|r.get::<_,i64>(0))?;
                    if active >= 8 {
                        return Err(StoreError::Capacity);
                    }
                    let expiry = certificate
                        .not_after_unix_seconds
                        .min(at + i64::from(duration_seconds.get()));
                    tx.execute(
                        "INSERT INTO approved_grant (id, approval, offer, certificate, expires_at)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![
                            Uuid::new_v4().to_string(),
                            approval_id.to_string(),
                            offer_text,
                            certificate.sha256,
                            expiry
                        ],
                    )?;
                    "approved"
                }
                Decision::Deny => "denied",
                Decision::Cancel => "cancelled",
            };
            tx.execute(
                "UPDATE approval SET state = ?1 WHERE id = ?2",
                params![state, approval_id.to_string()],
            )?;
            record_event(&tx, approval_id, Some(offer), state, at)?;
            Disposition::Committed
        } else {
            Disposition::AlreadyResolved
        };
        let result = match disposition {
            Disposition::Committed => "committed",
            Disposition::AlreadyResolved => "already_resolved",
        };
        tx.execute(
            "INSERT INTO decision (offer, id, payload, disposition) VALUES (?1, ?2, ?3, ?4)",
            params![offer_text, decision_id, payload, result],
        )?;
        tx.commit()?;
        Ok(disposition)
    }

    fn revoke(
        &mut self,
        owner: &Owner,
        device: Option<&DeviceSession>,
        id: Uuid,
    ) -> Result<Vec<Uuid>> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(device) = device {
            require_current_session(&tx, device)?;
            if &device.owner != owner {
                return Err(StoreError::Unavailable);
            }
        }
        let id_text = id.to_string();
        let authorized: bool=tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM approval a WHERE a.id=?1 AND a.integrator=?2 AND a.owner=?3
             AND (?4 IS NULL OR EXISTS(SELECT 1 FROM approved_grant g JOIN offer o ON o.id=g.offer
             WHERE g.approval=a.id AND o.pairing=?4 AND o.key_id=?5)))",
            params![id_text,owner.integrator,owner.user,device.map(|d|&d.pairing),device.map(|d|&d.key)],
            |r|r.get(0),
        )?;
        if !authorized {
            return Err(StoreError::Unavailable);
        }
        let affected=tx.prepare("SELECT id FROM approval a WHERE state IN ('approved','pending') AND
            (id=?1 OR (state='pending' AND EXISTS(SELECT 1 FROM renewal WHERE predecessor=?1 AND request=a.id)))")?
            .query_map([&id_text],|r|parse_id(r,"id"))?.collect::<rusqlite::Result<Vec<_>>>()?;
        let at = now(&tx)?;
        for target in &affected {
            tx.execute(
                "UPDATE approval SET state='cancelled' WHERE id=?1",
                [target.to_string()],
            )?;
            let actor = if device.is_some() {
                tx.query_row(
                    "SELECT offer FROM approved_grant WHERE approval=?1",
                    [&id_text],
                    |r| parse_id(r, "offer"),
                )
                .optional()?
            } else {
                None
            };
            record_event(
                &tx,
                *target,
                actor,
                if *target == id {
                    "revoked"
                } else {
                    "predecessor_revoked"
                },
                at,
            )?;
        }
        tx.commit()?;
        Ok(affected)
    }

    fn permit(&self, workload: &Workload, entry: Option<&str>) -> Result<()> {
        let generation =
            i64::try_from(workload.generation).map_err(|_| StoreError::InvalidInput)?;
        let ok:bool=self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM workload_binding WHERE integrator=?1 AND owner=?2 AND context=?3
             AND instance=?4 AND generation=?5 AND retired=0
             AND NOT EXISTS(SELECT 1 FROM emergency_stop WHERE integrator=?1)
             AND NOT EXISTS(SELECT 1 FROM issuer_stop WHERE integrator=?1)
             AND NOT EXISTS(SELECT 1 FROM suspended_user WHERE integrator=?1 AND owner=?2)
             AND NOT EXISTS(SELECT 1 FROM closed_context WHERE integrator=?1 AND owner=?2 AND context=?3)
             AND NOT EXISTS(SELECT 1 FROM denied_destination WHERE integrator=?1 AND owner=?2 AND entry_id=?6))",
            params![workload.owner.integrator,workload.owner.user,workload.context,workload.instance,generation,entry],
            |r|r.get(0),
        )?;
        if ok {
            Ok(())
        } else {
            Err(StoreError::Unavailable)
        }
    }

    fn issue_lease(
        &mut self,
        req: &countersign_protocol::wire::LeaseRequest,
        boot: Uuid,
        current_device: &countersign_protocol::wire::DeviceBinding,
        at_ms: u64,
        until_ms: u64,
    ) -> Result<()> {
        use countersign_protocol::wire::Enforcer;
        let role = match req.enforcer {
            Enforcer::Ingress => "ingress",
            Enforcer::Egress => "egress",
            _ => return Err(StoreError::InvalidInput),
        };
        if until_ms <= at_ms || until_ms - at_ms > 30_000 {
            return Err(StoreError::InvalidInput);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let gid = req.grant.grant.as_str();
        let generation =
            i64::try_from(req.generation.get()).map_err(|_| StoreError::InvalidInput)?;
        let sequence = i64::try_from(req.sequence.get()).map_err(|_| StoreError::InvalidInput)?;
        let at = i64::try_from(at_ms).map_err(|_| StoreError::InvalidInput)?;
        let until = i64::try_from(until_ms).map_err(|_| StoreError::InvalidInput)?;
        let saved: String = tx
            .query_row(
                "SELECT activation FROM working_identity WHERE grant_id=?1",
                [gid],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(StoreError::Unavailable)?;
        let mut original: countersign_protocol::wire::Activate =
            serde_json::from_str(&saved).map_err(|_| StoreError::Unavailable)?;
        if current_device.pairing != original.grant.device.pairing
            || current_device.key != original.grant.device.key
            || req.grant.device.channel_generation < original.grant.device.channel_generation
            || req.grant.device.channel_generation > current_device.channel_generation
        {
            return Err(StoreError::Unavailable);
        }
        original.grant.device.channel_generation = req.grant.device.channel_generation;
        if original.grant != req.grant {
            return Err(StoreError::Unavailable);
        }
        if req.grant.device != *current_device {
            let issued:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM enforcer_issue WHERE grant_id=?1 AND enforcer=?2 AND instance=?3)",
                params![gid,role,req.instance.as_str()],|r|r.get(0))?;
            if !issued {
                return Err(StoreError::Unavailable);
            }
        }
        let others: i64 = tx.query_row(
            "SELECT count(*) FROM enforcer_issue WHERE grant_id=?1
            AND NOT (enforcer=?2 AND instance=?3) AND expires_at_ms>?4 AND closed=0",
            params![gid, role, req.instance.as_str(), at],
            |r| r.get(0),
        )?;
        if others >= 64 {
            return Err(StoreError::Capacity);
        }
        let encoded = serde_json::to_string(&req.grant).map_err(|_| StoreError::InvalidInput)?;
        let changed=tx.execute("INSERT INTO enforcer_issue(grant_id,enforcer,instance,gateway_boot,grant_binding,expires_at_ms,generation,sequence)
            SELECT ?1,?2,?3,?4,?5,?6,?7,?8 WHERE EXISTS(
                SELECT 1 FROM working_identity w JOIN approval a ON a.id=w.approval JOIN approved_grant g ON g.id=w.grant_id
                WHERE w.grant_id=?1 AND a.state='approved' AND a.current=1 AND g.expires_at*1000>=?6)
            ON CONFLICT(grant_id,enforcer,instance) DO UPDATE SET expires_at_ms=excluded.expires_at_ms, sequence=excluded.sequence
            WHERE enforcer_issue.gateway_boot=excluded.gateway_boot AND enforcer_issue.grant_binding=excluded.grant_binding
              AND enforcer_issue.generation=excluded.generation AND enforcer_issue.sequence<excluded.sequence
              AND enforcer_issue.closed=0 AND enforcer_issue.expires_at_ms>?9",
            params![gid,role,req.instance.as_str(),boot.to_string(),encoded,until,generation,sequence,at])?;
        if changed != 1 {
            return Err(StoreError::Unavailable);
        }
        tx.commit()?;
        Ok(())
    }

    fn bind_activation(
        &mut self,
        workload: &Workload,
        activation: &countersign_protocol::wire::Activate,
        chain: &countersign_protocol::wire::PublicChain,
        verified_at_ms: u64,
        valid_until_ms: u64,
    ) -> Result<()> {
        let id =
            Uuid::parse_str(activation.approval.as_str()).map_err(|_| StoreError::InvalidInput)?;
        let grant = &activation.grant;
        if valid_until_ms <= verified_at_ms
            || crate::credentials::fingerprint(chain.as_slice()[0].as_slice())
                != grant.cert_sha256.0
        {
            return Err(StoreError::InvalidInput);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let public_chain = serde_json::to_string(chain).map_err(|_| StoreError::InvalidInput)?;
        let encoded = serde_json::to_string(activation).map_err(|_| StoreError::InvalidInput)?;
        let observed = i64::try_from(verified_at_ms).map_err(|_| StoreError::InvalidInput)?;
        let end = i64::try_from(valid_until_ms).map_err(|_| StoreError::InvalidInput)?;
        let written=tx.execute("INSERT OR IGNORE INTO working_identity(approval,grant_id,activation,public_chain,verified_at_ms,valid_until_ms)
            SELECT a.id,g.id,?1,?2,?3,?4 FROM approval a JOIN approved_grant g ON a.id=g.approval JOIN offer o ON o.id=g.offer
            WHERE a.id=?5 AND a.integrator=?6 AND a.owner=?7 AND a.context=?8 AND a.workload=?9 AND a.workload_generation=?10
            AND a.state='approved' AND a.current=1 AND g.expires_at>unixepoch() AND g.id=?11 AND o.id=?12
            AND o.pairing=?13 AND o.key_id=?14 AND g.certificate=?15 AND a.entry_id=?16 AND a.entry_version=?17 AND a.scope=?18",
            params![encoded,public_chain,observed,end,activation.approval.as_str(),workload.owner.integrator,workload.owner.user,
                workload.context,workload.instance,i64::try_from(workload.generation).map_err(|_|StoreError::InvalidInput)?,
                grant.grant.as_str(),activation.offer.as_str(),grant.device.pairing.as_str(),grant.device.key.as_str(),
                grant.cert_sha256.as_slice(),grant.scope.entry_id(),i64::try_from(grant.scope.entry_version()).map_err(|_|StoreError::InvalidInput)?,
                grant.scope.pattern().to_string()])?;
        if written == 0 {
            let same:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM working_identity WHERE approval=?1 AND activation=?2 AND public_chain=?3)",
                params![activation.approval.as_str(),encoded,public_chain],|r|r.get(0))?;
            if !same {
                return Err(StoreError::Resolved);
            }
        } else {
            record_event(&tx, id, None, "activation_bound", now(&tx)?)?;
        }
        tx.commit()?;
        Ok(())
    }

    fn approved_grant(
        &self,
        workload: &Workload,
        approval_id: Uuid,
    ) -> Result<Option<ApprovedGrant>> {
        Ok(self
            .connection
            .query_row(
                "SELECT g.id, g.certificate, g.expires_at, o.pairing, o.key_id FROM approval a
             JOIN approved_grant g ON g.approval = a.id JOIN offer o ON o.id = g.offer
             WHERE a.id = ?1 AND a.integrator = ?2 AND a.owner = ?3 AND a.context = ?4
             AND a.workload = ?5 AND a.workload_generation = ?6 AND a.current = 1
             AND a.state = 'approved' AND g.expires_at > unixepoch()",
                params![
                    approval_id.to_string(),
                    workload.owner.integrator,
                    workload.owner.user,
                    workload.context,
                    workload.instance,
                    i64::try_from(workload.generation).map_err(|_| StoreError::InvalidInput)?
                ],
                |r| {
                    Ok(ApprovedGrant {
                        id: parse_id(r, "id")?,
                        approval_id,
                        pairing: r.get("pairing")?,
                        pairing_key: r.get("key_id")?,
                        certificate_sha256: r.get("certificate")?,
                        expires_at: r.get("expires_at")?,
                    })
                },
            )
            .optional()?)
    }
}
