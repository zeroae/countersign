use super::*;
use crate::Trigger;
use axum::{Json, extract::State, http::HeaderMap};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub(super) fn bearer(h: &HeaderMap) -> Result<&str> {
    if h.get_all("authorization").iter().count() != 1 {
        return Err(Fault::Unauthenticated);
    }
    h.get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(Fault::Unauthenticated)
}
pub(super) fn auth(s: &Service, h: &HeaderMap) -> Result<()> {
    if s.credentials.backend_authorized(bearer(h)?.as_bytes()) {
        Ok(())
    } else {
        Err(Fault::Unauthenticated)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkloadRequest {
    user: w::Id,
    context: w::Id,
    workload: w::Id,
    workload_generation: NonZeroU64,
    mode: Option<String>,
}
#[derive(Serialize)]
pub(super) struct Token {
    token: String,
    binding: w::WorkloadBinding,
    expires_at_ms: u64,
}
pub(super) async fn workload(
    State(s): State<Service>,
    h: HeaderMap,
    Json(req): Json<WorkloadRequest>,
) -> Result<Json<Token>> {
    auth(&s, &h)?;
    let shared = match req.mode.as_deref() {
        None | Some("sidecar") => false,
        Some("shared") => true,
        _ => return Err(Fault::Invalid),
    };
    let b = s
        .apply(move |a| {
            let generation =
                i64::try_from(req.workload_generation.get()).map_err(|_| Fault::Invalid)?;
            let changed = a.store.connection.execute(
                "INSERT INTO workload_binding(integrator,owner,context,instance,generation,retired)
            VALUES (?1,?2,?3,?4,?5,0) ON CONFLICT(integrator,owner,context,instance) DO UPDATE
            SET generation=excluded.generation,retired=0 WHERE generation < excluded.generation OR
              (generation=excluded.generation AND retired=0)",
                params![
                    a.integrator.as_str(),
                    req.user.as_str(),
                    req.context.as_str(),
                    req.workload.as_str(),
                    generation
                ],
            )?;
            if changed != 1 {
                return Err(Fault::Denied);
            }
            Ok(w::WorkloadBinding {
                integrator: a.integrator.clone(),
                user: req.user,
                context: req.context,
                workload: req.workload,
                workload_generation: req.workload_generation,
            })
        })
        .await?;
    let (token, exp) = s
        .credentials
        .issue(b.clone(), clock_ms()? / 1000, shared)
        .ok_or(Fault::Storage)?;
    Ok(Json(Token {
        token,
        binding: b,
        expires_at_ms: exp * 1000,
    }))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Confirm {
    user: w::Id,
    attempt: w::Id,
    code: String,
}
pub(super) async fn confirm(
    State(s): State<Service>,
    h: HeaderMap,
    Json(req): Json<Confirm>,
) -> Result<StatusCode> {
    auth(&s, &h)?;
    s.apply(move |a| {
        // A failed code consumes this attempt too. A browser cannot make
        // thousands of guesses against a single desktop enrollment.
        let pending = a
            .enrollments
            .remove(req.attempt.as_str())
            .ok_or(Fault::Unavailable)?;
        if pending.until <= clock_ms()? || pending.code != req.code {
            return Err(Fault::Denied);
        }
        pending.user.send(req.user).map_err(|_| Fault::Unavailable)
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Create {
    binding: w::WorkloadBinding,
    host: Origin,
}
pub(super) async fn request(
    State(s): State<Service>,
    h: HeaderMap,
    Json(req): Json<Create>,
) -> Result<Json<Value>> {
    auth(&s, &h)?;
    s.apply(move |a| {
        a.allow_destination(
            &req.binding,
            a.policy.resolve(&req.host).ok_or(Fault::Denied)?.id(),
        )?;
        let r = a.store.request(
            &binding(&req.binding),
            &a.policy,
            &req.host,
            a.max_duration,
            Trigger::ExplicitConnect,
        )?;
        if r.state == crate::ApprovalState::Pending {
            a.notify(req.binding.user.as_str(), wire_id(r.id));
        }
        Ok(Json(
            json!({"id":r.id.to_string(),"state":format!("{:?}",r.state).to_ascii_lowercase()}),
        ))
    })
    .await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Owned {
    user: w::Id,
    id: w::Id,
}
pub(super) async fn status(
    State(s): State<Service>,
    h: HeaderMap,
    Json(req): Json<Owned>,
) -> Result<Json<Value>> {
    auth(&s, &h)?;
    s.apply(move|a| {
        let state=a.store.connection.query_row(
          "SELECT CASE WHEN state='pending' AND pending_until <= unixepoch() THEN 'expired'
             WHEN state='approved' AND EXISTS(SELECT 1 FROM approved_grant WHERE approval=approval.id AND expires_at<=unixepoch()) THEN 'expired'
             ELSE state END FROM approval WHERE id=?1 AND integrator=?2 AND owner=?3",
          params![req.id.as_str(),a.integrator.as_str(),req.user.as_str()],|r|r.get::<_,String>(0)).optional()?.ok_or(Fault::Unavailable)?;
        Ok(Json(json!({"id":req.id,"state":state})))
    }).await
}
pub(super) async fn revoke(
    State(s): State<Service>,
    h: HeaderMap,
    Json(req): Json<Owned>,
) -> Result<StatusCode> {
    auth(&s, &h)?;
    s.apply(move|a|{
        let tx=a.store.connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let changed=tx.execute("UPDATE approval SET state='cancelled' WHERE id=?1 AND integrator=?2 AND owner=?3
            AND state IN ('pending','approved') AND current=1",
          params![req.id.as_str(),a.integrator.as_str(),req.user.as_str()])?;
        if changed!=1 {return Err(Fault::Unavailable);}
        let event=Uuid::new_v4().to_string();
        tx.execute("INSERT INTO audit(event_id,approval,kind,occurred_at) VALUES(?1,?2,'revoked',unixepoch())",
            params![event,req.id.as_str()])?;
        tx.execute("INSERT INTO outbox(event_id,approval) VALUES(?1,?2)",params![event,req.id.as_str()])?;
        tx.commit()?;
        let retired:Vec<_>=a.grants.iter().filter(|(_,g)|g.activation.approval==req.id).map(|(id,_)|id.clone()).collect();
        for id in retired {
            if let Some(grant)=a.grants.remove(&id) {
                a.waiting.retain(|_,op|op.op.grant.grant!=grant.activation.grant.grant);
                if let Some(p)=a.peers.get(grant.activation.grant.device.pairing.as_str()){
                    let _=send(p,fresh(),w::BrokerToCompanion::Retire(grant.activation.grant));
                }
            }
        }
        a.notify(req.user.as_str(),req.id);
        Ok(StatusCode::NO_CONTENT)
    }).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Renewal {
    binding: w::WorkloadBinding,
    id: w::Id,
}
pub(super) async fn renew(
    State(s): State<Service>,
    h: HeaderMap,
    Json(req): Json<Renewal>,
) -> Result<Json<Value>> {
    auth(&s, &h)?;
    s.apply(move |a| {
        a.live_workload(&req.binding)?;
        let request = a.store.renew(
            &binding(&req.binding),
            &a.policy,
            uid(&req.id)?,
            a.max_duration,
        )?;
        a.notify(req.binding.user.as_str(), wire_id(request.id));
        Ok(Json(json!({"id":request.id.to_string(),"state":"pending"})))
    })
    .await
}
