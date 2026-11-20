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
            let b=w::WorkloadBinding {
                integrator:a.integrator.clone(), user:req.user, context:req.context,
                workload:req.workload, workload_generation:req.workload_generation,
            };
            let tx = a.store.connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let previous = tx.query_row(
                "SELECT generation,retired FROM workload_binding WHERE integrator=?1 AND owner=?2 AND context=?3 AND instance=?4",
                params![b.integrator.as_str(),b.user.as_str(),b.context.as_str(),b.workload.as_str()],
                |r|Ok((r.get::<_,i64>(0)?, r.get::<_,bool>(1)?)),
            ).optional()?;
            if previous.is_some_and(|(old,retired)|old>generation || (old==generation && retired)) {
                return Err(Fault::Denied);
            }
            let retired=match previous {
                Some((old,_)) if old<generation => controls::retire_generation(&tx,&b,old)?,
                _=>Vec::new(),
            };
            tx.execute(
                "INSERT INTO workload_binding(integrator,owner,context,instance,generation,retired)
                 VALUES (?1,?2,?3,?4,?5,0) ON CONFLICT(integrator,owner,context,instance) DO UPDATE
                 SET generation=excluded.generation,retired=0",
                params![b.integrator.as_str(),b.user.as_str(),b.context.as_str(),b.workload.as_str(),generation],
            )?;
            tx.commit()?;
            controls::clear_live(a,&retired);
            Ok(b)
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
            a.notify_pending(&r);
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
    s.apply(move |a| {
        let row = a.store.connection.query_row(
            "SELECT CASE WHEN state='pending' AND pending_until<=unixepoch() THEN 'expired'
             WHEN state='approved' AND g.expires_at<=unixepoch() THEN 'expired' ELSE state END,
             g.id, EXISTS(SELECT 1 FROM gateway_observation o WHERE o.grant_id=g.id AND o.observation='mtls_accepted'),
             (SELECT count(*) FROM gateway_observation o WHERE o.grant_id=g.id AND o.observation='ingress_closed'),
             (SELECT count(*) FROM gateway_observation o WHERE o.grant_id=g.id AND o.observation='egress_closed'),
             g.expires_at, lower(hex(g.certificate))
             FROM approval a LEFT JOIN approved_grant g ON g.approval=a.id
             WHERE a.id=?1 AND a.integrator=?2 AND a.owner=?3",
            params![req.id.as_str(),a.integrator.as_str(),req.user.as_str()],
            |r|Ok((r.get::<_,String>(0)?,r.get::<_,Option<String>>(1)?,r.get::<_,bool>(2)?,r.get::<_,i64>(3)?,r.get::<_,i64>(4)?,
                r.get::<_,Option<i64>>(5)?,r.get::<_,Option<String>>(6)?)),
        ).optional()?.ok_or(Fault::Unavailable)?;
        let (state, grant, accepted, ingress_closed, egress_closed, expires_at, certificate_sha256) = row;
        let ready = state=="approved" && grant.and_then(|id|a.grants.get(&id)).is_some_and(|g|{
            g.acknowledged && a.peers.get(g.activation.grant.device.pairing.as_str()).is_some_and(|p|p.binding==g.activation.grant.device)
        });
        let mut view = json!({"id":req.id,"state":state,"ready":ready,"upstream_mtls_accepted":accepted,"ingress_closed_count":ingress_closed,"egress_closed_count":egress_closed});
        // A grant row outlives its approval's end (expired, replaced, cancelled), so these
        // keep describing the grant that was approved; an approval that never had one omits them.
        if let (Some(expires_at), Some(sha256)) = (expires_at, certificate_sha256) {
            view["expires_at_ms"] = json!(expires_at.checked_mul(1000).ok_or(Fault::Storage)?);
            view["certificate"] = json!({"sha256": sha256});
        }
        Ok(Json(view))
    }).await
}
pub(super) async fn revoke(
    State(s): State<Service>,
    h: HeaderMap,
    Json(req): Json<Owned>,
) -> Result<StatusCode> {
    auth(&s, &h)?;
    s.apply(move |a| {
        let owner = Owner {
            integrator: a.integrator.as_str().into(),
            user: req.user.as_str().into(),
        };
        let affected = a.store.revoke(&owner, None, uid(&req.id)?)?;
        controls::withdraw(a, affected);
        Ok(StatusCode::NO_CONTENT)
    })
    .await
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
        a.notify_pending(&request);
        Ok(Json(json!({"id":request.id.to_string(),"state":"pending"})))
    })
    .await
}
