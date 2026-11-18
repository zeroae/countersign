use super::*;
use crate::{ApprovalState, Trigger};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::HeaderMap,
};
use std::time::Duration;
use tokio::time::{Instant, sleep_until, timeout_at};

pub(super) async fn request(
    State(s): State<Service>,
    Path(path): Path<String>,
    h: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let (binding, expires) = s
        .credentials
        .workload(
            backend::bearer(&h)?,
            clock_ms()? / 1000,
            h.get("x-countersign-gateway").and_then(|v| v.to_str().ok()),
        )
        .ok_or(Fault::Unauthenticated)?;
    let boot = h
        .get("x-countersign-gateway-instance")
        .and_then(|h| h.to_str().ok())
        .and_then(|v| Uuid::parse_str(v).ok())
        .ok_or(Fault::Invalid)?;
    let frame = w::Frame::<w::GatewayToBroker>::decode(&body).map_err(|_| Fault::Invalid)?;
    let id = frame.request_id;
    let response = match (path.as_str(), frame.message) {
        ("watch", w::GatewayToBroker::Watch(grant)) => {
            if grant.workload != binding {
                return Err(Fault::Denied);
            }
            let _permit = s
                .watchers
                .clone()
                .try_acquire_owned()
                .map_err(|_| Fault::Busy)?;
            let scope = grant.clone();
            let watcher = s.apply(move |a| {
                let at = clock_ms()?;
                if !a.grants.contains_key(scope.grant.as_str()) {
                    // A revoke can win between delivery of the previous
                    // heartbeat and reconnection of this long poll.
                    let encoded=serde_json::to_string(&scope).map_err(|_|Fault::Invalid)?;
                    let issued:bool=a.store.connection.query_row(
                        "SELECT EXISTS(SELECT 1 FROM enforcer_issue WHERE grant_id=?1 AND gateway_boot=?2 AND grant_binding=?3)",
                        params![scope.grant.as_str(),boot.to_string(),encoded],|r|r.get(0)
                    )?;
                    if !issued { return Err(Fault::Unavailable); }
                    return Ok(None);
                }
                a.require_gateway(&scope, boot)?;
                let validity = a.validate_traffic(&scope, at)?.min(expires * 1000);
                let live = a.grants.get(scope.grant.as_str()).ok_or(Fault::Unavailable)?;
                Ok(Some((live.retire_signal.subscribe(), validity)))
            }).await?;
            let live = if let Some((mut signal, validity)) = watcher {
                let wait = Duration::from_millis(validity.saturating_sub(clock_ms()?).min(20_000));
                tokio::time::timeout(wait, signal.changed()).await.is_err()
                    && validity > clock_ms()?
            } else {
                false
            };
            if live {
                w::BrokerToGateway::NoChange(grant)
            } else {
                w::BrokerToGateway::Retire(grant)
            }
        }
        ("observe", w::GatewayToBroker::Observed(event)) => {
            s.apply(move |a| {
                observations::observe(a, &binding, boot, &event)?;
                Ok(w::BrokerToGateway::Observed(event))
            })
            .await?
        }
        ("admit", w::GatewayToBroker::Connect(req) | w::GatewayToBroker::Lookup(req)) => {
            s.apply(move |a| {
                if req.workload != binding {
                    return Err(Fault::Denied);
                }
                a.allow_destination(
                    &binding,
                    a.policy.resolve(&req.host).ok_or(Fault::Denied)?.id(),
                )?;
                let r = a.store.request(
                    &super::binding(&binding),
                    &a.policy,
                    &req.host,
                    a.max_duration,
                    Trigger::Traffic,
                )?;
                match r.state {
                    ApprovalState::Pending => {
                        a.notify_pending(&r);
                        Ok(w::BrokerToGateway::Pending(w::Notice { id: wire_id(r.id) }))
                    }
                    ApprovalState::Approved => {
                        let g = a
                            .store
                            .approved_grant(&super::binding(&binding), r.id)?
                            .ok_or(Fault::Unavailable)?;
                        let live = a
                            .grants
                            .get_mut(&g.id.to_string())
                            .ok_or(Fault::Unavailable)?;
                        if !live.acknowledged {
                            return Ok(w::BrokerToGateway::Pending(w::Notice {
                                id: wire_id(r.id),
                            }));
                        }
                        if !a.policy.covers(&live.activation.grant.scope, &req.host) {
                            return Err(Fault::Denied);
                        }
                        if *live.gateway_boot.get_or_insert(boot) != boot {
                            return Err(Fault::Denied);
                        }
                        Ok(w::BrokerToGateway::Activate(w::GatewayActivation {
                            activation: live.activation.clone(),
                            chain: live.chain.clone(),
                        }))
                    }
                    ApprovalState::Expired => Err(Fault::Expired),
                    _ => Err(Fault::Denied),
                }
            })
            .await?
        }
        ("lease", w::GatewayToBroker::RenewLease(req)) => {
            s.apply(move |a| {
                let at = clock_ms()?;
                if req.grant.workload != binding
                    || matches!(req.enforcer, w::Enforcer::SigningRelay)
                {
                    return Err(Fault::Denied);
                }
                a.require_gateway(&req.grant, boot)?;
                let limit = a.validate_traffic(&req.grant, at)?;
                let until = (at + 30_000).min(expires * 1000).min(limit);
                let budget =
                    NonZeroU32::new(until.saturating_sub(at) as u32).ok_or(Fault::Expired)?;
                let current_device = &a
                    .grants
                    .get(req.grant.grant.as_str())
                    .ok_or(Fault::Unavailable)?
                    .activation
                    .grant
                    .device;
                a.store
                    .issue_lease(&req, boot, current_device, at, until)
                    .map_err(|e| match e {
                        crate::StoreError::Unavailable => Fault::Denied,
                        other => other.into(),
                    })?;
                Ok(w::BrokerToGateway::Lease(w::LeaseReply {
                    binding: req,
                    disposition: w::LeaseDisposition::Granted {
                        budget_ms: budget,
                        valid_until_ms: until,
                    },
                }))
            })
            .await?
        }
        ("sign", w::GatewayToBroker::Sign(req)) => {
            let request_id = id.clone();
            let op = req.binding.clone();
            let deadline = req.deadline_ms;
            let sent_at = Instant::now();
            let (rx, leased_until) = s
                .apply(move |a| {
                    let at = clock_ms()?;
                    a.prune(at);
                    if req.binding.grant.workload != binding
                        || !a.policy.covers(&req.binding.grant.scope, &req.binding.host)
                    {
                        return Err(Fault::Denied);
                    }
                    a.require_gateway(&req.binding.grant, boot)?;
                    let limit = a.validate_grant(&req.binding.grant, at)?;
                    let until = req.deadline_ms.min(expires * 1000).min(limit);
                    if req.deadline_ms > at + 120_000 || until <= at {
                        return Err(Fault::Expired);
                    }
                    validate_input(&req)?;
                    let key = operation_key(&req.binding);
                    let grant_id = req.binding.grant.grant.as_str();
                    let pairing = req.binding.grant.device.pairing.as_str();
                    let peer = a
                        .peers
                        .get(pairing)
                        .filter(|p| p.binding == req.binding.grant.device)
                        .ok_or(Fault::Unavailable)?;
                    if a.waiting
                        .values()
                        .filter(|w| w.op.grant.device.pairing == peer.binding.pairing)
                        .count()
                        >= 16
                        || a.waiting
                            .values()
                            .filter(|w| w.op.grant.grant == req.binding.grant.grant)
                            .count()
                            >= 4
                    {
                        return Err(Fault::Busy);
                    }
                    let g = a.grants.get_mut(grant_id).ok_or(Fault::Unavailable)?;
                    if g.operations.len() >= 65_536 {
                        return Err(Fault::Busy);
                    }
                    if g.operations.contains(&req.binding.operation) {
                        return Err(Fault::Denied);
                    }
                    let (tx, rx) = oneshot::channel();
                    let mut req = req;
                    req.deadline_ms = until;
                    let leased_until = sent_at + Duration::from_millis((until - at).min(30_000));
                    if leased_until <= Instant::now() {
                        return Err(Fault::Expired);
                    }
                    let op = req.binding.clone();
                    let scheme = req.scheme;
                    let input = req.certificate_verify.clone();
                    send(peer, request_id.clone(), w::BrokerToCompanion::Sign(req))?;
                    g.operations.insert(op.operation.clone());
                    a.waiting.insert(
                        key,
                        SignWait {
                            leased_until,
                            scheme,
                            input,
                            request_id,
                            op,
                            deadline: until,
                            reply: tx,
                        },
                    );
                    Ok((rx, leased_until))
                })
                .await?;
            let cleanup = CancelOnDrop {
                service: s.clone(),
                op: op.clone(),
            };
            let signed = wait_for_signature(&s, rx, &op, leased_until, expires, boot).await?;
            let response = s
                .apply(move |a| {
                    let at = clock_ms()?;
                    if deadline.min(expires * 1000) <= at {
                        return Err(Fault::Expired);
                    }
                    a.validate_grant(&signed.binding.grant, at)?;
                    Ok(w::BrokerToGateway::Signed(signed))
                })
                .await?;
            drop(cleanup);
            response
        }
        ("cancel", w::GatewayToBroker::Cancel(op)) => {
            s.apply(move |a| {
                if op.grant.workload != binding {
                    return Err(Fault::Denied);
                }
                a.live_workload(&binding)?;
                a.require_gateway(&op.grant, boot)?;
                if let Some(existing) = a.waiting.get(&operation_key(&op)) {
                    if existing.op != op {
                        return Err(Fault::Denied);
                    }
                    a.waiting.remove(&operation_key(&op));
                    if let Some(peer) = a.peers.get(op.grant.device.pairing.as_str()) {
                        let _ = send(peer, fresh(), w::BrokerToCompanion::Cancel(op.clone()));
                    }
                }
                Ok(w::BrokerToGateway::Cancel(op))
            })
            .await?
        }
        _ => return Err(Fault::Invalid),
    };
    let encoded = w::Frame {
        request_id: id,
        message: response,
    }
    .encode()
    .map_err(|_| Fault::Storage)?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        encoded,
    )
        .into_response())
}

fn validate_input(req: &w::Sign) -> Result<()> {
    let message = req.certificate_verify.as_slice();
    match req.tls {
        w::TlsVersion::Tls13 => {
            let (prefix, rest) = message.split_at_checked(64).ok_or(Fault::Invalid)?;
            let hash = rest
                .strip_prefix(b"TLS 1.3, client CertificateVerify\0")
                .ok_or(Fault::Invalid)?;
            if prefix != [0x20u8; 64]
                || !matches!(hash.len(), 32 | 48)
                || matches!(
                    req.scheme,
                    w::SignatureScheme::RsaPkcs1Sha256
                        | w::SignatureScheme::RsaPkcs1Sha384
                        | w::SignatureScheme::RsaPkcs1Sha512
                )
            {
                return Err(Fault::Invalid);
            }
        }
        w::TlsVersion::Tls12 => {
            // rustls supplies the raw transcript. Accept the supported initial
            // handshake structure and reject arbitrary digests or trailing data.
            let mut rest = message;
            let mut kinds = Vec::new();
            while !rest.is_empty() {
                let (h, body) = rest.split_at_checked(4).ok_or(Fault::Invalid)?;
                let len = u32::from_be_bytes([0, h[1], h[2], h[3]]) as usize;
                rest = body.get(len..).ok_or(Fault::Invalid)?;
                kinds.push(h[0]);
                if kinds.len() > 9 {
                    return Err(Fault::Invalid);
                }
            }
            // Optional staple (certificate_status) follows the server chain.
            if kinds != [1, 2, 11, 12, 13, 14, 11, 16]
                && kinds != [1, 2, 11, 22, 12, 13, 14, 11, 16]
            {
                return Err(Fault::Invalid);
            }
        }
    }
    Ok(())
}

/// The signing relay owns this lease separately from the two traffic leases.
/// A provider prompt can remain open for multiple successful renewals.
async fn wait_for_signature(
    s: &Service,
    mut rx: oneshot::Receiver<w::Signed>,
    op: &w::Operation,
    mut leased_until: Instant,
    token_expires: u64,
    boot: Uuid,
) -> Result<w::Signed> {
    loop {
        let next = (Instant::now() + Duration::from_secs(10)).min(leased_until);
        tokio::select! {
            answer = &mut rx => {
                if Instant::now() >= leased_until { return Err(Fault::Expired); }
                return answer.map_err(|_| Fault::Unavailable);
            }
            _ = sleep_until(next) => {}
        }
        let send_time = Instant::now();
        if send_time >= leased_until {
            return Err(Fault::Expired);
        }
        let binding = op.clone();
        leased_until = timeout_at(
            leased_until,
            s.apply(move |a| {
                let at = clock_ms()?;
                a.require_gateway(&binding.grant, boot)?;
                let validity = a
                    .validate_grant(&binding.grant, at)?
                    .min(token_expires * 1000);
                let pending = a
                    .waiting
                    .get_mut(&operation_key(&binding))
                    .ok_or(Fault::Unavailable)?;
                if pending.leased_until <= Instant::now() || pending.op != binding {
                    return Err(Fault::Expired);
                }
                let ms = validity
                    .min(pending.deadline)
                    .saturating_sub(at)
                    .min(30_000);
                let next = send_time + Duration::from_millis(ms);
                if next <= Instant::now() {
                    return Err(Fault::Expired);
                }
                pending.leased_until = next;
                Ok(next)
            }),
        )
        .await
        .map_err(|_| Fault::Expired)??;
    }
}

/// Dropping a disconnected HTTP request must also withdraw its device work.
struct CancelOnDrop {
    service: Service,
    op: w::Operation,
}
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        let s = self.service.clone();
        let op = self.op.clone();
        tokio::spawn(async move {
            let _ = s
                .apply(move |a| {
                    if a.waiting
                        .get(&operation_key(&op))
                        .is_some_and(|p| p.op == op)
                    {
                        a.waiting.remove(&operation_key(&op));
                        if let Some(peer) = a.peers.get(op.grant.device.pairing.as_str()) {
                            let _ = send(peer, fresh(), w::BrokerToCompanion::Cancel(op));
                        }
                    }
                    Ok(())
                })
                .await;
        });
    }
}
