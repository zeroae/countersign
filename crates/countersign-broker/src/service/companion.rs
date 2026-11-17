use super::*;
use crate::{
    Decision, Disposition, ValidatedCertificate,
    credentials::{fingerprint, verify_device_proof},
};
use axum::{
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::HeaderMap,
};
use ring::rand::{SecureRandom, SystemRandom};

use std::time::Duration;
use tokio::time::timeout;
use x509_parser::parse_x509_certificate;

type C = w::CompanionToBroker;
type B = w::BrokerToCompanion;
pub(super) async fn upgrade(
    State(s): State<Service>,
    h: HeaderMap,
    addr: Option<axum::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    ws: WebSocketUpgrade,
) -> Result<Response> {
    // Native clients omit Origin. Reject browser-originated WebSockets even
    // when a page has guessed the endpoint and the upgrade subprotocol.
    if h.contains_key("origin")
        || !h
            .get("sec-websocket-protocol")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.split(',').any(|p| p.trim() == w::SUBPROTOCOL))
    {
        return Err(Fault::Denied);
    }
    let slot = s
        .connections
        .clone()
        .try_acquire_owned()
        .map_err(|_| Fault::Busy)?;
    Ok(ws
        .protocols([w::SUBPROTOCOL])
        .max_message_size(w::MAX_FRAME_BYTES)
        .max_frame_size(w::MAX_FRAME_BYTES)
        .on_upgrade(move |mut socket| async move {
            let _slot = slot;
            let address = addr
                .map(|axum::Extension(axum::extract::ConnectInfo(remote))| remote.ip().to_string());
            let _ = run(&mut socket, s, address).await;
        }))
}
async fn receive(sock: &mut WebSocket) -> Result<w::Frame<C>> {
    loop {
        match sock.recv().await {
            Some(Ok(Message::Text(text))) => {
                return w::Frame::<C>::decode(text.as_bytes()).map_err(|_| Fault::Invalid);
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            _ => return Err(Fault::Unavailable),
        }
    }
}
async fn write(sock: &mut WebSocket, id: w::Id, msg: B) -> Result<()> {
    let text = String::from_utf8(
        w::Frame {
            request_id: id,
            message: msg,
        }
        .encode()
        .map_err(|_| Fault::Invalid)?,
    )
    .map_err(|_| Fault::Invalid)?;
    timeout(
        Duration::from_secs(5),
        sock.send(Message::Text(text.into())),
    )
    .await
    .map_err(|_| Fault::Expired)?
    .map_err(|_| Fault::Unavailable)
}
struct Login {
    user: w::Id,
    pairing: w::Id,
    key: w::Id,
    public: Vec<u8>,
    purpose: w::ProofPurpose,
}
async fn enroll(s: &Service, sock: &mut WebSocket, id: w::Id, enroll: w::Enroll) -> Result<Login> {
    let public = enroll.public_sec1.as_slice().to_vec();
    if public.first() != Some(&4) {
        return Err(Fault::Invalid);
    }
    let attempt = fresh();
    let code = Uuid::new_v4().simple().to_string()[..10].to_ascii_uppercase();
    let until = clock_ms()? + 600_000;
    let (tx, rx) = oneshot::channel();
    let k = attempt.as_str().to_owned();
    let pending = PendingPair {
        code: code.clone(),
        until,
        user: tx,
    };
    s.apply(move |a| {
        a.prune(clock_ms()?);
        if a.enrollments.len() >= 128 {
            return Err(Fault::Busy);
        }
        a.enrollments.insert(k, pending);
        Ok(())
    })
    .await?;
    write(
        sock,
        id,
        B::PairingPending(w::PairingPending {
            attempt: attempt.clone(),
            code: w::Id::new(code).map_err(|_| Fault::Invalid)?,
            expires_at_ms: until,
        }),
    )
    .await?;
    let user = timeout(Duration::from_secs(600), rx)
        .await
        .map_err(|_| Fault::Expired)?
        .map_err(|_| Fault::Denied)?;
    Ok(Login {
        user,
        pairing: fresh(),
        key: w::Id::new(base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            fingerprint(&public),
        ))
        .map_err(|_| Fault::Storage)?,
        public,
        purpose: w::ProofPurpose::Pair { attempt },
    })
}
async fn run(sock: &mut WebSocket, s: Service, address: Option<String>) -> Result<()> {
    let first = timeout(Duration::from_secs(10), receive(sock))
        .await
        .map_err(|_| Fault::Expired)??;
    let login=match first.message {
        C::Enroll(req)=>enroll(&s,sock,first.request_id.clone(),req).await?,
        C::Authenticate(req)=>s.apply(move|a|{
            let (user,public)=a.store.connection.query_row("SELECT user_id,public_sec1 FROM enrollment WHERE integrator=?1 AND pairing=?2 AND key_id=?3",
            params![a.integrator.as_str(),req.pairing.as_str(),req.key.as_str()],|r| Ok((r.get::<_,String>(0)?,r.get::<_,Vec<u8>>(1)?))).optional()?.ok_or(Fault::Denied)?;
            Ok(Login{user:w::Id::new(user).map_err(|_|Fault::Storage)?,pairing:req.pairing.clone(),key:req.key,public,
                purpose:w::ProofPurpose::Reconnect{pairing:req.pairing}})
        }).await?,
        _=>return Err(Fault::Unauthenticated),
    };
    let origin = s.apply(|a| Ok(a.origin.clone())).await?;
    let at = clock_ms()?;
    let mut nonce = [0u8; 32];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| Fault::Storage)?;
    let ch = w::Challenge {
        purpose: login.purpose.clone(),
        integrator_origin: origin.clone(),
        broker_origin: origin,
        user: login.user.clone(),
        key: login.key.clone(),
        connection: fresh(),
        nonce: w::FixedBytes::new(nonce),
        issued_at_ms: at,
        expires_at_ms: at + 60_000,
    };
    write(sock, first.request_id, B::Challenge(ch.clone())).await?;
    let proof = timeout(Duration::from_secs(60), receive(sock))
        .await
        .map_err(|_| Fault::Expired)??;
    match proof.message {
        C::Proof(p)
            if p.connection == ch.connection
                && verify_device_proof(&login.public, &ch, p.compact_jws.as_str(), clock_ms()?) => {
        }
        _ => return Err(Fault::Unauthenticated),
    }
    let (tx, mut rx) = mpsc::channel(32);
    let device=s.apply(move|a|{
        if matches!(login.purpose,w::ProofPurpose::Pair{..}){
            a.store.connection.execute("INSERT INTO enrollment(pairing,user_id,integrator,key_id,public_sec1) VALUES (?1,?2,?3,?4,?5)",
                params![login.pairing.as_str(),login.user.as_str(),a.integrator.as_str(),login.key.as_str(),login.public])?;
        }else {
            let active=a.store.connection.query_row("SELECT EXISTS(SELECT 1 FROM enrollment WHERE pairing=?1 AND key_id=?2 AND user_id=?3 AND integrator=?4)",
                params![login.pairing.as_str(),login.key.as_str(),login.user.as_str(),a.integrator.as_str()],|r|r.get::<_,bool>(0))?;
            if !active{return Err(Fault::Denied);}
        }
        let session=a.store.authenticate_device(&Owner{integrator:a.integrator.as_str().into(),user:login.user.as_str().into()},login.pairing.as_str(),login.key.as_str())?;
        let b=w::DeviceBinding{pairing:login.pairing,key:login.key,channel_generation:NonZeroU64::new(session.generation as u64).ok_or(Fault::Storage)?};
        a.waiting.retain(|_,w|w.op.grant.device.pairing!=b.pairing);
        let peer=Peer{session,binding:b.clone(),send:tx};
        for grant in a.grants.values_mut().filter(|g| g.activation.grant.device.pairing==b.pairing && g.activation.grant.device.key==b.key && g.activation.expires_at_ms>at) {
            grant.activation.grant.device=b.clone();
            grant.acknowledged=false;
            send(&peer,fresh(),B::Activate(grant.activation.clone()))?;
        }
        a.peers.insert(b.pairing.as_str().into(),peer);
        super::controls::connected(a,login.user.as_str(),&b,address)?;
        Ok(b)
    }).await?;
    let auth = write(sock, proof.request_id, B::Authenticated(device.clone())).await;
    if auth.is_ok() {
        loop {
            tokio::select! {
                outgoing=rx.recv()=>match outgoing {
                    Some(w::Frame{request_id,message}) => if write(sock,request_id,message).await.is_err(){break;},
                    None=>break,
                },
                incoming=receive(sock)=> {
                    let Ok(frame)=incoming else{break;};
                    let d=device.clone();
                    let id=frame.request_id.clone();
                    let result=s.apply(move|a|handle(a,&d,frame)).await;
                    let message=match result{
                        Ok(Some(msg))=>msg,Ok(None)=>continue,
                        Err(f)=>B::Error(w::Rejection{code:match f {
                            Fault::Invalid=>w::ErrorCode::InvalidRequest,Fault::Denied=>w::ErrorCode::Denied,
                            Fault::Expired=>w::ErrorCode::Expired,Fault::Resolved=>w::ErrorCode::AlreadyResolved,
                            Fault::Busy=>w::ErrorCode::Busy,_=>w::ErrorCode::Unavailable,
                        }}),
                    };
                    if write(sock,id,message).await.is_err(){break;}
                }
            }
        }
    }
    s.apply(move |a| {
        if a.peers
            .get(device.pairing.as_str())
            .is_some_and(|p| p.binding == device)
        {
            a.peers.remove(device.pairing.as_str());
            a.waiting.retain(|_, v| v.op.grant.device != device);
        }
        Ok(())
    })
    .await?;
    auth
}

fn offer(
    a: &mut Authority,
    device: &w::DeviceBinding,
    id: Uuid,
    previous: Option<Uuid>,
) -> Result<w::Offer> {
    let peer = a
        .peers
        .get(device.pairing.as_str())
        .ok_or(Fault::Unavailable)?;
    let o = match previous {
        Some(old) => a.store.check_offer(&peer.session, old)?,
        None => a.store.offer(&peer.session, id)?,
    };
    if o.approval.id != id {
        return Err(Fault::Denied);
    }
    let r = o.approval;
    let host = Origin::parse(&r.initiating_origin).map_err(|_| Fault::Storage)?;
    let scope = a.policy.scope_for(&host).ok_or(Fault::Denied)?;
    let b = workload(&r.workload)?;
    a.allow_destination(&b, scope.entry_id())?;
    if scope.entry_id() != r.entry_id
        || scope.entry_version() != r.entry_version
        || scope.pattern().to_string() != r.scope
    {
        return Err(Fault::Denied);
    }
    Ok(w::Offer {
        binding: w::OfferBinding {
            approval: wire_id(id),
            approval_version: NonZeroU64::MIN,
            offer: wire_id(o.id),
            device: device.clone(),
        },
        workload: b,
        initiating_host: host,
        scope,
        default_duration_s: r.max_duration_seconds.min(NonZeroU32::new(3600).unwrap()),
        max_duration_s: r.max_duration_seconds,
        expires_at_ms: r.pending_until as u64 * 1000,
    })
}
fn handle(a: &mut Authority, device: &w::DeviceBinding, frame: w::Frame<C>) -> Result<Option<B>> {
    let at = clock_ms()?;
    a.prune(at);
    let p = a
        .peers
        .get(device.pairing.as_str())
        .filter(|p| p.binding == *device)
        .ok_or(Fault::Unauthenticated)?;
    match frame.message {
        C::Devices(_) => Ok(Some(B::Devices(super::controls::devices(a, device)?))),
        C::ForgetDevices(req) => {
            let user = p.session.owner.user.clone();
            Ok(Some(B::Devices(super::controls::forget(
                a,
                &user,
                Some(device),
                req,
            )?)))
        }
        C::Inbox(_) => {
            let mut query = a.store.connection.prepare(
                "SELECT id FROM approval WHERE integrator=?1 AND owner=?2 AND state='pending'
                AND (current=1 OR EXISTS(SELECT 1 FROM renewal WHERE renewal.request=approval.id)) AND pending_until>unixepoch()
                    UNION ALL SELECT id FROM (SELECT id FROM security_event WHERE integrator=?1 AND owner=?2
                      AND kind IN ('concurrent_devices','devices_forgotten','credential_used_on_multiple_devices') ORDER BY occurred_at_ms DESC LIMIT 32)
                    LIMIT 160",
            )?;
            let ids = query
                .query_map(
                    params![p.session.owner.integrator, p.session.owner.user],
                    |r| r.get::<_, String>(0),
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?
                .into_iter()
                .map(|v| w::Id::new(v).map_err(|_| Fault::Storage))
                .collect::<Result<Vec<_>>>()?;
            Ok(Some(B::Inbox(w::Inbox { ids })))
        }
        C::Fetch(n) => {
            if let Some(event) = super::controls::fetch_event(a, &p.session.owner.user, &n.id)? {
                Ok(Some(B::SecurityEvent(event)))
            } else {
                Ok(Some(B::Offer(offer(a, device, uid(&n.id)?, None)?)))
            }
        }
        C::Decide(d) => decide(a, device, frame.request_id, d, at),
        C::Activated(act) => {
            let g = a
                .grants
                .get_mut(act.grant.grant.as_str())
                .ok_or(Fault::Unavailable)?;
            if act.grant.device != *device
                || g.activation.grant != act.grant
                || g.activation.approval != act.approval
                || g.activation.offer != act.offer
                || g.activation.expires_at_ms != act.expires_at_ms
            {
                return Err(Fault::Denied);
            }
            g.acknowledged = true;
            Ok(None)
        }
        C::Signed(done) => {
            a.validate_grant(&done.binding.grant, at)?;
            let g = a
                .grants
                .get(done.binding.grant.grant.as_str())
                .ok_or(Fault::Unavailable)?;
            if g.activation.grant.device != *device {
                return Err(Fault::Denied);
            }
            let op = a
                .waiting
                .get(done.binding.operation.as_str())
                .ok_or(Fault::Unavailable)?;
            if op.op != done.binding
                || op.deadline <= at
                || frame.request_id != op.request_id
                || tokio::time::Instant::now() >= op.leased_until
            {
                return Err(Fault::Denied);
            }
            verify_signature(g.chain.as_slice()[0].as_slice(), op, &done)?;
            let op = a
                .waiting
                .remove(done.binding.operation.as_str())
                .ok_or(Fault::Unavailable)?;
            super::controls::signature_observed(a, &done.binding.grant)?;
            let _ = op.reply.send(done);
            Ok(None)
        }
        C::Cancel(target) => {
            let op = a
                .waiting
                .get(target.operation.as_str())
                .ok_or(Fault::Unavailable)?;
            if op.op != target || op.op.grant.device != *device {
                return Err(Fault::Denied);
            }
            a.waiting.remove(target.operation.as_str());
            Ok(None)
        }
        _ => Err(Fault::Invalid),
    }
}

fn decide(
    a: &mut Authority,
    device: &w::DeviceBinding,
    response: w::Id,
    d: w::Decide,
    at: u64,
) -> Result<Option<B>> {
    if d.binding.device != *device || d.binding.approval_version != NonZeroU64::MIN {
        return Err(Fault::Denied);
    }
    let approval_id = uid(&d.binding.approval)?;
    let offered = offer(a, device, approval_id, Some(uid(&d.binding.offer)?))?;
    if offered.binding.offer != d.binding.offer {
        return Err(Fault::Denied);
    }
    let (decision, chain) = match d.answer {
        w::Answer::Deny => (Decision::Deny, None),
        w::Answer::Cancel => (Decision::Cancel, None),
        w::Answer::Approve {
            duration_s,
            chain,
            cert_sha256,
        } => {
            let profile = a
                .validators
                .get(offered.scope.entry_id())
                .ok_or(Fault::Denied)?;
            let valid = profile
                .verify(offered.workload.user.as_str(), &chain, at)
                .map_err(|_| Fault::Denied)?;
            let hash = fingerprint(chain.as_slice()[0].as_slice());
            if hash != cert_sha256.0 {
                return Err(Fault::Invalid);
            }
            let expiry = valid.certificate_end;
            (
                Decision::Approve {
                    certificate: ValidatedCertificate {
                        sha256: hash,
                        not_after_unix_seconds: expiry,
                    },
                    duration_seconds: duration_s,
                },
                Some(chain),
            )
        }
    };
    let peer = a
        .peers
        .get(device.pairing.as_str())
        .ok_or(Fault::Unavailable)?;
    let result = a.store.decide(
        &peer.session,
        uid(&d.binding.offer)?,
        uid(&response)?,
        &decision,
    )?;
    if result == Disposition::AlreadyResolved {
        return Err(Fault::Resolved);
    }
    a.notify(offered.workload.user.as_str(), d.binding.approval.clone());
    if let Some(chain) = chain {
        let g = a
            .store
            .approved_grant(&binding(&offered.workload), approval_id)?
            .ok_or(Fault::Denied)?;
        if let Some(previous) = a.grants.get(&g.id.to_string()) {
            if previous.activation.grant.device != *device || previous.chain != chain {
                return Err(Fault::Invalid);
            }
            return Ok(Some(B::Activate(previous.activation.clone())));
        }
        let replaced = a
            .store
            .connection
            .query_row(
                "SELECT predecessor FROM renewal WHERE request=?1",
                [d.binding.approval.as_str()],
                |r| r.get::<_, String>(0),
            )
            .optional()?;
        if let Some(old) = replaced {
            super::controls::clear_live(a, &[old]);
        }
        let grant = w::GrantBinding {
            workload: offered.workload,
            grant: wire_id(g.id),
            grant_version: NonZeroU64::MIN,
            worker: fresh(),
            worker_generation: NonZeroU64::MIN,
            scope: offered.scope,
            device: device.clone(),
            cert_sha256: w::FixedBytes::new(g.certificate_sha256),
        };
        let act = w::Activate {
            grant,
            approval: d.binding.approval,
            offer: d.binding.offer,
            expires_at_ms: g.expires_at as u64 * 1000,
        };
        a.grants.insert(
            act.grant.grant.as_str().to_owned(),
            LiveGrant {
                gateway_boot: None,
                activation: act.clone(),
                chain,
                acknowledged: false,
                lease_seq: HashMap::new(),
                operations: HashMap::new(),
            },
        );
        Ok(Some(B::Activate(act)))
    } else {
        Ok(None)
    }
}

fn verify_signature(leaf: &[u8], wait: &SignWait, result: &w::Signed) -> Result<()> {
    use ring::signature as sig;
    use w::SignatureScheme::*;
    let alg: &dyn sig::VerificationAlgorithm = match wait.scheme {
        EcdsaNistp256Sha256 => &sig::ECDSA_P256_SHA256_ASN1,
        EcdsaNistp384Sha384 => &sig::ECDSA_P384_SHA384_ASN1,
        RsaPkcs1Sha256 => &sig::RSA_PKCS1_2048_8192_SHA256,
        RsaPkcs1Sha384 => &sig::RSA_PKCS1_2048_8192_SHA384,
        RsaPkcs1Sha512 => &sig::RSA_PKCS1_2048_8192_SHA512,
        RsaPssSha256 => &sig::RSA_PSS_2048_8192_SHA256,
        RsaPssSha384 => &sig::RSA_PSS_2048_8192_SHA384,
        RsaPssSha512 => &sig::RSA_PSS_2048_8192_SHA512,
    };
    let (_, cert) = parse_x509_certificate(leaf).map_err(|_| Fault::Invalid)?;
    sig::UnparsedPublicKey::new(alg, cert.public_key().subject_public_key.data.as_ref())
        .verify(wait.input.as_slice(), result.signature.as_slice())
        .map_err(|_| Fault::Denied)
}
