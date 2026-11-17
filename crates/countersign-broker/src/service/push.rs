use super::{Fault, Result, Service, backend, w};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{Client, Url};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::IpAddr, path::PathBuf, sync::Arc, time::Duration};
use uuid::Uuid;
use web_push_native::{
    Auth, WebPushBuilder, jwt_simple::algorithms::ES256KeyPair, p256::PublicKey,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushConfig {
    vapid_key_file: PathBuf,
    contact: String,
    allowed_hosts: HashSet<String>,
}

pub(super) struct Sender {
    key: ES256KeyPair,
    contact: String,
    hosts: HashSet<String>,
}

impl PushConfig {
    pub(super) fn load(&self) -> std::result::Result<Arc<Sender>, Box<dyn std::error::Error>> {
        if self.allowed_hosts.is_empty() || !self.contact.starts_with("mailto:") {
            return Err("invalid Web Push service configuration".into());
        }
        let secret = std::fs::read_to_string(&self.vapid_key_file)?;
        Ok(Arc::new(Sender {
            key: ES256KeyPair::from_bytes(&URL_SAFE_NO_PAD.decode(secret.trim())?)?,
            contact: self.contact.clone(),
            hosts: self.allowed_hosts.clone(),
        }))
    }
}

#[derive(Serialize, Deserialize)]
struct Keys {
    p256dh: String,
    auth: String,
}
#[derive(Serialize, Deserialize)]
struct Subscription {
    endpoint: String,
    keys: Keys,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Register {
    user: w::Id,
    subscription: Subscription,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Remove {
    user: w::Id,
    endpoint: String,
}

fn endpoint(raw: &str, hosts: &HashSet<String>) -> Result<Url> {
    let url = Url::parse(raw).map_err(|_| Fault::Invalid)?;
    if raw.len() > 4096
        || url.scheme() != "https"
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || !url.domain().is_some_and(|h| hosts.contains(h))
    {
        return Err(Fault::Invalid);
    }
    Ok(url)
}

fn keys(value: &Keys) -> Result<(PublicKey, Auth)> {
    let key = URL_SAFE_NO_PAD
        .decode(&value.p256dh)
        .map_err(|_| Fault::Invalid)?;
    let public = PublicKey::from_sec1_bytes(&key).map_err(|_| Fault::Invalid)?;
    let secret: [u8; 16] = URL_SAFE_NO_PAD
        .decode(&value.auth)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(Fault::Invalid)?;
    Ok((public, secret.into()))
}

// Permit public unicast only, even if an allowed push service's DNS changes.
fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let [a, b, c, _] = v.octets();
            !matches!(a, 0 | 10 | 127 | 224..=255)
                && !(a == 100 && (64..128).contains(&b))
                && !(a == 169 && b == 254)
                && !(a == 172 && (16..32).contains(&b))
                && !(a == 192 && (b == 168 || b == 0 || (b == 88 && c == 99)))
                && !(a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                && !(a == 203 && b == 0 && c == 113)
        }
        IpAddr::V6(v) => {
            let [a, b, ..] = v.segments();
            (a & 0xe000) == 0x2000
                && a != 0x2002
                && !(a == 0x2001 && (b < 0x200 || b == 0xdb8))
                && a != 0x3fff
        }
    }
}

impl Sender {
    async fn deliver(
        &self,
        subscription: &Subscription,
        approval: Uuid,
        ttl: u32,
    ) -> Result<StatusCode> {
        let url = endpoint(&subscription.endpoint, &self.hosts)?;
        let host = url.domain().ok_or(Fault::Invalid)?;
        let addresses = tokio::net::lookup_host((host, 443))
            .await
            .map_err(|_| Fault::Unavailable)?
            .take(65)
            .collect::<Vec<_>>();
        if addresses.is_empty()
            || addresses.len() > 64
            || addresses.iter().any(|s| !public_ip(s.ip()))
        {
            return Err(Fault::Denied);
        }
        let client = Client::builder()
            .no_proxy()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(host, &addresses)
            .timeout(Duration::from_secs(6))
            .build()
            .map_err(|_| Fault::Unavailable)?;
        let (public, auth) = keys(&subscription.keys)?;
        let request = WebPushBuilder::new(
            url.as_str().parse().map_err(|_| Fault::Invalid)?,
            public,
            auth,
        )
        .with_valid_duration(Duration::from_secs(ttl.into()))
        .with_vapid(&self.key, &self.contact)
        .build(serde_json::to_vec(&approval.to_string()).map_err(|_| Fault::Invalid)?)
        .map_err(|_| Fault::Unavailable)?;
        let (parts, body) = request.into_parts();
        Ok(client
            .post(url)
            .headers(parts.headers)
            .body(body)
            .send()
            .await
            .map_err(|_| Fault::Unavailable)?
            .status())
    }
}

pub(super) fn routes() -> Router<Service> {
    Router::new()
        .route("/v1/backend/push/subscribe", post(register))
        .route("/v1/backend/push/unsubscribe", post(remove))
}

async fn register(
    State(s): State<Service>,
    headers: HeaderMap,
    Json(req): Json<Register>,
) -> Result<StatusCode> {
    backend::auth(&s, &headers)?;
    let sender = s.push_sender.as_ref().ok_or(Fault::Unavailable)?;
    endpoint(&req.subscription.endpoint, &sender.hosts)?;
    keys(&req.subscription.keys)?;
    s.apply(move|a|{
        let db=&a.store.connection;
        let count:i64=db.query_row("SELECT count(*) FROM push_subscription WHERE owner=?1",[req.user.as_str()],|r|r.get(0))?;
        if count>=16{return Err(Fault::Busy);}
        let changed=db.execute("INSERT INTO push_subscription(owner,endpoint,subscription) VALUES (?1,?2,?3)
            ON CONFLICT(endpoint) DO UPDATE SET subscription=excluded.subscription WHERE owner=excluded.owner",
            params![req.user.as_str(),req.subscription.endpoint,serde_json::to_string(&req.subscription).map_err(|_|Fault::Invalid)?])?;
        if changed==0 {return Err(Fault::Denied);} Ok(())
    }).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn remove(
    State(s): State<Service>,
    headers: HeaderMap,
    Json(req): Json<Remove>,
) -> Result<StatusCode> {
    backend::auth(&s, &headers)?;
    s.apply(move |a| {
        a.store.connection.execute(
            "DELETE FROM push_subscription WHERE owner=?1 AND endpoint=?2",
            params![req.user.as_str(), req.endpoint],
        )?;
        Ok(())
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) fn start(service: Service, sender: Arc<Sender>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(2));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let job=service.apply(|a|{
                let db=&a.store.connection;
                // Derive deliveries from committed pending approvals and their
                // outbox records. A wakeup is best effort and idempotent by ID.
                let mut query=db.prepare("SELECT DISTINCT a.id,a.owner,s.endpoint,s.subscription,a.pending_until
                    FROM outbox o JOIN approval a ON a.id=o.approval JOIN push_subscription s ON s.owner=a.owner
                    LEFT JOIN push_attempt p ON p.approval=a.id AND p.endpoint=s.endpoint
                    WHERE a.current=1 AND a.state='pending' AND a.pending_until>unixepoch() AND
                    a.integrator=?1 AND (p.retry_at IS NULL OR p.retry_at<=unixepoch()) ORDER BY a.pending_until")?;
                let mut rows=query.query([a.integrator.as_str()])?;
                while let Some(r)=rows.next()? {
                    let user:String=r.get(1)?;
                    if a.peers.values().any(|p|p.session.owner.user==user){continue;}
                    let id:String=r.get(0)?;let ep:String=r.get(2)?;let value:String=r.get(3)?;let until:i64=r.get(4)?;
                    db.execute("INSERT INTO push_attempt VALUES(?1,?2,unixepoch()+30)
                        ON CONFLICT(approval,endpoint) DO UPDATE SET retry_at=excluded.retry_at",params![id,ep])?;
                    return Ok(Some((id,ep,value,until)));
                }
                Ok(None)
            }).await;
            if let Ok(Some((id, ep, value, until))) = job
                && let (Ok(uid), Ok(sub)) = (
                    Uuid::parse_str(&id),
                    serde_json::from_str::<Subscription>(&value),
                )
            {
                let Ok(ms) = super::clock_ms() else {
                    continue;
                };
                let secs = until.saturating_sub((ms / 1000) as i64).clamp(0, 600) as u32;
                if secs == 0 {
                    continue;
                }
                let status =
                    tokio::time::timeout(Duration::from_secs(8), sender.deliver(&sub, uid, secs))
                        .await;
                let Ok(Ok(code)) = status else {
                    continue;
                };
                let _=service.apply(move|a|{
                    if code==StatusCode::GONE || code==StatusCode::NOT_FOUND {
                        a.store.connection.execute("DELETE FROM push_subscription WHERE endpoint=?1 AND subscription=?2",params![ep,value])?;
                    } else if code.is_success(){
                        a.store.connection.execute("UPDATE push_attempt SET retry_at=?1 WHERE approval=?2 AND endpoint=?3",params![until,id,ep])?;
                    }
                    Ok(())
                }).await;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn push_service_is_exact_and_public() {
        let hosts = HashSet::from(["push.example".to_owned()]);
        for bad in [
            "https://push.example.evil/u",
            "https://user@push.example/u",
            "http://push.example/u",
            "https://push.example:8443/u",
        ] {
            assert!(endpoint(bad, &hosts).is_err());
        }
        assert!(endpoint("https://push.example/subscription", &hosts).is_ok());
        for ip in [
            "::1",
            "::ffff:10.0.0.1",
            "169.254.169.254",
            "2001:db8::7",
            "10.1.2.3",
        ] {
            assert!(!public_ip(ip.parse().unwrap()));
        }
    }
}
