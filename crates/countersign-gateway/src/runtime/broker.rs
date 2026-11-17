use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use countersign_protocol::{Origin, wire::*};
use futures_util::StreamExt;
use rustls::{ClientConfig, RootCertStore, crypto::ring::default_provider};
use serde::Deserialize;
use std::{
    num::{NonZeroU32, NonZeroU64},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::{Instant, timeout_at};
use uuid::Uuid;

use super::{
    Result,
    config::{Config, anchors},
    invalid,
};

pub fn id() -> Id {
    Id::new(Uuid::new_v4().to_string()).expect("UUID format")
}
pub fn utc_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}

#[derive(Clone)]
pub enum Credential {
    File(PathBuf),
    Ingress(String),
}
impl Credential {
    async fn read(&self) -> Result<String> {
        match self {
            Self::File(path) => Ok(tokio::fs::read_to_string(path).await?.trim().to_owned()),
            Self::Ingress(value) => Ok(value.clone()),
        }
    }
    pub fn ingress(token: &str) -> Result<(Self, WorkloadBinding)> {
        // An untrusted hint for the admission request. The Broker verifies
        // JWT signature, audience and membership before returning a binding.
        #[derive(Deserialize)]
        struct Claims {
            aud: String,
            binding: WorkloadBinding,
        }
        let mut parts = token.split('.');
        let (Some(_), Some(body), Some(_), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(invalid("invalid proxy credentials"));
        };
        if token.len() > 16384 {
            return Err(invalid("invalid proxy credentials"));
        }
        let claims: Claims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(body)?)?;
        if claims.aud != "countersign:gateway:workload" {
            return Err(invalid("wrong proxy credential audience"));
        }
        Ok((Self::Ingress(token.to_owned()), claims.binding))
    }
}

pub struct Broker {
    url: String,
    client: reqwest::Client,
    instance: Uuid,
    gateway_token: Option<String>,
    uncertainty_ms: u64,
}
impl Broker {
    pub fn new(config: &Config) -> Result<Self> {
        let mut roots = RootCertStore::empty();
        for cert in anchors(&config.broker_ca)? {
            roots.add(cert)?;
        }
        let tls = ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .tls_backend_preconfigured(tls)
            .connect_timeout(Duration::from_secs(5))
            .build()?;
        let gateway_token = config
            .shared
            .as_ref()
            .map(|s| read_secret(&s.gateway_token))
            .transpose()?;
        Ok(Self {
            url: config.broker_url.trim_end_matches('/').to_owned(),
            client,
            instance: Uuid::new_v4(),
            gateway_token,
            uncertainty_ms: config.clock_uncertainty_ms,
        })
    }

    pub async fn call(
        &self,
        path: &'static str,
        credential: &Credential,
        message: GatewayToBroker,
        deadline: Instant,
    ) -> Result<BrokerToGateway> {
        timeout_at(deadline, async {
            let request_id = id();
            let body = Frame {
                request_id: request_id.clone(),
                message,
            }
            .encode()?;
            let mut request = self
                .client
                .post(format!("{}/v1/gateway/{path}", self.url))
                .bearer_auth(credential.read().await?)
                .header("X-Countersign-Gateway-Instance", self.instance.to_string())
                .header(reqwest::header::CONTENT_TYPE, "application/json");
            if let Some(secret) = &self.gateway_token {
                request = request.header("X-Countersign-Gateway", secret);
            }
            let response = request.body(body).send().await?.error_for_status()?;
            let mut bytes = Vec::new();
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                if bytes.len() + chunk.len() > MAX_FRAME_BYTES {
                    return Err(invalid("Broker response exceeds limit"));
                }
                bytes.extend_from_slice(&chunk);
            }
            let frame = Frame::<BrokerToGateway>::decode(&bytes)?;
            if frame.request_id != request_id {
                return Err(invalid("Broker response binding mismatch"));
            }
            Ok(frame.message)
        })
        .await?
    }
    pub async fn admit(
        &self,
        credential: &Credential,
        workload: &WorkloadBinding,
        origin: &Origin,
        deadline: Instant,
    ) -> Result<GatewayActivation> {
        let mut pending = false;
        loop {
            let connect = Connect {
                workload: workload.clone(),
                host: origin.clone(),
            };
            let message = if pending {
                GatewayToBroker::Lookup(connect)
            } else {
                GatewayToBroker::Connect(connect)
            };
            match self.call("admit", credential, message, deadline).await? {
                BrokerToGateway::Activate(response)
                    if &response.activation.grant.workload == workload
                        && response.activation.expires_at_ms > utc_ms()? =>
                {
                    return Ok(response);
                }
                BrokerToGateway::Pending(_) => {
                    pending = true;
                    timeout_at(deadline, tokio::time::sleep(Duration::from_millis(450))).await?;
                }
                _ => return Err(invalid("protected connection denied")),
            }
        }
    }
    pub async fn renew(
        &self,
        credential: &Credential,
        request: LeaseRequest,
        grant_expiry_ms: u64,
        previous: Instant,
    ) -> Result<Lease> {
        let send = Instant::now();
        let wall = utc_ms()?;
        let message = self
            .call(
                "lease",
                credential,
                GatewayToBroker::RenewLease(request.clone()),
                previous,
            )
            .await?;
        let BrokerToGateway::Lease(reply) = message else {
            return Err(invalid("Broker refused lease"));
        };
        if reply.binding != request {
            return Err(invalid("lease response binding mismatch"));
        }
        let LeaseDisposition::Granted {
            budget_ms,
            valid_until_ms,
        } = reply.disposition
        else {
            return Err(invalid("lease refused"));
        };
        Lease::from_reply(
            send,
            wall,
            budget_ms,
            valid_until_ms.min(grant_expiry_ms),
            self.uncertainty_ms,
        )
    }
}
fn read_secret(path: &Path) -> Result<String> {
    let secret = std::fs::read_to_string(path)?;
    let value = secret.trim();
    if value.len() < 32 {
        return Err(invalid("service credential too short"));
    }
    Ok(value.to_owned())
}

pub struct Lease {
    pub deadline: Instant,
    wall_deadline: u64,
    clock_sample: u64,
    sent: Instant,
    uncertainty: u64,
}
impl Lease {
    fn from_reply(
        sent: Instant,
        wall: u64,
        budget: NonZeroU32,
        cap: u64,
        uncertainty: u64,
    ) -> Result<Self> {
        if budget.get() > 30_000 {
            return Err(invalid("lease budget exceeds maximum"));
        }
        let cap = cap.saturating_sub(uncertainty);
        let budget_ms = u64::from(budget.get()).min(cap.saturating_sub(wall));
        let lease = Self {
            deadline: sent + Duration::from_millis(budget_ms),
            wall_deadline: wall.saturating_add(budget_ms),
            clock_sample: wall,
            sent,
            uncertainty,
        };
        lease.check()?;
        Ok(lease)
    }
    pub fn check(&self) -> Result<()> {
        let now = Instant::now();
        let wall = utc_ms()?;
        let elapsed = u64::try_from(now.duration_since(self.sent).as_millis())?;
        if now >= self.deadline
            || wall >= self.wall_deadline
            || self.clock_sample.saturating_add(elapsed).abs_diff(wall) > self.uncertainty
        {
            return Err(invalid("lease expired or clock uncertain"));
        }
        Ok(())
    }
}
pub fn lease_request(grant: GrantBinding, enforcer: Enforcer) -> LeaseRequest {
    LeaseRequest {
        grant,
        enforcer,
        instance: id(),
        generation: NonZeroU64::MIN,
        sequence: NonZeroU64::MIN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lease_budget_starts_at_send_and_never_exceeds_the_absolute_cap() {
        let now = utc_ms().unwrap();
        let budget = NonZeroU32::new(30000).unwrap();
        assert!(
            Lease::from_reply(
                Instant::now() - Duration::from_secs(31),
                now - 31000,
                budget,
                now + 60000,
                100
            )
            .is_err()
        );
        assert!(Lease::from_reply(Instant::now(), now, budget, now + 99, 100).is_err());
        assert!(
            Lease::from_reply(
                Instant::now(),
                now,
                NonZeroU32::new(30001).unwrap(),
                now + 60000,
                100
            )
            .is_err()
        );
        let sent = Instant::now();
        let capped = Lease::from_reply(sent, now, budget, now + 2000, 100).unwrap();
        assert_eq!(capped.deadline, sent + Duration::from_millis(1900));
    }
}
