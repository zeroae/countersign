use super::{
    Result,
    broker::{Broker, Credential, Lease},
    invalid,
};
use countersign_protocol::wire::LeaseRequest;
use std::{
    pin::Pin,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;

#[derive(Debug, thiserror::Error)]
#[error("required authorization lease lapsed")]
pub struct LeaseLost;

#[derive(Clone)]
pub struct Guard(Arc<RwLock<Lease>>, Arc<AtomicU64>);
impl Guard {
    pub fn new(lease: Lease) -> Self {
        Self(
            Arc::new(RwLock::new(lease)),
            Arc::new(AtomicU64::new(u64::MAX)),
        )
    }
    pub fn cap(&self, wall_ms: u64) -> Result<()> {
        self.1.fetch_min(wall_ms, Ordering::Release);
        self.check()
    }
    pub fn check(&self) -> Result<()> {
        if super::broker::utc_ms()? >= self.1.load(Ordering::Acquire) {
            return Err(invalid("upstream evidence expired"));
        }
        self.0
            .read()
            .map_err(|_| invalid("lease state unavailable"))?
            .check()
    }
    pub fn deadline(&self) -> Result<Instant> {
        Ok(self
            .0
            .read()
            .map_err(|_| invalid("lease state unavailable"))?
            .deadline)
    }
}
struct Guarded<T> {
    io: T,
    guard: Guard,
}
impl<T: AsyncRead + Unpin> AsyncRead for Guarded<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.guard.check().map_err(io::Error::other)?;
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for Guarded<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.guard.check().map_err(io::Error::other)?;
        Pin::new(&mut self.io).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.guard.check().map_err(io::Error::other)?;
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

pub struct EnforcedLeg {
    pub request: LeaseRequest,
    pub guard: Guard,
}
impl EnforcedLeg {
    pub async fn acquire(
        broker: &Broker,
        credential: &Credential,
        request: LeaseRequest,
        expiry: u64,
        deadline: Instant,
    ) -> Result<Self> {
        let lease = broker
            .renew(credential, request.clone(), expiry, deadline)
            .await?;
        Ok(Self {
            request,
            guard: Guard::new(lease),
        })
    }
    async fn renew(mut self, broker: &Broker, credential: &Credential, expiry: u64) -> Result<()> {
        loop {
            self.guard.check()?;
            let deadline = self.guard.deadline()?;
            let next = (Instant::now() + Duration::from_secs(10)).min(deadline);
            tokio::time::sleep_until(next).await;
            self.guard.check()?;
            self.request.sequence = self
                .request
                .sequence
                .checked_add(1)
                .ok_or_else(|| invalid("lease sequence exhausted"))?;
            let lease = broker
                .renew(credential, self.request.clone(), expiry, deadline)
                .await?;
            self.guard.check()?;
            *self
                .guard
                .0
                .write()
                .map_err(|_| invalid("lease state unavailable"))? = lease;
        }
    }
    pub async fn relay<A: AsyncRead + AsyncWrite + Unpin, B: AsyncRead + AsyncWrite + Unpin>(
        self,
        a: A,
        b: B,
        broker: &Broker,
        credential: &Credential,
        expiry: u64,
    ) -> Result<()> {
        // Guard both writes including bytes already read before a missed
        // renewal. The independent timer also closes idle and stalled streams.
        let mut a = Guarded {
            io: a,
            guard: self.guard.clone(),
        };
        let mut b = Guarded {
            io: b,
            guard: self.guard.clone(),
        };
        let egress = matches!(
            self.request.enforcer,
            countersign_protocol::wire::Enforcer::Egress
        );
        let renew = self.renew(broker, credential, expiry);
        tokio::pin!(renew);
        tokio::select! {
            biased;
            result=&mut renew => result.map_err(|_|Box::new(LeaseLost) as _),
            result=io::copy_bidirectional(&mut a,&mut b)=>{
                result?;
                // The site may close immediately after its last response byte.
                // Allow the worker to deliver that response under the original
                // independent leases until the downstream leg finishes.
                drop((a,b));
                if egress { renew.await.map_err(|_|Box::new(LeaseLost) as _) } else { Ok(()) }
            },
        }
    }
}
