use super::*;

pub(super) fn issued(
    db: &rusqlite::Connection,
    req: &w::LeaseRequest,
    role: &str,
    boot: Uuid,
    until: u64,
) -> Result<()> {
    db.execute(
        "INSERT INTO enforcer_issue(grant_id,enforcer,instance,gateway_boot,grant_binding,expires_at_ms)
         VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(grant_id,enforcer,instance)
         DO UPDATE SET expires_at_ms=excluded.expires_at_ms WHERE gateway_boot=excluded.gateway_boot",
        params![req.grant.grant.as_str(),role,req.instance.as_str(),boot.to_string(),
            serde_json::to_string(&req.grant).map_err(|_|Fault::Storage)?,until as i64],
    )?;
    Ok(())
}

pub(super) fn observe(
    authority: &mut Authority,
    binding: &w::WorkloadBinding,
    boot: Uuid,
    event: &w::Observed,
) -> Result<()> {
    if &event.grant.workload != binding || !authority.policy.covers(&event.grant.scope, &event.host)
    {
        return Err(Fault::Denied);
    }
    let at = clock_ms()?;
    let (role, kind) = match event.observation {
        w::ObservationKind::MtlsAccepted => ("egress", "mtls_accepted"),
        w::ObservationKind::IngressClosed => ("ingress", "ingress_closed"),
        w::ObservationKind::EgressClosed => ("egress", "egress_closed"),
    };
    let tx = authority
        .store
        .connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let stored:String = tx.query_row(
        "SELECT grant_binding FROM enforcer_issue WHERE grant_id=?1 AND enforcer=?2 AND instance=?3 AND gateway_boot=?4",
        params![event.grant.grant.as_str(),role,event.enforcer_instance.as_str(),boot.to_string()],|r|r.get(0)
    ).optional()?.ok_or(Fault::Denied)?;
    let grant: w::GrantBinding = serde_json::from_str(&stored).map_err(|_| Fault::Storage)?;
    if grant != event.grant {
        return Err(Fault::Denied);
    }
    // A socket instance has precisely one peer and TLS connection throughout
    // its life. Duplicate terminal reports can be retried after a lost reply.
    let host = event.host.to_string();
    let changed: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM gateway_observation WHERE grant_id=?1 AND enforcer=?2 AND instance=?3
         AND (host<>?4 OR tls_connection<>?5))",
        params![event.grant.grant.as_str(),role,event.enforcer_instance.as_str(),host,event.tls_connection.as_str()],|r|r.get(0)
    )?;
    if changed {
        return Err(Fault::Denied);
    }
    tx.execute("INSERT OR IGNORE INTO gateway_observation(grant_id,enforcer,instance,observation,host,tls_connection,received_at_ms)
        VALUES(?1,?2,?3,?4,?5,?6,?7)",params![event.grant.grant.as_str(),role,event.enforcer_instance.as_str(),kind,host,event.tls_connection.as_str(),at as i64])?;
    tx.commit()?;
    Ok(())
}
