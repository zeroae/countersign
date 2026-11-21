use countersign_broker::*;
use countersign_protocol::{ApprovalMode, DestinationEntry, DestinationPolicy, Origin};
use rusqlite::{Connection, params};
use std::{
    num::NonZeroU32,
    sync::{Arc, Barrier},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};
use tempfile::TempDir;
use uuid::Uuid;

struct Fixture {
    dir: TempDir,
    store: SqliteApprovalStore,
    workload: Workload,
    policy: DestinationPolicy,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteApprovalStore::open(dir.path().join("authority.db")).unwrap();
        let owner = Owner {
            integrator: "site".into(),
            user: "user".into(),
        };
        let workload = Workload {
            owner,
            context: "context".into(),
            instance: "workload".into(),
            generation: 1,
        };
        let policy = DestinationPolicy::new(vec![
            DestinationEntry::new("sites", 1, "*.example:443", ApprovalMode::WholeWildcard)
                .unwrap(),
        ])
        .unwrap();
        Self {
            dir,
            store,
            workload,
            policy,
        }
    }

    fn connect(&self) -> Connection {
        Connection::open(self.dir.path().join("authority.db")).unwrap()
    }

    fn request(&mut self, host: &str, trigger: Trigger) -> Approval {
        self.store
            .request(
                &self.workload,
                &self.policy,
                &Origin::parse(host).unwrap(),
                NonZeroU32::new(7200).unwrap(),
                trigger,
            )
            .unwrap()
    }

    fn session(&mut self, pairing: &str) -> DeviceSession {
        self.store
            .authenticate_device(&self.workload.owner, pairing, "key")
            .unwrap()
    }
}

fn approve(cert: u8, seconds: u32) -> Decision {
    Decision::Approve {
        certificate: ValidatedCertificate {
            sha256: [cert; 32],
            not_after_unix_seconds: i64::MAX,
            subject: "CN=user".into(),
            issuer: "CN=issuer".into(),
            leaf_not_after_unix_seconds: i64::MAX,
        },
        duration_seconds: NonZeroU32::new(seconds).unwrap(),
    }
}

#[test]
fn separate_connections_commit_one_choice_and_retry_idempotently() {
    let mut f = Fixture::new();
    let request = f.request("a.example", Trigger::Traffic);
    let scopes_join = f.request("b.example", Trigger::Traffic);
    assert_eq!(request, scopes_join);
    assert_eq!(request.initiating_origin, "a.example:443");
    assert_eq!(request.scope, "*.example:443");
    let barrier = Arc::new(Barrier::new(2));
    let mut threads = Vec::new();
    for cert in [1, 2] {
        let session = f.session(&format!("device-{cert}"));
        let offer = f.store.offer(&session, request.id).unwrap();
        assert_eq!(f.store.offer(&session, request.id).unwrap().id, offer.id);
        let mut store = SqliteApprovalStore::open(f.dir.path().join("authority.db")).unwrap();
        let barrier = Arc::clone(&barrier);
        threads.push(thread::spawn(move || {
            let response = Uuid::new_v4();
            let decision = approve(cert, 3600);
            barrier.wait();
            let result = store
                .decide(&session, offer.id, response, &decision)
                .unwrap();
            assert_eq!(
                store
                    .decide(&session, offer.id, response, &decision)
                    .unwrap(),
                result
            );
            assert!(matches!(
                store.decide(&session, offer.id, response, &Decision::Cancel),
                Err(StoreError::DecisionConflict)
            ));
            (cert, result)
        }));
    }
    let winners: Vec<_> = threads
        .into_iter()
        .map(|t| t.join().unwrap())
        .filter_map(|(cert, result)| (result == Disposition::Committed).then_some(cert))
        .collect();
    assert_eq!(winners.len(), 1);
    let grant = f
        .store
        .approved_grant(&f.workload, request.id)
        .unwrap()
        .unwrap();
    assert_eq!(grant.certificate_sha256, [winners[0]; 32]);
    assert_eq!(grant.pairing, format!("device-{}", winners[0]));
    let db = f.connect();
    let count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM audit JOIN outbox USING(event_id)
        WHERE audit.approval = ?1 AND audit.kind = 'approved'",
            [request.id.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
    assert_eq!(
        f.request("a.example", Trigger::ExplicitConnect).id,
        request.id
    );
    let mut other_workload = f.workload.clone();
    other_workload.generation += 1;
    assert!(
        f.store
            .approved_grant(&other_workload, request.id)
            .unwrap()
            .is_none()
    );
}

#[test]
fn only_an_owned_current_offer_can_decide() {
    let mut f = Fixture::new();
    let request = f.request("a.example", Trigger::Traffic);
    let first = f.session("device");
    let offered = f.store.offer(&first, request.id).unwrap();
    for alien in [
        Owner {
            integrator: "other".into(),
            user: "user".into(),
        },
        Owner {
            integrator: "site".into(),
            user: "other".into(),
        },
    ] {
        let foreign = f
            .store
            .authenticate_device(&alien, "device", "key")
            .unwrap();
        assert!(matches!(
            f.store.offer(&foreign, request.id),
            Err(StoreError::Unavailable)
        ));
        assert!(matches!(
            f.store
                .decide(&foreign, offered.id, Uuid::new_v4(), &Decision::Deny),
            Err(StoreError::Unavailable)
        ));
    }
    assert!(matches!(
        f.store
            .authenticate_device(&f.workload.owner, "device", "replacement-key"),
        Err(StoreError::Unavailable)
    ));
    let current = f.session("device");
    for session in [&first, &current] {
        assert!(matches!(
            f.store
                .decide(session, offered.id, Uuid::new_v4(), &Decision::Deny),
            Err(StoreError::Unavailable)
        ));
    }
    let renewed = f.store.offer(&current, request.id).unwrap();
    assert_ne!(offered.id, renewed.id);
    assert_eq!(
        f.store
            .decide(&current, renewed.id, Uuid::new_v4(), &Decision::Deny)
            .unwrap(),
        Disposition::Committed
    );
    assert_eq!(
        f.request("a.example", Trigger::Traffic).state,
        ApprovalState::Denied
    );
    let retry = f.request("b.example", Trigger::ExplicitConnect);
    assert_ne!(retry.id, request.id);
    assert_eq!(retry.state, ApprovalState::Pending);
    assert_eq!(
        f.store
            .decide(&current, renewed.id, Uuid::new_v4(), &approve(1, 60))
            .unwrap(),
        Disposition::AlreadyResolved
    );
}

#[test]
fn expired_requests_cannot_create_grants_and_validation_cannot_extend_consent() {
    let mut f = Fixture::new();
    let request = f.request("a.example", Trigger::Traffic);
    let device = f.session("device");
    let offer = f.store.offer(&device, request.id).unwrap();
    let db = f.connect();
    db.execute(
        "UPDATE approval SET pending_until = unixepoch() WHERE id=?1",
        [request.id.to_string()],
    )
    .unwrap();
    assert_eq!(
        f.store
            .decide(&device, offer.id, Uuid::new_v4(), &approve(9, 60))
            .unwrap(),
        Disposition::AlreadyResolved
    );
    assert_eq!(
        f.request("a.example", Trigger::Traffic).state,
        ApprovalState::Expired
    );
    assert!(
        f.store
            .approved_grant(&f.workload, request.id)
            .unwrap()
            .is_none()
    );
    let retry = f.request("a.example", Trigger::ExplicitConnect);
    let offer = f.store.offer(&device, retry.id).unwrap();
    assert!(matches!(
        f.store
            .decide(&device, offer.id, Uuid::new_v4(), &approve(1, 7201)),
        Err(StoreError::InvalidInput)
    ));
    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + 60;
    let decision = Decision::Approve {
        certificate: ValidatedCertificate {
            sha256: [9; 32],
            not_after_unix_seconds: expiry,
            subject: "CN=user".into(),
            issuer: "CN=issuer".into(),
            leaf_not_after_unix_seconds: expiry,
        },
        duration_seconds: NonZeroU32::new(7200).unwrap(),
    };
    f.store
        .decide(&device, offer.id, Uuid::new_v4(), &decision)
        .unwrap();
    assert_eq!(
        f.store
            .approved_grant(&f.workload, retry.id)
            .unwrap()
            .unwrap()
            .expires_at,
        expiry
    );
}

#[test]
fn publication_failure_rolls_back_the_grant_and_audit() {
    let mut f = Fixture::new();
    let request = f.request("a.example", Trigger::Traffic);
    let device = f.session("device");
    let offer = f.store.offer(&device, request.id).unwrap();
    let db = f.connect();
    db.execute_batch(
        "CREATE TRIGGER no_publish BEFORE INSERT ON outbox BEGIN
        SELECT RAISE(ABORT,'outbox unavailable'); END;",
    )
    .unwrap();
    let response = Uuid::new_v4();
    assert!(matches!(
        f.store.decide(&device, offer.id, response, &approve(7, 60)),
        Err(StoreError::Database(_))
    ));
    assert_eq!(
        f.request("a.example", Trigger::Traffic).state,
        ApprovalState::Pending
    );
    assert!(
        f.store
            .approved_grant(&f.workload, request.id)
            .unwrap()
            .is_none()
    );
    let events: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM audit WHERE approval=?1 AND kind='approved'",
            params![request.id.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(events, 0);
    db.execute_batch("DROP TRIGGER no_publish;").unwrap();
    assert_eq!(
        f.store
            .decide(&device, offer.id, response, &approve(7, 60))
            .unwrap(),
        Disposition::Committed
    );
}

#[test]
fn renewal_replaces_only_at_commit_and_rejection_preserves_existing_grant() {
    let mut f = Fixture::new();
    let active = f.request("a.example", Trigger::Traffic);
    let session = f.session("device");
    let offer = f.store.offer(&session, active.id).unwrap();
    f.store
        .decide(&session, offer.id, Uuid::new_v4(), &approve(1, 3600))
        .unwrap();
    let original = f
        .store
        .approved_grant(&f.workload, active.id)
        .unwrap()
        .unwrap();
    let renew = |f: &mut Fixture| {
        f.store
            .renew(
                &f.workload,
                &f.policy,
                active.id,
                NonZeroU32::new(7200).unwrap(),
            )
            .unwrap()
    };
    let cancelled = renew(&mut f);
    let first = f.store.offer(&session, cancelled.id).unwrap();
    f.store
        .decide(&session, first.id, Uuid::new_v4(), &Decision::Deny)
        .unwrap();
    assert_eq!(
        f.store.approved_grant(&f.workload, active.id).unwrap(),
        Some(original.clone())
    );
    let next = renew(&mut f);
    assert_ne!(next.id, cancelled.id);
    assert_eq!(renew(&mut f).id, next.id);
    assert_eq!(f.request("b.example", Trigger::Traffic).id, active.id);
    let second = f.store.offer(&session, next.id).unwrap();
    f.store
        .decide(&session, second.id, Uuid::new_v4(), &approve(2, 3600))
        .unwrap();
    assert!(
        f.store
            .approved_grant(&f.workload, active.id)
            .unwrap()
            .is_none()
    );
    assert_eq!(f.request("b.example", Trigger::Traffic).id, next.id);
    assert_eq!(
        f.store
            .approved_grant(&f.workload, next.id)
            .unwrap()
            .unwrap()
            .certificate_sha256,
        [2; 32]
    );
}

#[test]
fn winning_pairing_withdraws_consent_and_pending_renewal_idempotently() {
    let mut f = Fixture::new();
    let req = f.request("a.example", Trigger::Traffic);
    let winner = f.session("winner");
    let other = f.session("other");
    let offer = f.store.offer(&winner, req.id).unwrap();
    f.store
        .decide(&winner, offer.id, Uuid::new_v4(), &approve(1, 3600))
        .unwrap();
    let renewal = f
        .store
        .renew(&f.workload, &f.policy, req.id, NonZeroU32::MIN)
        .unwrap();
    let renewal_offer = f.store.offer(&other, renewal.id).unwrap();
    assert!(
        f.store
            .revoke(&f.workload.owner, Some(&other), req.id)
            .is_err()
    );
    let mut ids = f
        .store
        .revoke(&f.workload.owner, Some(&winner), req.id)
        .unwrap();
    ids.sort();
    let mut expected = vec![req.id, renewal.id];
    expected.sort();
    assert_eq!(ids, expected);
    assert!(
        f.store
            .revoke(&f.workload.owner, Some(&winner), req.id)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        f.store
            .decide(&other, renewal_offer.id, Uuid::new_v4(), &approve(2, 1))
            .unwrap(),
        Disposition::AlreadyResolved
    );
    assert!(
        f.store
            .approved_grant(&f.workload, req.id)
            .unwrap()
            .is_none()
    );
}

#[test]
fn opening_preview_database_migrates_lease_fences_transactionally() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("preview.db");
    let old = Connection::open(&path).unwrap();
    old.execute_batch("CREATE TABLE enforcer_issue (
      grant_id TEXT NOT NULL REFERENCES approved_grant(id) ON DELETE CASCADE,
      enforcer TEXT NOT NULL, instance TEXT NOT NULL, gateway_boot TEXT NOT NULL,
      grant_binding TEXT NOT NULL, expires_at_ms INTEGER NOT NULL, PRIMARY KEY(grant_id,enforcer,instance)
    ) STRICT;").unwrap();
    drop(old);
    drop(SqliteApprovalStore::open(&path).unwrap());
    let inspect = Connection::open(&path).unwrap();
    assert_eq!(
        inspect
            .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(inspect.query_row("SELECT count(*) FROM pragma_table_info('enforcer_issue') WHERE name IN ('closed','generation','sequence')",[],|r|r.get::<_,i64>(0)).unwrap(),3);
    inspect.pragma_update(None, "user_version", 99).unwrap();
    assert!(SqliteApprovalStore::open(&path).is_err());
}

#[test]
fn opening_an_older_store_adds_the_leaf_columns_to_existing_grants() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("authority.db");
    {
        let old = Connection::open(&path).unwrap();
        old.execute_batch(
            "CREATE TABLE approved_grant (
                id TEXT PRIMARY KEY NOT NULL,
                approval TEXT NOT NULL UNIQUE REFERENCES approval(id),
                offer TEXT NOT NULL UNIQUE REFERENCES offer(id),
                certificate BLOB NOT NULL CHECK (length(certificate) = 32),
                expires_at INTEGER NOT NULL
            ) STRICT;
            PRAGMA user_version = 1;",
        )
        .unwrap();
    }
    for _ in 0..2 {
        drop(SqliteApprovalStore::open(&path).unwrap());
    }
    let db = Connection::open(&path).unwrap();
    let columns: Vec<String> = db
        .prepare("SELECT name FROM pragma_table_info('approved_grant')")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    for column in ["subject", "issuer", "not_after"] {
        assert!(columns.iter().any(|c| c == column), "{columns:?}");
    }
    let version: i64 = db
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 1, "an older Broker can still open the store");
}
