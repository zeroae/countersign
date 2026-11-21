CREATE TABLE IF NOT EXISTS device (
    integrator TEXT NOT NULL,
    owner TEXT NOT NULL,
    pairing TEXT NOT NULL,
    key_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation > 0),
    PRIMARY KEY (integrator, owner, pairing)
) STRICT;

CREATE TABLE IF NOT EXISTS approval (
    id TEXT PRIMARY KEY NOT NULL,
    integrator TEXT NOT NULL,
    owner TEXT NOT NULL,
    context TEXT NOT NULL,
    workload TEXT NOT NULL,
    workload_generation INTEGER NOT NULL CHECK (workload_generation > 0),
    entry_id TEXT NOT NULL,
    entry_version INTEGER NOT NULL CHECK (entry_version > 0),
    scope TEXT NOT NULL,
    initiating_origin TEXT NOT NULL,
    max_duration INTEGER NOT NULL CHECK (max_duration > 0),
    pending_until INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending','approved','denied','cancelled','expired','replaced')),
    current INTEGER NOT NULL DEFAULT 1 CHECK (current IN (0,1))
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS current_scope ON approval (
    integrator, owner, context, workload, workload_generation,
    entry_id, entry_version, scope
) WHERE current = 1;

CREATE TABLE IF NOT EXISTS offer (
    id TEXT PRIMARY KEY NOT NULL,
    approval TEXT NOT NULL REFERENCES approval(id),
    pairing TEXT NOT NULL,
    key_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    UNIQUE (approval, pairing, key_id, generation)
) STRICT;

CREATE TABLE IF NOT EXISTS approved_grant (
    id TEXT PRIMARY KEY NOT NULL,
    approval TEXT NOT NULL UNIQUE REFERENCES approval(id),
    offer TEXT NOT NULL UNIQUE REFERENCES offer(id),
    certificate BLOB NOT NULL CHECK (length(certificate) = 32),
    expires_at INTEGER NOT NULL,
    -- The selected leaf's names and own not-after; NULL for grants recorded
    -- before the Broker kept them.
    subject TEXT, issuer TEXT, not_after INTEGER
) STRICT;

CREATE TABLE IF NOT EXISTS decision (
    offer TEXT NOT NULL REFERENCES offer(id),
    id TEXT NOT NULL,
    payload TEXT NOT NULL,
    disposition TEXT NOT NULL CHECK(disposition IN ('committed', 'already_resolved')),
    PRIMARY KEY (offer, id)
) STRICT;

CREATE TABLE IF NOT EXISTS audit (
    event_id TEXT PRIMARY KEY NOT NULL,
    approval TEXT NOT NULL REFERENCES approval(id),
    kind TEXT NOT NULL,
    actor_offer TEXT REFERENCES offer(id),
    occurred_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS outbox (
    event_id TEXT PRIMARY KEY NOT NULL REFERENCES audit(event_id),
    approval TEXT NOT NULL REFERENCES approval(id)
) STRICT;

CREATE TABLE IF NOT EXISTS enrollment (
    pairing TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    integrator TEXT NOT NULL,
    key_id TEXT NOT NULL,
    public_sec1 BLOB NOT NULL CHECK(length(public_sec1) = 65)
) STRICT;

CREATE TABLE IF NOT EXISTS workload_binding (
    integrator TEXT NOT NULL, owner TEXT NOT NULL, context TEXT NOT NULL,
    instance TEXT NOT NULL, generation INTEGER NOT NULL CHECK(generation > 0),
    retired INTEGER NOT NULL CHECK(retired IN(0,1)),
    PRIMARY KEY(integrator, owner, context, instance)
) STRICT;

CREATE TABLE IF NOT EXISTS push_subscription (
    owner TEXT NOT NULL, endpoint TEXT PRIMARY KEY NOT NULL, subscription TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS push_attempt (
    approval TEXT NOT NULL REFERENCES approval(id) ON DELETE CASCADE,
    endpoint TEXT NOT NULL REFERENCES push_subscription(endpoint) ON DELETE CASCADE,
    retry_at INTEGER NOT NULL, PRIMARY KEY(approval,endpoint)
) STRICT;

CREATE TABLE IF NOT EXISTS closed_context (
    integrator TEXT NOT NULL, owner TEXT NOT NULL, context TEXT NOT NULL,
    PRIMARY KEY (integrator,owner,context)
) STRICT;
CREATE TABLE IF NOT EXISTS suspended_user (
    integrator TEXT NOT NULL, owner TEXT NOT NULL,
    PRIMARY KEY (integrator,owner)
) STRICT;
CREATE TABLE IF NOT EXISTS denied_destination (
    integrator TEXT NOT NULL, owner TEXT NOT NULL, entry_id TEXT NOT NULL,
    PRIMARY KEY (integrator,owner,entry_id)
) STRICT;
CREATE TABLE IF NOT EXISTS emergency_stop (
    integrator TEXT PRIMARY KEY NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS security_event (
    id TEXT PRIMARY KEY, integrator TEXT NOT NULL, owner TEXT,
    kind TEXT NOT NULL, actor TEXT, target TEXT, observed_address TEXT,
    occurred_at_ms INTEGER NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS security_user ON security_event(integrator,owner,occurred_at_ms);

CREATE TABLE IF NOT EXISTS renewal (
    request TEXT PRIMARY KEY REFERENCES approval(id),
    predecessor TEXT UNIQUE NOT NULL REFERENCES approval(id)
) STRICT;

CREATE TABLE IF NOT EXISTS presence (
    pairing TEXT PRIMARY KEY REFERENCES enrollment(pairing) ON DELETE CASCADE,
    connected_at INTEGER NOT NULL, address TEXT
) STRICT;

CREATE TABLE IF NOT EXISTS credential_use (
    integrator TEXT NOT NULL, owner TEXT NOT NULL, fingerprint BLOB NOT NULL,
    pairing TEXT NOT NULL, key_id TEXT NOT NULL, generation INTEGER NOT NULL,
    observed_at_ms INTEGER NOT NULL,
    PRIMARY KEY(integrator,owner,fingerprint,pairing)
) STRICT;

CREATE TABLE IF NOT EXISTS deployment (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    integrator TEXT NOT NULL, verified_origin TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS issuer_stop (
    integrator TEXT PRIMARY KEY NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS enforcer_issue (
    grant_id TEXT NOT NULL REFERENCES approved_grant(id) ON DELETE CASCADE,
    enforcer TEXT NOT NULL CHECK(enforcer IN ('ingress','egress')), instance TEXT NOT NULL,
    gateway_boot TEXT NOT NULL, grant_binding TEXT NOT NULL, expires_at_ms INTEGER NOT NULL,
    generation INTEGER NOT NULL, sequence INTEGER NOT NULL, closed INTEGER NOT NULL DEFAULT 0 CHECK(closed IN (0,1)),
    PRIMARY KEY(grant_id,enforcer,instance)
) STRICT;

CREATE TABLE IF NOT EXISTS gateway_observation (
    grant_id TEXT NOT NULL REFERENCES approved_grant(id) ON DELETE CASCADE,
    enforcer TEXT NOT NULL, instance TEXT NOT NULL, observation TEXT NOT NULL,
    host TEXT NOT NULL, tls_connection TEXT NOT NULL, received_at_ms INTEGER NOT NULL,
    PRIMARY KEY(grant_id,enforcer,instance,observation)
) STRICT;

CREATE TABLE IF NOT EXISTS working_identity (
    approval TEXT PRIMARY KEY REFERENCES approval(id) ON DELETE CASCADE,
    grant_id TEXT NOT NULL UNIQUE REFERENCES approved_grant(id) ON DELETE CASCADE,
    activation TEXT NOT NULL, public_chain TEXT NOT NULL,
    verified_at_ms INTEGER NOT NULL, valid_until_ms INTEGER NOT NULL
) STRICT;
CREATE TRIGGER IF NOT EXISTS drop_ended_identity AFTER UPDATE OF state ON approval
WHEN NEW.state <> 'approved'
BEGIN
    DELETE FROM working_identity WHERE approval=NEW.id;
END;
