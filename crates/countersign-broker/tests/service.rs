use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use countersign_broker::{config::Config, service::Service};
use futures_util::{SinkExt, StreamExt};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use ring::{
    digest,
    rand::SystemRandom,
    signature::{
        ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _,
    },
};
use serde_json::{Value, json};
use std::{
    fs,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tempfile::TempDir;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{Message, client::IntoClientRequest},
};
use uuid::Uuid;

const ADMIN: &str = "test-only-dedicated-administrator-secret";
const BACKEND: &str = "integration-test-dedicated-service-secret";
type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
struct Harness {
    addr: String,
    client: reqwest::Client,
    leaf: Vec<u8>,
    key: EcdsaKeyPair,
    _dir: TempDir,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Harness {
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Broker integration test CA");
        let root_key = KeyPair::generate().unwrap();
        let ca = params.self_signed(&root_key).unwrap();
        let issuer = Issuer::from_params(&params, &root_key);
        let client_key = KeyPair::generate().unwrap();
        let mut identity = CertificateParams::default();
        identity.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let leaf = identity
            .signed_by(&client_key, &issuer)
            .unwrap()
            .der()
            .to_vec();
        let key = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            &client_key.serialize_der(),
            &SystemRandom::new(),
        )
        .unwrap();
        for (name, secret) in [
            ("backend", BACKEND),
            ("admin", ADMIN),
            ("hmac", "a-different-service-secret-with-32-bytes"),
            ("ca.pem", ca.pem().as_str()),
        ] {
            fs::write(dir.path().join(name), secret).unwrap();
        }
        let cfg:Config=serde_json::from_value(json!({
            "admin_token_file":dir.path().join("admin"),"integrator":"integration","origin":"integrator.test:443","listen":"127.0.0.1:0",
            "database":dir.path().join("store.db"),"client_ca_file":dir.path().join("ca.pem"),
            "workload_hmac_key_file":dir.path().join("hmac"),"backend_token_file":dir.path().join("backend"),
            "destinations":[{"id":"test","version":1,"pattern":"upstream.test:443"}]
        })).unwrap();
        let app = Service::open(&cfg).unwrap().router();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .no_proxy()
            .build()
            .unwrap();
        Self {
            addr,
            client,
            leaf,
            key,
            _dir: dir,
            server,
        }
    }
    async fn post(&self, path: &str, auth: &str, body: Value) -> reqwest::Response {
        self.client
            .post(format!("http://{}/v1/{path}", self.addr))
            .header(
                "x-countersign-gateway-instance",
                "fcd50bed-2958-4ae3-9f36-102636ee1cce",
            )
            .bearer_auth(auth)
            .json(&body)
            .send()
            .await
            .unwrap()
    }
    async fn socket(&self) -> Socket {
        let mut req = format!("ws://{}/v1/companion", self.addr)
            .into_client_request()
            .unwrap();
        req.headers_mut()
            .insert("sec-websocket-protocol", "countersign.v1".parse().unwrap());
        connect_async(req).await.unwrap().0
    }
}
fn frame(kind: &str, body: Value) -> Value {
    json!({"version":1,"request_id":Uuid::new_v4().to_string(),"type":kind,"body":body})
}
async fn send(socket: &mut Socket, frame: Value) {
    socket
        .send(Message::Text(frame.to_string().into()))
        .await
        .unwrap();
}
async fn receive(socket: &mut Socket, kind: &str) -> Value {
    let timeout = tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            let msg = socket.next().await.unwrap().unwrap();
            let v: Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
            if v["type"] == kind {
                return v;
            }
            assert_eq!(
                v["type"], "notify",
                "unexpected message while awaiting {kind}: {v}"
            );
        }
    });
    timeout.await.unwrap()
}
fn millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
fn device_key() -> EcdsaKeyPair {
    let rand = SystemRandom::new();
    let key = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rand).unwrap();
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, key.as_ref(), &rand).unwrap()
}
async fn prove(socket: &mut Socket, key: &EcdsaKeyPair) -> Value {
    let ch = receive(socket, "challenge").await["body"].clone();
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"countersign-device-proof+jws"}"#);
    let payload = URL_SAFE_NO_PAD.encode(json!({"version":1,"challenge":ch}).to_string());
    let input = format!("{header}.{payload}");
    let signature = key.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
    let proof = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()));
    send(
        socket,
        frame(
            "proof",
            json!({"connection":ch["connection"],"compact_jws":proof}),
        ),
    )
    .await;
    receive(socket, "authenticated").await["body"].clone()
}

#[tokio::test]
async fn authenticated_consent_signing_reconnect_and_revocation() {
    let h = Harness::start().await;
    let mut sock = h.socket().await;
    let pairing_key = device_key();
    send(
        &mut sock,
        frame(
            "enroll",
            json!({"public_sec1":STANDARD.encode(pairing_key.public_key().as_ref())}),
        ),
    )
    .await;
    let pending = receive(&mut sock, "pairing_pending").await["body"].clone();
    let confirm = json!({"user":"u","attempt":pending["attempt"],"code":pending["code"]});
    assert_eq!(
        h.post("backend/pairings/confirm", "wrong", confirm.clone())
            .await
            .status(),
        401
    );
    assert_eq!(
        h.post("backend/pairings/confirm", BACKEND, confirm.clone())
            .await
            .status(),
        204
    );
    assert_eq!(
        h.post("backend/pairings/confirm", BACKEND, confirm)
            .await
            .status(),
        404
    );
    let device = prove(&mut sock, &pairing_key).await;
    let credentials: Value = h
        .post(
            "backend/workloads",
            BACKEND,
            json!({"user":"u","context":"job","workload":"instance","workload_generation":1}),
        )
        .await
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = credentials["token"].as_str().unwrap();
    let connect = frame(
        "connect",
        json!({"workload":credentials["binding"],"host":"upstream.test:443"}),
    );
    let initial: Value = h
        .post("gateway/admit", token, connect.clone())
        .await
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(initial["type"], "pending");
    send(&mut sock, frame("fetch", initial["body"].clone())).await;
    let offered = receive(&mut sock, "offer").await["body"].clone();
    let hash = digest::digest(&digest::SHA256, &h.leaf);
    let decide = frame(
        "decide",
        json!({"binding":offered["binding"],"answer":{"approve":{
            "duration_s":900,"chain":[STANDARD.encode(&h.leaf)],"cert_sha256":STANDARD.encode(hash.as_ref())
        }}}),
    );
    send(&mut sock, decide).await;
    let activation = receive(&mut sock, "activate").await["body"].clone();
    send(&mut sock, frame("activated", activation.clone())).await;
    // FIFO on one connection makes this response a barrier for activation acknowledgment.
    send(&mut sock, frame("inbox", json!({}))).await;
    receive(&mut sock, "inbox").await;
    let grant = &activation["grant"];
    let active: Value = h
        .post("gateway/admit", token, connect)
        .await
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(active["body"]["chain"][0], STANDARD.encode(&h.leaf));
    let lease = |sequence: u64| {
        frame(
            "renew_lease",
            json!({"grant":grant,"enforcer":"ingress","instance":"gateway","generation":1,"sequence":sequence}),
        )
    };
    let lease_reply: Value = h
        .post("gateway/lease", token, lease(1))
        .await
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        lease_reply["body"]["disposition"]["granted"]["budget_ms"]
            .as_u64()
            .unwrap()
            <= 30_000
    );
    assert_eq!(h.post("gateway/lease", token, lease(1)).await.status(), 403);
    let swapped = h
        .client
        .post(format!("http://{}/v1/gateway/lease", h.addr))
        .header("x-countersign-gateway-instance", Uuid::new_v4().to_string())
        .bearer_auth(token)
        .json(&lease(3))
        .send()
        .await
        .unwrap();
    assert_eq!(swapped.status(), 403);
    let observe = |event: &str, instance: &str| {
        frame(
            "observed",
            json!({
                "grant":grant,"host":"upstream.test:443","enforcer_instance":instance,"tls_connection":"socket-1","observation":event
            }),
        )
    };
    assert_eq!(
        h.post(
            "gateway/observe",
            token,
            observe("mtls_accepted", "gateway")
        )
        .await
        .status(),
        403
    );
    let mut egress = lease(1);
    egress["body"]["enforcer"] = "egress".into();
    egress["body"]["instance"] = "site-leg".into();
    assert_eq!(h.post("gateway/lease", token, egress).await.status(), 200);
    assert_eq!(
        h.post(
            "gateway/observe",
            token,
            observe("mtls_accepted", "site-leg")
        )
        .await
        .status(),
        200
    );
    let status_req = json!({"user":"u","id":offered["binding"]["approval"]});
    let view: Value = h
        .post("backend/status", BACKEND, status_req.clone())
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(view["ready"], true);
    assert_eq!(view["upstream_mtls_accepted"], true);
    assert_eq!(view["egress_closed_count"], 0);
    let mut data = vec![0x20u8; 64];
    data.extend_from_slice(b"TLS 1.3, client CertificateVerify\0");
    data.extend_from_slice(&[5u8; 32]);
    let op = json!({"grant":grant,"host":"upstream.test:443","tls_connection":"socket-1","operation":"op-1"});
    let sign = frame(
        "sign",
        json!({"binding":op,"tls":"tls13","scheme":"ecdsa_nistp256_sha256","certificate_verify":STANDARD.encode(&data),"deadline_ms":millis()+10_000}),
    );
    let response = h.post("gateway/sign", token, sign.clone());
    let device_reply = async {
        let operation = receive(&mut sock, "sign").await;
        let sig = h.key.sign(&SystemRandom::new(), &data).unwrap();
        let mut signed = frame(
            "signed",
            json!({"binding":op,"signature":STANDARD.encode(sig.as_ref())}),
        );
        signed["request_id"] = operation["request_id"].clone();
        send(&mut sock, signed).await;
    };
    let (signed, _) = tokio::join!(response, device_reply);
    assert_eq!(signed.status(), 200);
    assert_eq!(h.post("gateway/sign", token, sign).await.status(), 403);
    sock.close(None).await.unwrap();
    drop(sock);
    assert_eq!(h.post("gateway/lease", token, lease(2)).await.status(), 200);
    let mut second = h.socket().await;
    send(
        &mut second,
        frame(
            "authenticate",
            json!({"pairing":device["pairing"],"key":device["key"]}),
        ),
    )
    .await;
    assert_ne!(
        prove(&mut second, &pairing_key).await["channel_generation"],
        device["channel_generation"]
    );
    let snapshot = receive(&mut second, "activate").await;
    assert_eq!(snapshot["body"]["grant"]["grant"], grant["grant"]);
    send(&mut second, frame("activated", snapshot["body"].clone())).await;
    send(&mut second, frame("inbox", json!({}))).await;
    receive(&mut second, "inbox").await;
    let op = json!({"grant":snapshot["body"]["grant"],"host":"upstream.test:443","tls_connection":"socket-2","operation":"op-2"});
    let request = frame(
        "sign",
        json!({"binding":op,"tls":"tls13","scheme":"ecdsa_nistp256_sha256",
        "certificate_verify":STANDARD.encode(&data),"deadline_ms":millis()+10000}),
    );
    let pending_sign = h.post("gateway/sign", token, request);
    let withdraw = async {
        let asked = receive(&mut second, "sign").await;
        assert_eq!(
            h.post(
                "backend/revoke",
                BACKEND,
                json!({"user":"u","id":offered["binding"]["approval"]})
            )
            .await
            .status(),
            204
        );
        receive(&mut second, "retire").await;
        let sig = h.key.sign(&SystemRandom::new(), &data).unwrap();
        let mut late = frame(
            "signed",
            json!({"binding":op,"signature":STANDARD.encode(sig.as_ref())}),
        );
        late["request_id"] = asked["request_id"].clone();
        send(&mut second, late).await;
        assert_eq!(
            receive(&mut second, "error").await["body"]["code"],
            "unavailable"
        );
    };
    let watch = h.post("gateway/watch", token, frame("watch", grant.clone()));
    let (refused, _, retired) = tokio::join!(pending_sign, withdraw, watch);
    assert_eq!(
        retired
            .error_for_status()
            .unwrap()
            .json::<Value>()
            .await
            .unwrap()["type"],
        "retire"
    );
    assert!(!refused.status().is_success());
    let db = rusqlite::Connection::open(h._dir.path().join("store.db")).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM working_identity", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    let n = json!({"id":offered["binding"]["approval"]});
    send(&mut second, frame("revoke_approval", n.clone())).await;
    assert_eq!(receive(&mut second, "revoke_recorded").await["body"], n);
    let (mut other, _) = pair(&h, "u").await;
    send(&mut other, frame("revoke_approval", n)).await;
    assert_eq!(
        receive(&mut other, "error").await["body"]["code"],
        "unavailable"
    );
    for _ in 0..2 {
        assert_eq!(
            h.post(
                "gateway/observe",
                token,
                observe("egress_closed", "site-leg")
            )
            .await
            .status(),
            200
        );
    }
    let ended: Value = h
        .post("backend/status", BACKEND, status_req)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(ended["state"], "cancelled");
    assert_eq!(ended["ready"], false);
    assert_eq!(ended["egress_closed_count"], 1);
    assert!(
        !h.post("gateway/lease", token, lease(3))
            .await
            .status()
            .is_success()
    );
}

async fn pair(h: &Harness, user: &str) -> (Socket, Value) {
    let mut socket = h.socket().await;
    let key = device_key();
    send(
        &mut socket,
        frame(
            "enroll",
            json!({"public_sec1":STANDARD.encode(key.public_key().as_ref())}),
        ),
    )
    .await;
    let attempt = receive(&mut socket, "pairing_pending").await["body"].clone();
    assert_eq!(
        h.post(
            "backend/pairings/confirm",
            BACKEND,
            json!({"user":user,"attempt":attempt["attempt"],"code":attempt["code"]})
        )
        .await
        .status(),
        204
    );
    let device = prove(&mut socket, &key).await;
    (socket, device)
}
#[tokio::test]
async fn device_snapshot_and_notices_are_scoped_and_forget_fences_reconnect() {
    let h = Harness::start().await;
    let (mut first, one) = pair(&h, "u").await;
    let (_second, two) = pair(&h, "u").await;
    let (mut other, _) = pair(&h, "another").await;
    let concurrent = receive(&mut first, "notify").await["body"].clone();
    send(&mut first, frame("fetch", concurrent.clone())).await;
    let event = receive(&mut first, "security_event").await["body"].clone();
    assert_eq!(event["kind"], "concurrent_devices");
    assert_eq!(event["actor"], two);
    send(&mut other, frame("fetch", concurrent)).await;
    receive(&mut other, "error").await;
    send(&mut first, frame("devices", json!({}))).await;
    assert_eq!(
        receive(&mut first, "devices").await["body"]["devices"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    // A changed snapshot or any attempt to include the actor is rejected.
    send(
        &mut first,
        frame(
            "forget_devices",
            json!({"targets":[one,two],"all_others":true}),
        ),
    )
    .await;
    receive(&mut first, "error").await;
    send(
        &mut first,
        frame("forget_devices", json!({"targets":[two],"all_others":true})),
    )
    .await;
    let left = receive(&mut first, "devices").await["body"]["devices"].clone();
    assert_eq!(left.as_array().unwrap().len(), 1);
    assert_eq!(left[0]["binding"], one);
    send(&mut first, frame("inbox", json!({}))).await;
    let ids = receive(&mut first, "inbox").await["body"]["ids"]
        .as_array()
        .unwrap()
        .clone();
    let mut forgotten = false;
    for id in ids {
        send(&mut first, frame("fetch", json!({"id":id}))).await;
        let e = receive(&mut first, "security_event").await["body"].clone();
        if e["kind"] == "devices_forgotten" {
            assert_eq!(e["actor"], one);
            assert_eq!(e["targets"][0], two);
            forgotten = true;
        }
    }
    assert!(forgotten);
    let mut stale = h.socket().await;
    send(
        &mut stale,
        frame(
            "authenticate",
            json!({"pairing":two["pairing"],"key":two["key"]}),
        ),
    )
    .await;
    let closed = tokio::time::timeout(Duration::from_secs(3), stale.next())
        .await
        .unwrap();
    assert!(!matches!(closed, Some(Ok(Message::Text(_)))));
}

#[tokio::test]
async fn admin_authority_and_context_tombstones_gate_workload_admission() {
    let h = Harness::start().await;
    let creds: Value = h
        .post(
            "backend/workloads",
            BACKEND,
            json!({"user":"u","context":"job","workload":"job-a","workload_generation":1}),
        )
        .await
        .json()
        .await
        .unwrap();
    let request = json!({"binding":creds["binding"],"host":"upstream.test:443"});
    for op in [
        json!({"operation":"destination","user":"u","entry":"test","denied":true}),
        json!({"operation":"account","user":"u","blocked":true}),
        json!({"operation":"emergency","stopped":true}),
        json!({"operation":"issuer","stopped":true}),
    ] {
        assert_eq!(
            h.post("admin/control", BACKEND, op.clone()).await.status(),
            401
        );
        assert_eq!(
            h.post("admin/control", ADMIN, op.clone()).await.status(),
            204
        );
        assert_eq!(
            h.post("backend/requests", BACKEND, request.clone())
                .await
                .status(),
            403
        );
        let mut restore = op;
        for k in ["denied", "blocked", "stopped"] {
            if restore.get(k).is_some() {
                restore[k] = Value::Bool(false);
            }
        }
        assert_eq!(h.post("admin/control", ADMIN, restore).await.status(), 204);
        assert_eq!(
            h.post("backend/requests", BACKEND, request.clone())
                .await
                .status(),
            200
        );
    }
    assert_eq!(
        h.post(
            "backend/contexts/close",
            BACKEND,
            json!({"user":"u","context":"job"})
        )
        .await
        .status(),
        204
    );
    assert_eq!(
        h.post("backend/requests", BACKEND, request).await.status(),
        403
    );
}
