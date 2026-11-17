use base64::{Engine, engine::general_purpose::STANDARD};
use countersign_protocol::wire::*;

const NOTIFY: &str =
    r#"{"version":1,"request_id":"request","type":"notify","body":{"id":"opaque-notice"}}"#;
#[test]
fn role_and_direction_are_checked_before_dispatch() {
    let notice = Frame::<BrokerToCompanion>::decode(NOTIFY.as_bytes()).unwrap();
    assert_eq!(notice.request_id.as_str(), "request");
    assert_eq!(notice.encode().unwrap(), NOTIFY.as_bytes());
    assert!(matches!(
        Frame::<CompanionToBroker>::decode(NOTIFY.as_bytes()),
        Err(FrameError::UnexpectedMessage)
    ));
    assert!(matches!(
        Frame::<GatewayToBroker>::decode(NOTIFY.as_bytes()),
        Err(FrameError::UnexpectedMessage)
    ));
    assert!(matches!(
        Frame::<BrokerToGateway>::decode(NOTIFY.as_bytes()),
        Err(FrameError::UnexpectedMessage)
    ));
}
#[test]
fn malformed_payloads_and_duplicate_keys_fail_closed() {
    for frame in [
        NOTIFY.replace(r#""version":1"#, r#""version":2"#),
        NOTIFY.replace(r#""version":1"#, r#""version":1,"version":1"#),
        NOTIFY.replace(r#""type":"notify""#, r#""type":"notify","type":"sign""#),
        NOTIFY.replace(r#""id":"opaque-notice""#, r#""id":"a","id":"b""#),
        NOTIFY.replace(r#""id":"opaque-notice""#, r#""id":"a","host":"secret""#),
        NOTIFY.replace(r#""request_id":"request""#, r#""request_id":"""#),
        NOTIFY.replace(r#""type":"notify""#, r#""type":"unknown""#),
        NOTIFY.replace(r#""version":1"#, r#""version":1,"other":1"#),
        format!("{NOTIFY} null"),
    ] {
        assert!(Frame::<BrokerToCompanion>::decode(frame.as_bytes()).is_err());
    }
    assert!(Frame::<BrokerToCompanion>::decode(&[255, 0]).is_err());
    assert!(matches!(
        Frame::<BrokerToCompanion>::decode(&vec![b'x'; MAX_FRAME_BYTES + 1]),
        Err(FrameError::FrameTooLarge)
    ));
    assert!(matches!(
        Frame::<BrokerToCompanion>::decode("[".repeat(MAX_JSON_DEPTH + 1).as_bytes()),
        Err(FrameError::TooDeep)
    ));
    let brackets = NOTIFY.replace("opaque-notice", &"[".repeat(MAX_JSON_DEPTH + 5));
    assert!(Frame::<BrokerToCompanion>::decode(brackets.as_bytes()).is_ok());
}
#[test]
fn request_and_response_bindings_survive_the_wire() {
    let body = r#"{"workload":{"integrator":"i","user":"u","context":"c","workload":"w","workload_generation":1},"host":"SVC.example:443"}"#;
    let input = format!(r#"{{"version":1,"request_id":"r","type":"connect","body":{body}}}"#);
    let frame = Frame::<GatewayToBroker>::decode(input.as_bytes()).unwrap();
    assert_eq!(
        frame.encode().unwrap(),
        input.replace("SVC.example", "svc.example").as_bytes()
    );
    let duplicate = input.replace(r#""user":"u""#, r#""user":"u","user":"other""#);
    assert!(Frame::<GatewayToBroker>::decode(duplicate.as_bytes()).is_err());
}
#[test]
fn certificate_and_signing_limits_apply_after_base64_decode() {
    let encode = |bytes: &[u8]| serde_json::to_string(&STANDARD.encode(bytes)).unwrap();
    assert!(serde_json::from_str::<SigningInput>(&encode(&vec![0; MAX_SIGNING_INPUT])).is_ok());
    assert!(
        serde_json::from_str::<SigningInput>(&encode(&vec![0; MAX_SIGNING_INPUT + 1])).is_err()
    );
    for chain in [
        "[]".into(),
        r#"[""]"#.into(),
        r#"["/==="]"#.into(),
        serde_json::to_string(&vec!["AA=="; MAX_CERTIFICATES + 1]).unwrap(),
        format!("[{},\"AA==\"]", encode(&vec![0; MAX_CHAIN_BYTES])),
    ] {
        assert!(serde_json::from_str::<PublicChain>(&chain).is_err());
    }
    let valid = PublicChain::new(vec![vec![42; 3]]).unwrap();
    assert_eq!(serde_json::to_string(&valid).unwrap(), r#"["Kioq"]"#);
}
