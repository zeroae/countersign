use countersign_protocol::{
    ApprovalMode::*, DestinationEntry, DestinationPolicy, DestinationScope, Origin, PolicyError,
};

fn origin(s: &str) -> Origin {
    Origin::parse(s).unwrap()
}

#[test]
fn all_consumers_share_canonical_wire_authorities() {
    let expected = origin("xn--bcher-kva.example:443");
    for host in [
        "BÜCHER.example",
        "bücher.example.",
        "XN--BCHER-KVA.example:443",
    ] {
        let actual = origin(host);
        assert_eq!(actual, expected);
        assert_eq!(actual.host(), "xn--bcher-kva.example");
        assert_eq!(actual.port(), 443);
        assert_eq!(actual.to_string(), "xn--bcher-kva.example:443");
    }
    assert_eq!(
        serde_json::from_str::<Origin>(r#""BÜCHER.example""#).unwrap(),
        expected
    );
    assert_eq!(
        serde_json::to_string(&expected).unwrap(),
        r#""xn--bcher-kva.example:443""#
    );
    assert_eq!(
        Origin::parse_connect("api.example"),
        Err(PolicyError::MissingPort)
    );
    assert_eq!(
        Origin::parse_connect("api.example:8443").unwrap().port(),
        8443
    );
}

#[test]
fn malformed_or_ambiguous_authorities_cannot_be_origins() {
    for invalid in [
        "",
        ".",
        " ",
        "api.example..",
        ".api.example",
        "api..example",
        "api.example\n",
        "[::1]:443",
        "::1",
        "127.0.0.1",
        "１２７.０.０.１",
        "127.1",
        "0177.0.1",
        "0X7F000001",
        "2130706433",
        "example:443:443",
        "example:",
        "example:0",
        "example:-4",
        "example:+443",
        "example:0443",
        "example:65536",
        "a.b:８０",
        "https://api.example",
        "api.example/a",
        "api.example\\evil",
        "api.example%2f",
        "evil@api.example",
        "api.example?x",
        "api.example#x",
        "*.foo.bar",
        "a.*.example",
        "abc_def",
        "x。.example",
        "api.example\u{0000}evil",
        "-abc.example",
        "xn--.example",
    ] {
        assert!(Origin::parse(invalid).is_err(), "accepted {invalid:?}");
    }
    assert!(Origin::parse(&format!("{}.example", "a".repeat(64))).is_err());
}

#[test]
fn broader_grant_tracks_its_rule_and_exact_overrides_win() {
    let group = DestinationEntry::new("teams", 1, "*.foo.bar:443", WholeWildcard).unwrap();
    assert_eq!(group.constraint_dns_name(), "foo.bar");
    let exact = DestinationEntry::new("payroll", 3, "secret.foo.bar", ExactHost).unwrap();
    for entries in [
        vec![group.clone(), exact.clone()],
        vec![exact.clone(), group.clone()],
    ] {
        let policy = DestinationPolicy::new(entries).unwrap();
        let grant = policy.scope_for(&origin("a.foo.bar")).unwrap();
        assert_eq!(grant.pattern().to_string(), "*.foo.bar:443");
        assert_eq!(grant.entry_id(), "teams");
        assert_eq!(grant.entry_version(), 1);
        assert!(policy.covers(&grant, &origin("b.foo.bar")));
        for denied in [
            "foo.bar",
            "x.y.foo.bar",
            "badfoo.bar",
            "a.foo.bar:8443",
            "secret.foo.bar",
        ] {
            assert!(!policy.covers(&grant, &origin(denied)), "{denied}");
        }
        assert_eq!(
            policy.resolve(&origin("secret.foo.bar")).unwrap().id(),
            "payroll"
        );
        let updated = DestinationPolicy::new(vec![
            DestinationEntry::new("teams", 2, "*.foo.bar", WholeWildcard).unwrap(),
        ])
        .unwrap();
        assert!(!updated.covers(&grant, &origin("a.foo.bar")));
    }
}

#[test]
fn wildcard_defaults_to_one_concrete_target() {
    let policy = DestinationPolicy::new(vec![
        DestinationEntry::new("one", 1, "*.foo.bar", Default::default()).unwrap(),
    ])
    .unwrap();
    let approved = origin("A.foo.bar");
    let scope = policy.scope_for(&approved).unwrap();
    assert_eq!(scope.pattern().to_string(), "a.foo.bar:443");
    let stored = serde_json::to_string(&scope).unwrap();
    let restored: DestinationScope = serde_json::from_str(&stored).unwrap();
    assert!(policy.covers(&restored, &approved));
    assert!(!policy.covers(&restored, &origin("b.foo.bar")));
    let tampered = stored.replace("a.foo.bar", "*.foo.bar");
    let changed: DestinationScope = serde_json::from_str(&tampered).unwrap();
    assert!(!policy.covers(&changed, &approved));
    assert!(DestinationPolicy::default().resolve(&approved).is_none());
}

#[test]
fn invalid_and_conflicting_policy_definitions_fail_at_startup() {
    let a = DestinationEntry::new("a", 1, "*.BÜCHER.example", ExactHost).unwrap();
    let alias =
        DestinationEntry::new("b", 1, "*.xn--bcher-kva.example:443", WholeWildcard).unwrap();
    assert_eq!(
        DestinationPolicy::new(vec![a.clone(), alias]).unwrap_err(),
        PolicyError::DuplicatePattern
    );
    let reused = DestinationEntry::new("a", 2, "other.example", ExactHost).unwrap();
    assert_eq!(
        DestinationPolicy::new(vec![a, reused]).unwrap_err(),
        PolicyError::DuplicateId
    );
    assert_eq!(
        DestinationEntry::new("a", 1, "foo.bar", WholeWildcard).unwrap_err(),
        PolicyError::InvalidApprovalMode
    );
    for invalid in [
        "foo.*.bar",
        "**.foo.bar",
        "*.127.1",
        "*.foo.bar@abc.test",
        "*.",
    ] {
        assert!(DestinationEntry::new("a", 1, invalid, ExactHost).is_err());
    }
}
