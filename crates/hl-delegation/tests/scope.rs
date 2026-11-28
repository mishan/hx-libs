use hl_delegation::scope::{Action, Scope, ScopeError};

#[test]
fn grant_scopes_parse_or_refuse() {
    let long_resource = format!("svc:act:{}", "r".repeat(256));
    let too_long_resource = format!("svc:act:{}", "r".repeat(257));
    let long_pattern = format!("svc:act:{}/*", "r".repeat(254));
    let too_long_pattern = format!("svc:act:{}/*", "r".repeat(255));
    let long_service = format!("{}:act:res", "s".repeat(32));
    let too_long_service = format!("{}:act:res", "s".repeat(33));
    let long_action = format!("svc:{}:res", "a".repeat(64));
    let too_long_action = format!("svc:{}:res", "a".repeat(65));
    let cases: &[(&str, Result<(), ScopeError>)] = &[
        ("github:pr.open:acme/repo", Ok(())),
        ("github:pr.open:acme/*", Ok(())),
        ("github:pr.open:*", Ok(())),
        ("github:*:acme/repo", Ok(())),
        ("*:*:*", Ok(())),
        ("svc:act:/*", Ok(())),
        ("svc:act:host:22/path", Ok(())),
        ("svc-2:a-b.c-d:x", Ok(())),
        (&long_resource, Ok(())),
        (&long_pattern, Ok(())),
        (&long_service, Ok(())),
        (&long_action, Ok(())),
        ("github:pr.open", Err(ScopeError::Shape)),
        ("github", Err(ScopeError::Shape)),
        ("", Err(ScopeError::Shape)),
        ("GitHub:pr.open:x", Err(ScopeError::Service)),
        (":pr.open:x", Err(ScopeError::Service)),
        ("git_hub:pr.open:x", Err(ScopeError::Service)),
        ("s*:act:x", Err(ScopeError::Service)),
        (&too_long_service, Err(ScopeError::Service)),
        ("svc::x", Err(ScopeError::Action)),
        ("svc:pr.*:x", Err(ScopeError::Action)),
        ("svc:pr..open:x", Err(ScopeError::Action)),
        ("svc:.open:x", Err(ScopeError::Action)),
        ("svc:open.:x", Err(ScopeError::Action)),
        ("svc:Open:x", Err(ScopeError::Action)),
        (&too_long_action, Err(ScopeError::Action)),
        ("svc:act:", Err(ScopeError::Resource)),
        ("svc:act:foo*", Err(ScopeError::Resource)),
        ("svc:act:acme*", Err(ScopeError::Resource)),
        ("svc:act:a*b", Err(ScopeError::Resource)),
        ("svc:act:acme/**", Err(ScopeError::Resource)),
        ("svc:act:*/x", Err(ScopeError::Resource)),
        ("svc:act:has space", Err(ScopeError::Resource)),
        ("svc:act:tab\there", Err(ScopeError::Resource)),
        ("svc:act:caf\u{e9}", Err(ScopeError::Resource)),
        (&too_long_resource, Err(ScopeError::Resource)),
        (&too_long_pattern, Err(ScopeError::Resource)),
    ];
    for (input, want) in cases {
        assert_eq!(Scope::parse(input).map(|_| ()), *want, "{input:?}");
    }
}

#[test]
fn actions_are_concrete() {
    let cases: &[(&str, Result<(), ScopeError>)] = &[
        ("github:pr.open:acme/repo", Ok(())),
        ("svc:act:host:22/path", Ok(())),
        ("*:pr.open:x", Err(ScopeError::Service)),
        ("svc:*:x", Err(ScopeError::Action)),
        ("svc:act:*", Err(ScopeError::Resource)),
        ("svc:act:acme/*", Err(ScopeError::Resource)),
        ("svc:act", Err(ScopeError::Shape)),
    ];
    for (input, want) in cases {
        assert_eq!(Action::parse(input).map(|_| ()), *want, "{input:?}");
    }
}

fn scope(s: &str) -> Scope {
    Scope::parse(s).unwrap_or_else(|e| panic!("{s:?}: {e}"))
}

fn action(s: &str) -> Action {
    Action::parse(s).unwrap_or_else(|e| panic!("{s:?}: {e}"))
}

#[test]
fn covering() {
    let cases = [
        ("github:pr.open:acme/repo", "github:pr.open:acme/repo", true),
        (
            "github:pr.open:acme/repo",
            "github:pr.open:acme/repo2",
            false,
        ),
        ("github:pr.open:acme/*", "github:pr.open:acme/repo", true),
        ("github:pr.open:acme/*", "github:pr.open:acme/a/b", true),
        ("github:pr.open:acme/*", "github:pr.open:acme/", false),
        ("github:pr.open:acme/*", "github:pr.open:acme", false),
        (
            "github:pr.open:acme/*",
            "github:pr.open:acme-evil/repo",
            false,
        ),
        ("github:pr.open:*", "github:pr.open:anything", true),
        ("github:*:acme/repo", "github:pr.merge:acme/repo", true),
        ("github:pr:acme/repo", "github:pr.open:acme/repo", false),
        (
            "github:pr.open:acme/repo",
            "gitlab:pr.open:acme/repo",
            false,
        ),
        ("*:*:*", "hexline:say:room/lobby", true),
        ("svc:a:acme/Repo", "svc:a:acme/repo", false),
    ];
    for (grant, act, want) in cases {
        assert_eq!(
            scope(grant).covers(&action(act)),
            want,
            "{grant:?} covers {act:?}"
        );
    }
}

#[test]
fn containment() {
    let cases = [
        ("github:pr.open:acme/*", "github:pr.open:acme/repo", true),
        ("github:pr.open:acme/*", "github:pr.open:acme/repo/*", true),
        ("github:pr.open:acme/*", "github:pr.open:acme/*", true),
        ("github:pr.open:acme/*", "github:pr.open:acme/", false),
        ("github:pr.open:acme/*", "github:pr.open:acme-evil/*", false),
        ("github:pr.open:acme/*", "github:pr.open:*", false),
        ("github:pr.open:acme/repo", "github:pr.open:acme/*", false),
        ("github:*:*", "github:pr.open:acme/repo", true),
        ("github:pr.open:*", "github:*:acme/repo", false),
        ("*:*:*", "*:*:*", true),
        ("github:pr.open:x", "gitlab:pr.open:x", false),
    ];
    for (parent, child, want) in cases {
        assert_eq!(
            scope(parent).contains(&scope(child)),
            want,
            "{parent:?} contains {child:?}"
        );
    }
}

// Every string over `alphabet` of length 1..=max.
fn strings(alphabet: &[char], max: usize) -> Vec<String> {
    let mut all = Vec::new();
    let mut level = vec![String::new()];
    for _ in 0..max {
        level = level
            .iter()
            .flat_map(|s| alphabet.iter().map(move |c| format!("{s}{c}")))
            .collect();
        all.extend(level.iter().cloned());
    }
    all
}

fn small_grants() -> Vec<Scope> {
    let mut resources: Vec<String> = strings(&['a', '/'], 3);
    resources.extend(
        strings(&['a', '/'], 3)
            .into_iter()
            .filter(|p| p.ends_with('/'))
            .map(|p| format!("{p}*")),
    );
    resources.push("*".into());
    let mut out = Vec::new();
    for service in ["*", "a", "b"] {
        for act in ["*", "x", "x.y"] {
            for resource in &resources {
                out.push(scope(&format!("{service}:{act}:{resource}")));
            }
        }
    }
    out
}

fn small_actions() -> Vec<Action> {
    let mut out = Vec::new();
    for service in ["a", "b"] {
        for act in ["x", "x.y", "y"] {
            for resource in strings(&['a', '/'], 4) {
                out.push(action(&format!("{service}:{act}:{resource}")));
            }
        }
    }
    out
}

// A child a parent contains never covers an action the parent doesn't.
// Exhaustive over a small alphabet, where every prefix boundary case
// (`a/` against `a`, `a/` against `a/a`, `/` against `//`) occurs.
#[test]
fn containment_is_sound() {
    let grants = small_grants();
    let actions = small_actions();
    let mut contained_pairs = 0;
    for parent in &grants {
        for child in &grants {
            if !parent.contains(child) {
                continue;
            }
            contained_pairs += 1;
            for a in &actions {
                assert!(
                    !child.covers(a) || parent.covers(a),
                    "{parent:?} contains {child:?}, which covers {a:?}"
                );
            }
        }
    }
    // Well past the reflexive pairs, so prefixes under prefixes and
    // literals under wildcards were all exercised.
    assert!(contained_pairs > 2 * grants.len(), "{contained_pairs}");
}

#[test]
fn containment_is_reflexive_and_transitive() {
    let grants = small_grants();
    for g in &grants {
        assert!(g.contains(g), "{g:?}");
    }
    for a in &grants {
        for b in grants.iter().filter(|b| a.contains(b)) {
            for c in grants.iter().filter(|c| b.contains(c)) {
                assert!(a.contains(c), "{a:?} > {b:?} > {c:?}");
            }
        }
    }
}
