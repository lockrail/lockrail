//! Proxy-env self-check (PLAN.md section 3.6, B8; adv_message_3 m23).
//!
//! Every managed hook runs this first. Claude Code hooks inherit the client's environment
//! (hooks.md:761), so a session launched with `HTTPS_PROXY` overridden, or with a `NO_PROXY` that
//! covers a model host, is seen here and the turn is refused with `proxy_bypass`. Codex
//! inheritance is assumption A-9 (GATE 6 decides).
//!
//! The effective proxy is resolved with the clients' own precedence: `https_proxy`, then
//! `HTTPS_PROXY`, then `ALL_PROXY`/`all_proxy`. `NO_PROXY`/`no_proxy` (lowercase first) is matched
//! with the common semantics: `*`, exact host, `.suffix`, bare `suffix` (also matching the domain
//! itself), entries separated by commas or whitespace, an optional `:port` ignored.

/// The sealer endpoint the managed settings install.
pub const EXPECTED_PROXY: &str = "http://127.0.0.1:8789";

/// Hosts that must go through the sealer: exactly the hosts the sealer opens, so a `NO_PROXY`
/// entry for any of them is a bypass.
pub const MODEL_HOSTS: &[&str] = lockrail_proxy::sealer::SEALER_MITM_HOSTS;

#[derive(Debug, PartialEq, Eq)]
pub enum Violation {
    NoProxy,
    WrongProxy(String),
    Bypassed(&'static str),
}

impl Violation {
    pub fn reason(&self) -> String {
        match self {
            Violation::NoProxy => {
                "proxy_bypass: no HTTPS proxy is set for this session; Lockrail cannot seal it"
                    .into()
            }
            Violation::WrongProxy(p) => {
                format!("proxy_bypass: this session's HTTPS proxy is {p}, not the Lockrail sealer")
            }
            Violation::Bypassed(h) => {
                format!("proxy_bypass: NO_PROXY sends {h} around the Lockrail sealer")
            }
        }
    }
}

fn normalise_proxy(value: &str) -> String {
    let v = value.trim().trim_end_matches('/');
    let v = if v.contains("://") {
        v.to_string()
    } else {
        format!("http://{v}")
    };
    v.replace("://localhost:", "://127.0.0.1:")
}

/// Check an environment, given as a lookup function (tests pass a map).
///
/// Every proxy variable that is present must point at the sealer: clients differ in which one
/// they prefer (curl, Node, Rust, Go), and an empty value is an override, not an absence. Both
/// `no_proxy` and `NO_PROXY` are checked, and an entry covers a model host under the broadest
/// client semantics: `*`, exact, `.suffix`, bare `suffix`, `*.suffix` and `*suffix`.
pub fn check(get: impl Fn(&str) -> Option<String>) -> Result<(), Violation> {
    let mut any_proxy = false;
    for key in ["https_proxy", "HTTPS_PROXY", "ALL_PROXY", "all_proxy"] {
        if let Some(value) = get(key) {
            if value.trim().is_empty() || normalise_proxy(&value) != EXPECTED_PROXY {
                return Err(Violation::WrongProxy(format!("{key}={value}")));
            }
            any_proxy = true;
        }
    }
    if !any_proxy {
        return Err(Violation::NoProxy);
    }
    for key in ["no_proxy", "NO_PROXY"] {
        let list = get(key).unwrap_or_default();
        for entry in list.split(|c: char| c == ',' || c.is_whitespace()) {
            let entry = entry.trim().to_ascii_lowercase();
            if entry.is_empty() {
                continue;
            }
            if entry.chars().all(|c| c == '*' || c == '.') {
                return Err(Violation::Bypassed(MODEL_HOSTS[0]));
            }
            let entry = entry
                .rsplit_once(':')
                .filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit()))
                .map(|(h, _)| h.to_string())
                .unwrap_or(entry);
            let suffix = entry.trim_start_matches('*').trim_start_matches('.');
            if suffix.is_empty() {
                continue;
            }
            for host in MODEL_HOSTS {
                let covered = *host == suffix
                    || host.ends_with(&format!(".{suffix}"))
                    // `*anthropic.com`-style entries match any name ending in the text.
                    || (entry.starts_with('*') && host.ends_with(suffix));
                if covered {
                    return Err(Violation::Bypassed(host));
                }
            }
        }
    }
    Ok(())
}

/// True when Claude Code or an OpenAI-style client is pointed at a provider the sealer does not
/// open (Bedrock, Vertex, Foundry, or a base URL outside [`MODEL_HOSTS`]). The sealer only
/// tunnels such traffic, so a secret typed in a prompt would reach it unsealed.
pub fn unsealed_provider(get: impl Fn(&str) -> Option<String>) -> bool {
    for key in [
        "CLAUDE_CODE_USE_BEDROCK",
        "CLAUDE_CODE_USE_VERTEX",
        "CLAUDE_CODE_USE_FOUNDRY",
    ] {
        if let Some(v) = get(key) {
            let v = v.trim().to_ascii_lowercase();
            if !matches!(v.as_str(), "" | "0" | "false" | "no" | "off") {
                return true;
            }
        }
    }
    for key in ["ANTHROPIC_BASE_URL", "OPENAI_BASE_URL"] {
        let Some(url) = get(key) else { continue };
        let url = url.trim();
        if url.is_empty() {
            continue;
        }
        let rest = url.split_once("://").map_or(url, |(_, r)| r);
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let host = authority.rsplit('@').next().unwrap_or_default();
        let host = host.rsplit_once(':').map_or(host, |(h, _)| h);
        if !MODEL_HOSTS.contains(&host.to_ascii_lowercase().as_str()) {
            return true;
        }
    }
    false
}

/// Check the process environment.
pub fn check_process() -> Result<(), Violation> {
    check(|k| std::env::var(k).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn the_managed_setting_passes() {
        assert_eq!(
            check(env(&[("HTTPS_PROXY", "http://127.0.0.1:8789")])),
            Ok(())
        );
        assert_eq!(
            check(env(&[
                ("HTTPS_PROXY", "127.0.0.1:8789/"),
                ("NO_PROXY", "localhost,127.0.0.1,.internal.corp")
            ])),
            Ok(())
        );
    }

    #[test]
    fn missing_or_overridden_proxy_fails() {
        assert_eq!(check(env(&[])), Err(Violation::NoProxy));
        assert!(matches!(
            check(env(&[("HTTPS_PROXY", "http://evil:8080")])),
            Err(Violation::WrongProxy(_))
        ));
        // Lowercase wins, as in curl, Node and Rust clients.
        assert!(matches!(
            check(env(&[
                ("https_proxy", "http://other:1"),
                ("HTTPS_PROXY", "http://127.0.0.1:8789")
            ])),
            Err(Violation::WrongProxy(_))
        ));
        assert_eq!(
            check(env(&[("ALL_PROXY", "http://127.0.0.1:8789")])),
            Ok(())
        );
    }

    #[test]
    fn no_proxy_forms_that_bypass_are_caught() {
        for no_proxy in [
            "api.anthropic.com",
            ".anthropic.com",
            "anthropic.com",
            "*",
            "localhost api.anthropic.com",
            "chatgpt.com:443",
            "OPENAI.COM",
        ] {
            let r = check(env(&[
                ("HTTPS_PROXY", EXPECTED_PROXY),
                ("NO_PROXY", no_proxy),
            ]));
            assert!(
                matches!(r, Err(Violation::Bypassed(_))),
                "{no_proxy}: {r:?}"
            );
        }
        let r = check(env(&[
            ("HTTPS_PROXY", EXPECTED_PROXY),
            ("no_proxy", ".anthropic.com"),
            ("NO_PROXY", ""),
        ]));
        assert!(matches!(r, Err(Violation::Bypassed("api.anthropic.com"))));
    }

    #[test]
    fn every_host_the_sealer_opens_is_protected_from_no_proxy() {
        for host in lockrail_proxy::sealer::SEALER_MITM_HOSTS {
            let r = check(env(&[("HTTPS_PROXY", EXPECTED_PROXY), ("NO_PROXY", host)]));
            assert_eq!(r, Err(Violation::Bypassed(host)), "{host}");
        }
    }

    #[test]
    fn providers_the_sealer_does_not_open_are_flagged() {
        let some = |k: &'static str, v: &'static str| {
            let e = env(&[(k, v)]);
            move |key: &str| e(key)
        };
        assert!(unsealed_provider(some("CLAUDE_CODE_USE_BEDROCK", "1")));
        assert!(unsealed_provider(some("CLAUDE_CODE_USE_VERTEX", "true")));
        assert!(unsealed_provider(some(
            "ANTHROPIC_BASE_URL",
            "https://llm-gw.corp.example/v1"
        )));
        assert!(unsealed_provider(some(
            "OPENAI_BASE_URL",
            "http://user:pw@localhost:4000"
        )));
        assert!(!unsealed_provider(some("CLAUDE_CODE_USE_BEDROCK", "0")));
        assert!(!unsealed_provider(some("ANTHROPIC_BASE_URL", "")));
        assert!(!unsealed_provider(some(
            "ANTHROPIC_BASE_URL",
            "https://api.anthropic.com/"
        )));
        assert!(!unsealed_provider(some(
            "OPENAI_BASE_URL",
            "https://API.OPENAI.COM:443/v1"
        )));
        assert!(!unsealed_provider(env(&[])));
    }

    #[test]
    fn wildcards_and_empty_overrides_are_caught() {
        for no_proxy in ["*.anthropic.com", "*anthropic.com", "*.com", ".*"] {
            let r = check(env(&[
                ("HTTPS_PROXY", EXPECTED_PROXY),
                ("NO_PROXY", no_proxy),
            ]));
            assert!(
                matches!(r, Err(Violation::Bypassed(_))),
                "{no_proxy}: {r:?}"
            );
        }
        let r = check(env(&[("HTTPS_PROXY", EXPECTED_PROXY), ("https_proxy", "")]));
        assert!(matches!(r, Err(Violation::WrongProxy(_))), "{r:?}");
        let r = check(env(&[
            ("HTTPS_PROXY", EXPECTED_PROXY),
            ("ALL_PROXY", "http://elsewhere:1"),
        ]));
        assert!(matches!(r, Err(Violation::WrongProxy(_))), "{r:?}");
        // Unrelated wildcards are fine.
        assert_eq!(
            check(env(&[
                ("HTTPS_PROXY", EXPECTED_PROXY),
                ("NO_PROXY", "*.internal.corp,localhost")
            ])),
            Ok(())
        );
    }
}
