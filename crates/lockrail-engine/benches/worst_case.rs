//! GATE 3 / GATE 1 worst-case bench (PLAN.md Phase 0C and 3): 1 MiB of adversarial input per
//! detector must scan in under 25 ms in a release build. Fuzzing cannot build these inputs
//! (D20), so each is constructed to hit one detector's slow path: repeated keywords with no
//! value, unterminated blocks, near-miss shapes and long runs.
//!
//! `cargo bench -p lockrail-engine --bench worst_case` prints one line per input and exits 1 if
//! any input is over the bound. Each input is scanned 5 times and the minimum is reported.

use lockrail_engine::phi::{PhiOptions, scan_phi};
use lockrail_engine::seal::{ScanOptions, scan_text};
use std::time::{Duration, Instant};

const MIB: usize = 1024 * 1024;
const BOUND: Duration = Duration::from_millis(25);

fn fill(unit: &str) -> String {
    unit.repeat(MIB / unit.len())
}

/// 1 MiB of distinct AWS key ids, so per-finding work cannot be amortised by repetition.
fn unique_aws_ids() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(MIB);
    let mut n: u64 = 0x9E37_79B9_7F4A_7C15;
    while out.len() + 21 <= MIB {
        out.push_str("AKIA");
        for _ in 0..16 {
            n ^= n << 13;
            n ^= n >> 7;
            n ^= n << 17;
            out.push(ALPHABET[(n % 32) as usize] as char);
        }
        out.push(' ');
    }
    out
}

fn main() {
    // Synthetic AWS-shaped values, built at runtime so no literal matches a secret-scanner rule.
    let aws_id = ["AKIA", "Q7ZK3M9B2N4P6R8T"].concat();
    let aws_secret = ["k3Jd8Lq2PzXw7", "/Nc4Hv9Bm+T1rY6sGf0aEuQ5o"].concat();
    let cases: Vec<(&str, String)> = vec![
        ("token-no-sep", fill("token")),
        ("password-no-sep", fill("password")),
        ("assignment-chain", fill("token:")),
        ("begin-no-end", fill("-----BEGIN ")),
        ("bearer-no-token", fill("bearer ")),
        ("jwt-near-miss", fill("eyJhbGciOi.")),
        ("db-url-no-at", fill("postgres://user:")),
        ("prefix-sk-proj", fill("sk-proj-")),
        ("prefix-sk-legacy-short", fill("sk-abc ")),
        ("aws-id-dense", fill(&format!("{aws_id} "))),
        ("aws-id-unique", unique_aws_ids()),
        (
            "aws-id-and-40char",
            fill(&format!("{aws_id} {aws_secret} ")),
        ),
        ("hex32-dense", fill("0123456789abcdef0123456789abcdef ")),
        ("twilio-context-dense", fill("twilio auth_token ")),
        ("azure-no-key", fill("AccountKey=")),
        (
            "base64-short-runs",
            fill("QUJDREVGR0hJSktMTU5PUFFSU1RVVldY "),
        ),
        ("base64-one-run", "QUJD".repeat(MIB / 4)),
        ("entropy-tokens", fill("aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY ")),
        ("multibyte", fill("é漢字🙂 token ")),
        ("ssn-near-miss", fill("123-45-678 ")),
        ("ssn-dense", fill("123-45-6789 ")),
        ("phone-dense", fill("(555) 010-0199 ")),
        ("email-dense", fill("a.b@c.example.com ")),
        ("email-no-tld", fill("aaaaaaaa@bbbbbbbb")),
        ("address-near-miss", fill("1234 Elm Elm Elm ")),
        ("mrn-context-dense", fill("MRN: ")),
        ("dob-context-dense", fill("DOB ")),
        ("npi-context-dense", fill("NPI 1234567893 ")),
        ("mbi-dense", fill("1EG4TE5MK73 ")),
        ("icd-context-dense", fill("diagnosis E11.9 ")),
        ("patient-context-dense", fill("patient ")),
        (
            "hl7-pid-dense",
            fill(
                "PID|1||00482913^^^H^MR||ROE^JANE||19620314|F|||1 ELM ST^^X^IL^62701||(217)555-0147\r",
            ),
        ),
        ("hl7-pid-no-fields", fill("PID|")),
        // Detection v2 (teardown C): URL authorities, wide password values, escapes, Basic auth.
        ("url-authority-dense", fill("https://a:b")),
        ("url-userinfo-dense", fill("x://u:pw12@h")),
        ("password-wide-dense", fill("password=a!b")),
        ("password-quote-unclosed", fill("password=\"abc")),
        ("percent-escape-dense", fill("token%5F")),
        ("json-escape-dense", fill("key\\/")),
        ("unicode-escape-dense", fill("\\u0041pwd=")),
        ("basic-auth-dense", fill("Basic QUJD ")),
        ("telegram-near-miss", fill("12345678:A")),
        ("entra-near-miss", fill("abc1Q~")),
        ("curl-user-dense", fill(" -u a:bcdef")),
        ("hex-run", "6162".repeat(MIB / 4)),
        // PHI v2 (teardown B): table headers, rows, markdown, JSON keys, clinical ICD.
        ("csv-header-dense", fill("mrn,dob,icd10,name\n")),
        (
            "csv-rows",
            format!(
                "mrn,dob,dx_code,name\n{}",
                fill("QX40172,07/04/1950,E78.5,Roe\n")
            ),
        ),
        ("csv-quote-unclosed", format!("mrn,dob\n{}", fill("\"a,"))),
        (
            "markdown-rows",
            format!(
                "| MRN | DOB |\n|---|---|\n{}",
                fill("| QX40172 | 1950-07-04 |\n")
            ),
        ),
        (
            "json-keys-dense",
            fill("\"mrn\": \"QX40172\", \"dob\": \"1950-07-04\", "),
        ),
        ("clinical-icd-dense", fill("patient E11.9 ")),
        ("long-line-commas", ",".repeat(MIB)),
        // Security review: base64 runs that each decode to `token=` (72 ms/MiB before).
        ("base64-token-runs", fill("dG9rZW49YWJjZGVmZ2g= ")),
        // Runs decoding to 24 bytes of `token=` (31 ms/MiB before rescans were batched).
        (
            "base64-24b-token-runs",
            fill("dG9rZW49YWJjZGVmZ2ggdG9rZW49YWJj "),
        ),
        (
            "fhir-identifier-unclosed",
            format!(
                "{{\"resourceType\":\"Patient\",{}",
                "\"identifier\":[ ".repeat(MIB / 16)
            ),
        ),
        (
            "fhir-patient-dense",
            fill(
                "{\"resourceType\":\"Patient\",\"birthDate\":\"1962-03-14\",\"telecom\":[{\"system\":\"phone\",\"value\":\"(217) 555-0147\"}]} ",
            ),
        ),
    ];
    let mut failed = 0;
    for (name, input) in &cases {
        let secrets = (0..5)
            .map(|_| {
                let t = Instant::now();
                std::hint::black_box(scan_text(
                    input,
                    ScanOptions {
                        aggressive: true,
                        protection_mode: true,
                    },
                ));
                t.elapsed()
            })
            .min()
            .expect("runs");
        let phi = (0..5)
            .map(|_| {
                let t = Instant::now();
                std::hint::black_box(scan_phi(input, PhiOptions::default()));
                t.elapsed()
            })
            .min()
            .expect("runs");
        let ok = secrets < BOUND && phi < BOUND;
        if !ok {
            failed += 1;
        }
        println!(
            "{:<26} {:>7} KiB  secrets {:>9.3?}  phi {:>9.3?}  {}",
            name,
            input.len() / 1024,
            secrets,
            phi,
            if ok { "ok" } else { "OVER 25ms" }
        );
    }
    if failed > 0 {
        eprintln!("worst_case: {failed} input(s) over {BOUND:?}");
        std::process::exit(1);
    }
    println!("worst_case: all {} inputs under {BOUND:?}", cases.len());
}
