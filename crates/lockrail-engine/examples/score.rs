//! Corpus scorer (PLAN.md GATE 3).
//!
//! `cargo run --release -p lockrail-engine --example score -- <cases.jsonl> [--gate]`
//!
//! Each line: `{"id", "category": "secret"|"phi"|"benign", "text", "expect": [{"class",
//! "type", "value"}]}`. Detectors run with the hook defaults (protection mode, not aggressive;
//! PHI with no `phi_paths` hint).
//! - A secret is recalled when the value no longer appears in the sealed text and a sealed
//!   finding overlaps its span.
//! - A PHI value is recalled when a PHI finding overlaps its span.
//! - A benign case is a false positive when anything is sealed or any PHI finding fires.
//!
//! `--gate` exits 1 unless secret recall >= 0.95, PHI recall >= 0.90 and benign FP <= 1%.

use lockrail_engine::phi::{PhiOptions, scan_phi};
use lockrail_engine::seal::{SealOptions, seal_text};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Default)]
struct Tally {
    hit: usize,
    total: usize,
    missed_ids: Vec<String>,
}

fn overlaps(a: (usize, usize), b: (usize, usize)) -> bool {
    a.0 < b.1 && b.0 < a.1
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let path = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .expect("usage: score <cases.jsonl> [--gate] [--show-misses]");
    let gate = args.iter().any(|a| a == "--gate");
    let show = args.iter().any(|a| a == "--show-misses");
    let text = std::fs::read_to_string(path).expect("read corpus");

    let mut secret: BTreeMap<String, Tally> = BTreeMap::new();
    let mut phi: BTreeMap<String, Tally> = BTreeMap::new();
    let mut benign_total = 0usize;
    let mut benign_fp: BTreeMap<String, usize> = BTreeMap::new();
    let mut benign_fp_ids = Vec::new();

    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let case: Value = serde_json::from_str(line).expect("json line");
        let id = case["id"].as_str().unwrap_or("?").to_string();
        let body = case["text"].as_str().expect("text");
        let sealed = seal_text(body, SealOptions::default());
        let sealed_spans: Vec<(usize, usize)> = sealed
            .findings
            .iter()
            .filter(|f| f.should_seal)
            .map(|f| (f.start, f.end))
            .collect();
        let phi_findings = scan_phi(body, PhiOptions::default());
        let phi_spans: Vec<(usize, usize)> =
            phi_findings.iter().map(|f| (f.start, f.end)).collect();

        if case["category"] == "benign" {
            benign_total += 1;
            let mut reasons = Vec::new();
            for f in sealed.findings.iter().filter(|f| f.should_seal) {
                reasons.push(format!("secret:{}", f.kind));
            }
            for f in &phi_findings {
                reasons.push(format!("phi:{}", f.kind));
            }
            if !reasons.is_empty() {
                for r in &reasons {
                    *benign_fp.entry(r.clone()).or_default() += 1;
                }
                benign_fp_ids.push(format!("{id} [{}]", reasons.join(",")));
            }
            continue;
        }
        for exp in case["expect"].as_array().into_iter().flatten() {
            let value = exp["value"].as_str().expect("value");
            let class = exp["class"].as_str().unwrap_or("");
            let kind = exp["type"].as_str().unwrap_or("?").to_string();
            let Some(start) = body.find(value) else {
                continue;
            };
            let span = (start, start + value.len());
            let (hit, table) = if class == "phi" {
                (phi_spans.iter().any(|s| overlaps(*s, span)), &mut phi)
            } else {
                (
                    !sealed.safe_text.contains(value)
                        && sealed_spans.iter().any(|s| overlaps(*s, span)),
                    &mut secret,
                )
            };
            let t = table.entry(kind).or_default();
            t.total += 1;
            if hit {
                t.hit += 1;
            } else {
                t.missed_ids.push(id.clone());
            }
        }
    }

    let sum = |m: &BTreeMap<String, Tally>| {
        m.values()
            .fold((0, 0), |(h, t), x| (h + x.hit, t + x.total))
    };
    let print = |name: &str, m: &BTreeMap<String, Tally>| {
        println!("{name}");
        for (k, t) in m {
            println!(
                "  {:<24} {:>3}/{:<3} {:>6.1}%",
                k,
                t.hit,
                t.total,
                100.0 * t.hit as f64 / t.total.max(1) as f64
            );
            if show && !t.missed_ids.is_empty() {
                println!("      missed: {}", t.missed_ids.join(" "));
            }
        }
    };
    print("secret recall by type", &secret);
    print("phi recall by type", &phi);
    let (sh, st) = sum(&secret);
    let (ph, pt) = sum(&phi);
    let fp = benign_fp_ids.len();
    let srec = sh as f64 / st.max(1) as f64;
    let prec = ph as f64 / pt.max(1) as f64;
    let fpr = fp as f64 / benign_total.max(1) as f64;
    println!("benign false positives by detector: {benign_fp:?}");
    if show {
        for id in &benign_fp_ids {
            println!("  fp: {id}");
        }
    }
    println!("SECRET recall {sh}/{st} = {:.3}", srec);
    println!("PHI    recall {ph}/{pt} = {:.3}", prec);
    println!("BENIGN FP     {fp}/{benign_total} = {:.3}%", 100.0 * fpr);
    if gate {
        let ok = srec >= 0.95 && prec >= 0.90 && fpr <= 0.01;
        println!("GATE 3 corpus: {}", if ok { "PASS" } else { "FAIL" });
        if !ok {
            std::process::exit(1);
        }
    }
}
