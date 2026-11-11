//! PHI detectors (PLAN.md section 3.2, Phase 3C).
//!
//! Covered identifiers, each with a validator or a context rule:
//! - `ssn`: `ddd-dd-dddd` (or spaces) with the SSA validity rules; nine bare digits only when
//!   labelled as an SSN.
//! - `npi`: ten digits passing the Luhn check over `80840` + NPI, next to provider context.
//! - `mrn`: the value after `MRN`, `medical record number`, `chart #`.
//! - `dob`: a date after `DOB`, `date of birth`, `born`, or right after `Patient <Name>`.
//! - `medicare-mbi`: the 11-character Medicare Beneficiary Identifier format.
//! - `icd10`: an ICD-10 code within 64 bytes of diagnosis context.
//! - `phone`, `email`, `street-address`: contact identifiers count only within 256 bytes of
//!   patient or clinical context, or when the caller says the text comes from a `phi_paths` file
//!   (P-18).
//!
//! This is a subset of the Safe Harbor identifiers (45 CFR 164.514(b)(2)). Names, other dates,
//! geography below the state and free-text clinical content are NOT detected, so sealing with
//! these detectors is not de-identification.
//!
//! Every pattern is a `regex` (linear time) run once over the input. Context checks collect
//! anchor positions in one pass and binary-search them, so the whole scan is `O(n log n)`.

use core::fmt;
use regex::Regex;
use std::sync::LazyLock;

/// A span of PHI in the scanned text. The value is not copied: [`PhiFinding::value`] slices it
/// from the input, so a scan allocates nothing per finding and leaves no extra copy of patient
/// data on the heap.
#[derive(Clone, PartialEq, Eq)]
pub struct PhiFinding {
    pub kind: &'static str,
    pub start: usize,
    pub end: usize,
}

impl PhiFinding {
    /// The identifier itself, from the text that was scanned.
    pub fn value<'a>(&self, input: &'a str) -> &'a str {
        &input[self.start..self.end]
    }
}

impl fmt::Debug for PhiFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PhiFinding")
            .field("kind", &self.kind)
            .field("start", &self.start)
            .field("end", &self.end)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PhiOptions {
    /// The text comes from a file under policy `phi_paths`: contact identifiers count without
    /// nearby clinical context.
    pub phi_path: bool,
}

/// Radius for contact identifiers (P-18).
pub const CONTACT_CONTEXT_BYTES: usize = 256;
const CODE_CONTEXT_BYTES: usize = 64;

/// ASCII-only: see `seal::ascii_regex` (Unicode `\b` costs 250 ms per MiB of multibyte text).
fn re(pattern: &str) -> Regex {
    regex::RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .expect("phi regex")
}

const DATE: &str = r"(?:\d{1,2}[/.\-]\d{1,2}[/.\-](?:\d{4}|\d{2})|\d{4}[/.\-]\d{1,2}[/.\-]\d{1,2}|(?i:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4}|\d{1,2}(?:st|nd|rd|th)?[\s\-]+(?i:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?[\s,\-]+(?:\d{4}|\d{2}))";

static SSN: LazyLock<Regex> = LazyLock::new(|| re(r"\b(\d{3})([- ])(\d{2})([- ])(\d{4})\b"));
static SSN_LABELLED: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)\b(?:ssn|social\s+security(?:\s+(?:number|no\.?|num|#))?|ss#)\s*[:#]?\s*(?:is\s+)?(\d{9}|\d{3}-\d{2}-\d{4})\b",
    )
});
static TEN_DIGITS: LazyLock<Regex> = LazyLock::new(|| re(r"\b(\d{10})\b"));
static NPI_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)\bnpi\b|provider|prescriber|prescribing|physician|rendering|referring|attending|\bdr\.?\s|\bm\.?d\.?\b|\bnp\b|\bpa-c\b",
    )
});
static MRN: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r#"(?i)\b(?:mrn|mr\s*#|medical[\s_]*record(?:[\s_]*(?:number|no\.?|num|#))?|med(?:ical)?\.?\s+rec(?:ord)?\.?\s*(?:#|no\.?|number|num)|chart[\s_]*(?:#|no\.?|number|num|id)|patient[\s_]*(?:id|number|no\.?)|pt\.?[\s_]+(?:id|no\.?))["']?[\s:#.\-=]{0,4}["']?([A-Za-z0-9][A-Za-z0-9\-]{4,14})\b"#,
    )
});
static DOB: LazyLock<Regex> = LazyLock::new(|| {
    re(&format!(
        r#"(?i)\b(?:dob|d\.o\.b\.?|date[\s_]*of[\s_]*birth|birth[\s_]*date|birthdate|birth\s+dt|born(?:\s+on)?)["']?\s*[:\-=#]?\s*["']?\s*\(?\s*({DATE}|[01]\d[0-3]\d(?:19|20)\d\d\b|(?:19|20)\d\d[01]\d[0-3]\d\b)"#
    ))
});
static PATIENT_NAME_DATE: LazyLock<Regex> = LazyLock::new(|| {
    re(&format!(
        r"\b(?:[Pp]atient|PATIENT|[Pp]t\.?|[Nn]ame)\s*:?\s+(?:[A-Z][a-z'\-]+,?\s+){{1,3}}[(,\-]?\s*({DATE})"
    ))
});
/// `First Last 03/14/1962`, `Last, First (03/14/1962)`: a date right after a person-like name.
/// Counted only with clinical context within 256 bytes (see `scan_phi`).
static NAME_DATE: LazyLock<Regex> = LazyLock::new(|| {
    re(&format!(
        r"\b[A-Z][a-z'\-]+,?\s+[A-Z][a-z'\-]+(?:\s+[A-Z]\.?)?\s*[(,\-]?\s*({DATE})"
    ))
});
static MBI: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"\b([1-9][AC-HJKMNP-RT-Y][AC-HJKMNP-RT-Y0-9]\d-?[AC-HJKMNP-RT-Y][AC-HJKMNP-RT-Y0-9]\d-?[AC-HJKMNP-RT-Y]{2}\d{2})\b",
    )
});
static ICD10: LazyLock<Regex> = LazyLock::new(|| re(r"\b([A-Z]\d[0-9AB](?:\.[0-9A-Z]{1,4})?)\b"));
static ICD_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)\bdiagnos|\bdx(?:[\s_]*codes?)?\b|\bicd[\s_\-]*10(?:-cm)?|\bicd\b|\bassessment\b|\bimpression\b|\bproblem[\s_]+list\b|\bcondition\b|\bcomorbidit",
    )
});
/// The SOAP note `A:` (assessment) line, case-sensitive at a line start.
static SOAP_ASSESSMENT: LazyLock<Regex> = LazyLock::new(|| re(r"(?m)^[ \t]*A:[ \t]"));
static PHONE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?:\+1[\s.\-]?|\b1[\s.\-])?(?:\([2-9]\d{2}\)\s?|\b[2-9]\d{2}[\s.\-]?)[2-9]\d{2}[\s.\-]?\d{4}\b",
    )
});
static EMAIL: LazyLock<Regex> = LazyLock::new(|| {
    re(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,24}\b")
});
static ADDRESS: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"\b\d{1,6}\s+(?:[NSEW]\.?\s+)?(?:[A-Z0-9][A-Za-z0-9'\-]*\.?\s+){1,4}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Terrace|Ter|Circle|Cir|Parkway|Pkwy|Highway|Hwy|Trail|Trl|Square|Sq)\b\.?(?:,?\s*(?:Apt|Apartment|Suite|Ste|Unit|#)\.?\s*[A-Za-z0-9\-]+)?(?:,\s*[A-Z][A-Za-z .'\-]{1,30},\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?)?",
    )
});
static CLINICAL_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)\bpatient|\bpt\b|\bmrn\b|\bdob\b|date\s+of\s+birth|diagnos|\bdx\b|\bchart\b|\bclinic|\badmit|admission|discharg|prescri|\brx\b|medication|physician|hospital|\bicd[\- ]?10|\bhipaa\b|\bphi\b|\bmedical\b|treatment|appointment|referral|insurance|medicare|medicaid|guarantor|emergency\s+contact|\bnurse|\bencounter\b|intake|symptom",
    )
});

fn positions(re: &Regex, input: &str) -> Vec<usize> {
    re.find_iter(input).map(|m| m.start()).collect()
}

/// True when an anchor lies within `radius` bytes of `[start, end)` (anchors sorted).
fn near(anchors: &[usize], start: usize, end: usize, radius: usize) -> bool {
    let lo = start.saturating_sub(radius);
    let i = anchors.partition_point(|a| *a < lo);
    anchors.get(i).is_some_and(|a| *a <= end + radius)
}

fn ssn_valid(area: &str, group: &str, serial: &str) -> bool {
    let area: u32 = area.parse().unwrap_or(0);
    area != 0 && area != 666 && area < 900 && group != "00" && serial != "0000"
}

/// Luhn over `80840` + the 10-digit NPI (the NPI check digit is defined that way).
fn npi_valid(npi: &str) -> bool {
    let mut sum = 0;
    for (i, b) in b"80840".iter().chain(npi.as_bytes()).rev().enumerate() {
        let mut v = u32::from(b - b'0');
        if i % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum % 10 == 0
}

fn push(out: &mut Vec<PhiFinding>, kind: &'static str, input: &str, start: usize, end: usize) {
    debug_assert!(input.is_char_boundary(start) && input.is_char_boundary(end));
    out.push(PhiFinding { kind, start, end });
}

/// Scan `input` for the covered PHI identifiers. Findings are non-overlapping and sorted.
pub fn scan_phi(input: &str, options: PhiOptions) -> Vec<PhiFinding> {
    let mut out = Vec::new();

    for c in SSN.captures_iter(input) {
        let (a, sep1, g, sep2, s) = (&c[1], &c[2], &c[3], &c[4], &c[5]);
        if sep1 == sep2 && ssn_valid(a, g, s) {
            let m = c.get(0).expect("match");
            push(&mut out, "ssn", input, m.start(), m.end());
        }
    }
    for c in SSN_LABELLED.captures_iter(input) {
        let m = c.get(1).expect("group");
        let digits: String = m.as_str().chars().filter(char::is_ascii_digit).collect();
        if ssn_valid(&digits[..3], &digits[3..5], &digits[5..]) {
            push(&mut out, "ssn", input, m.start(), m.end());
        }
    }

    let npi_context = positions(&NPI_CONTEXT, input);
    if !npi_context.is_empty() {
        for c in TEN_DIGITS.captures_iter(input) {
            let m = c.get(1).expect("group");
            if npi_valid(m.as_str()) && near(&npi_context, m.start(), m.end(), CODE_CONTEXT_BYTES) {
                push(&mut out, "npi", input, m.start(), m.end());
            }
        }
    }

    for c in MRN.captures_iter(input) {
        let m = c.get(1).expect("group");
        let v = m.as_str().trim_end_matches('-');
        if v.len() >= 5 && v.bytes().any(|b| b.is_ascii_digit()) {
            push(&mut out, "mrn", input, m.start(), m.start() + v.len());
        }
    }

    for re in [&*DOB, &*PATIENT_NAME_DATE] {
        for c in re.captures_iter(input) {
            let m = c.get(1).expect("group");
            push(&mut out, "dob", input, m.start(), m.end());
        }
    }

    let clinical = positions(&CLINICAL_CONTEXT, input);
    if !clinical.is_empty() {
        for c in NAME_DATE.captures_iter(input) {
            let m = c.get(1).expect("group");
            if near(&clinical, m.start(), m.end(), CONTACT_CONTEXT_BYTES) {
                push(&mut out, "dob", input, m.start(), m.end());
            }
        }
    }

    for c in MBI.captures_iter(input) {
        let m = c.get(1).expect("group");
        push(&mut out, "medicare-mbi", input, m.start(), m.end());
    }

    let mut icd_context = positions(&ICD_CONTEXT, input);
    icd_context.extend(positions(&SOAP_ASSESSMENT, input));
    icd_context.sort_unstable();
    let mut icd_positions = Vec::new();
    if !icd_context.is_empty() || !clinical.is_empty() {
        // A code right after an accepted code (a diagnosis list) is in context too. A dotted
        // code (`E03.9`, the specific form) also counts near clinical words (teardown B idea
        // 4); a bare three-character code (`B12`) needs diagnosis context.
        let mut chain_end: Option<usize> = None;
        for c in ICD10.captures_iter(input) {
            let m = c.get(1).expect("group");
            let chained = chain_end.is_some_and(|e| m.start() >= e && m.start() - e <= 24);
            let dotted_clinical = m.as_str().contains('.')
                && near(&clinical, m.start(), m.end(), CONTACT_CONTEXT_BYTES);
            if chained
                || dotted_clinical
                || near(&icd_context, m.start(), m.end(), CODE_CONTEXT_BYTES)
            {
                chain_end = Some(m.end());
                icd_positions.push(m.start());
                push(&mut out, "icd10", input, m.start(), m.end());
            }
        }
    }

    // Contact identifiers: clinical words, or any strong identifier found above, are context.
    let mut context = clinical;
    context.extend(out.iter().map(|f| f.start));
    context.extend(icd_positions);
    context.sort_unstable();
    let contact_ok = |start: usize, end: usize| {
        options.phi_path || near(&context, start, end, CONTACT_CONTEXT_BYTES)
    };
    if options.phi_path || !context.is_empty() {
        for m in EMAIL.find_iter(input) {
            if contact_ok(m.start(), m.end()) {
                push(&mut out, "email", input, m.start(), m.end());
            }
        }
        for m in ADDRESS.find_iter(input) {
            if contact_ok(m.start(), m.end()) {
                push(&mut out, "street-address", input, m.start(), m.end());
            }
        }
        for m in PHONE.find_iter(input) {
            if contact_ok(m.start(), m.end()) {
                push(&mut out, "phone", input, m.start(), m.end());
            }
        }
    }

    structured::hl7(input, &mut out);
    structured::fhir(input, &mut out);
    structured::table(input, &mut out);

    resolve_overlaps(out)
}

/// PHI in structured healthcare payloads, read by field position or field name from the
/// published standards rather than by labels in free text.
mod structured {
    use super::{PhiFinding, push, re};
    use regex::Regex;
    use std::sync::LazyLock;

    /// HL7 v2 segments that carry patient, next-of-kin or guarantor identifiers. Fields are
    /// `|`-separated, components `^`, repeats `~`. Field numbers count from the segment name
    /// (PID-1 is after the first `|`).
    pub fn hl7(input: &str, out: &mut Vec<PhiFinding>) {
        let mut offset = 0;
        for segment in input.split_inclusive(['\r', '\n']) {
            let start = offset;
            offset += segment.len();
            let body = segment.trim_end_matches(['\r', '\n']);
            let kind = match body.get(..4) {
                Some("PID|") => Seg::Pid,
                Some("NK1|") => Seg::Nk1,
                Some("GT1|") => Seg::Gt1,
                Some("DG1|") => Seg::Dg1,
                _ => continue,
            };
            let mut field_start = start;
            for (index, field) in body.split('|').enumerate() {
                let here = field_start;
                field_start += field.len() + 1;
                if field.is_empty() || index == 0 {
                    continue;
                }
                match (kind, index) {
                    (Seg::Pid, 2..=4) => first_component(input, out, "mrn", here, field),
                    (Seg::Pid, 5) | (Seg::Nk1, 2) | (Seg::Gt1, 3) => name(input, out, here, field),
                    (Seg::Pid, 7) | (Seg::Gt1, 8) => {
                        first_component(input, out, "dob", here, field)
                    }
                    (Seg::Pid, 11) | (Seg::Nk1, 4) | (Seg::Gt1, 5) => {
                        first_component(input, out, "street-address", here, field)
                    }
                    (Seg::Pid, 13 | 14) | (Seg::Nk1, 5 | 6) | (Seg::Gt1, 6 | 7) => {
                        first_component(input, out, "phone", here, field)
                    }
                    (Seg::Pid, 19) | (Seg::Gt1, 12) => {
                        first_component(input, out, "ssn", here, field)
                    }
                    // DG1-3: the diagnosis code (`code^text^coding system`).
                    (Seg::Dg1, 3) => {
                        let code = field.split('^').next().unwrap_or("");
                        if super::ICD10
                            .find(code)
                            .is_some_and(|m| m.start() == 0 && m.end() == code.len())
                        {
                            push(out, "icd10", input, here, here + code.len());
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    #[derive(Clone, Copy)]
    enum Seg {
        Pid,
        Nk1,
        Gt1,
        Dg1,
    }

    /// The first component of a field (`ID^check^scheme...`); each `~` repeat on its own.
    fn first_component(
        input: &str,
        out: &mut Vec<PhiFinding>,
        kind: &'static str,
        at: usize,
        field: &str,
    ) {
        let mut rep_start = at;
        for repeat in field.split('~') {
            let value = repeat.split('^').next().unwrap_or("");
            if value.len() >= 3 && value.bytes().any(|b| b.is_ascii_alphanumeric()) {
                push(out, kind, input, rep_start, rep_start + value.len());
            }
            rep_start += repeat.len() + 1;
        }
    }

    /// `FAMILY^GIVEN^MIDDLE...`: the first three components.
    fn name(input: &str, out: &mut Vec<PhiFinding>, at: usize, field: &str) {
        let mut comp_start = at;
        for (i, comp) in field.split('^').enumerate().take(3) {
            if comp.len() >= 2
                && comp
                    .bytes()
                    .all(|b| b.is_ascii_alphabetic() || matches!(b, b'-' | b'\'' | b' '))
            {
                push(
                    out,
                    "patient-name",
                    input,
                    comp_start,
                    comp_start + comp.len(),
                );
            }
            comp_start += comp.len() + 1;
            let _ = i;
        }
    }

    static FHIR_PATIENT: LazyLock<Regex> =
        LazyLock::new(|| re(r#""resourceType"\s*:\s*"(?:Patient|RelatedPerson|Person)""#));
    static BIRTH_DATE: LazyLock<Regex> =
        LazyLock::new(|| re(r#""birthDate"\s*:\s*"(\d{4}-\d{2}-\d{2})""#));
    static FHIR_BLOCK_KEYS: LazyLock<aho_corasick::AhoCorasick> = LazyLock::new(|| {
        aho_corasick::AhoCorasick::new(["\"identifier\"", "\"telecom\"", "\"address\"", "\"name\""])
            .expect("aho-corasick")
    });

    /// What a column header names, after lowercasing and dropping `_ - . # space`.
    fn column_kind(header: &str) -> Option<(&'static str, bool)> {
        // Normalised on the stack: this runs for every cell of every header candidate.
        let mut buf = [0u8; 32];
        let mut len = 0;
        for b in header.bytes().filter(u8::is_ascii_alphanumeric) {
            if len == buf.len() {
                return None;
            }
            buf[len] = b.to_ascii_lowercase();
            len += 1;
        }
        let key = std::str::from_utf8(&buf[..len]).ok()?;
        // (kind, strong): a table is read only when at least one strong column is present.
        Some(match key {
            "mrn"
            | "mr"
            | "mrno"
            | "medicalrecordnumber"
            | "medicalrecordno"
            | "medrecno"
            | "patientid"
            | "ptid"
            | "patientnumber"
            | "patientno"
            | "chartnumber"
            | "chartno"
            | "chartid" => ("mrn", true),
            "dob" | "dateofbirth" | "birthdate" | "birthdt" => ("dob", true),
            "ssn" | "socialsecuritynumber" => ("ssn", true),
            "icd10" | "icd" | "icd10cm" | "icd10code" | "dx" | "dxcode" | "diagnosiscode"
            | "diagnosis" | "primarydx" | "primarydiagnosis" => ("icd10", true),
            "mbi" | "medicarembi" | "medicareid" | "medicarenumber" => ("medicare-mbi", true),
            "npi" => ("npi", true),
            "email" | "emailaddress" | "patientemail" => ("email", false),
            "phone" | "phonenumber" | "mobile" | "cell" | "homephone" | "patientphone" => {
                ("phone", false)
            }
            "lastname" | "firstname" | "patientname" | "fullname" | "name" | "middlename"
            | "familyname" | "givenname" => ("patient-name", false),
            _ => return None,
        })
    }

    /// Split one table line into trimmed fields with their byte spans. `,` honours double
    /// quotes; `|` drops the outer pipes of a markdown row.
    fn fields(line: &str, at: usize, delim: u8, out: &mut Vec<(usize, usize)>) {
        out.clear();
        let bytes = line.as_bytes();
        let mut i = 0;
        let mut start = 0;
        let mut quoted = false;
        while i <= bytes.len() {
            let b = bytes.get(i).copied();
            if b == Some(b'"') && delim == b',' {
                quoted = !quoted;
            } else if (b == Some(delim) && !quoted) || b.is_none() {
                out.push((start, i));
                start = i + 1;
            }
            i += 1;
        }
        if delim == b'|' {
            if out
                .first()
                .is_some_and(|(s, e)| line[*s..*e].trim().is_empty())
            {
                out.remove(0);
            }
            if out
                .last()
                .is_some_and(|(s, e)| line[*s..*e].trim().is_empty())
            {
                out.pop();
            }
        }
        for span in out.iter_mut() {
            let (s, e) = *span;
            let raw = &line[s..e];
            let lead = raw.len() - raw.trim_start_matches([' ', '\t', '"']).len();
            let trimmed = raw.trim_matches([' ', '\t', '"']);
            *span = (at + s + lead, at + s + lead + trimmed.len());
        }
    }

    fn full(re: &Regex, v: &str) -> bool {
        re.find(v)
            .is_some_and(|m| m.start() == 0 && m.end() == v.len())
    }

    static DOB_VALUE: LazyLock<Regex> = LazyLock::new(|| {
        re(&format!(
            r"(?:{}|[01]\d[0-3]\d(?:19|20)\d\d|(?:19|20)\d\d[01]\d[0-3]\d)",
            super::DATE
        ))
    });

    /// `[A-Z]\d[0-9AB](\.[0-9A-Z]{1,4})?`, the same shape as `ICD10`, checked bytewise: this
    /// runs for every row of a table.
    fn icd10_shape(v: &[u8]) -> bool {
        let head = v.len() >= 3
            && v[0].is_ascii_uppercase()
            && v[1].is_ascii_digit()
            && (v[2].is_ascii_digit() || matches!(v[2], b'A' | b'B'));
        let tail = &v[3.min(v.len())..];
        head && (tail.is_empty()
            || (tail[0] == b'.'
                && (2..=5).contains(&tail.len())
                && tail[1..]
                    .iter()
                    .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())))
    }

    fn valid(kind: &str, v: &str) -> bool {
        let b = v.as_bytes();
        match kind {
            "mrn" => {
                (4..=20).contains(&b.len())
                    && b[0].is_ascii_alphanumeric()
                    && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
                    && !v.eq_ignore_ascii_case("null")
            }
            "dob" => b.first().is_some_and(u8::is_ascii_alphanumeric) && full(&DOB_VALUE, v),
            "ssn" => {
                let d: Vec<u8> = b.iter().copied().filter(u8::is_ascii_digit).collect();
                d.len() == 9
                    && b.iter().all(|c| c.is_ascii_digit() || *c == b'-')
                    && matches!(b.len(), 9 | 11)
                    && super::ssn_valid(
                        std::str::from_utf8(&d[..3]).unwrap_or(""),
                        std::str::from_utf8(&d[3..5]).unwrap_or(""),
                        std::str::from_utf8(&d[5..]).unwrap_or(""),
                    )
            }
            "icd10" => icd10_shape(b),
            "medicare-mbi" => b.len() >= 11 && full(&super::MBI, v),
            "npi" => b.len() == 10 && b.iter().all(u8::is_ascii_digit) && super::npi_valid(v),
            "email" => b.contains(&b'@') && full(&super::EMAIL, v),
            "phone" => {
                b.iter().filter(|c| c.is_ascii_digit()).count() >= 10 && full(&super::PHONE, v)
            }
            "patient-name" => {
                (1..=41).contains(&b.len())
                    && b[0].is_ascii_alphabetic()
                    && b.iter().all(|c| {
                        c.is_ascii_alphabetic() || matches!(c, b'\'' | b' ' | b'.' | b',' | b'-')
                    })
            }
            _ => false,
        }
    }

    /// Delimited tables (CSV, TSV, markdown): a header that names at least one strong PHI column
    /// labels that column in every following row with the same number of fields (teardown B
    /// idea 1: the column header is the label). Each value must pass its column's validator.
    /// Every line is split once, so the pass is linear.
    pub fn table(input: &str, out: &mut Vec<PhiFinding>) {
        let mut columns: Vec<(usize, &'static str)> = Vec::new();
        let mut width = 0usize;
        let mut delim = b',';
        let mut offset = 0;
        let mut row: Vec<(usize, usize)> = Vec::new();
        let mut header: Vec<(usize, usize)> = Vec::new();
        for raw_line in input.split_inclusive('\n') {
            let at = offset;
            offset += raw_line.len();
            let line = raw_line.trim_end_matches(['\r', '\n']);
            if !columns.is_empty() {
                fields(line, at, delim, &mut row);
                let separator =
                    delim == b'|' && line.bytes().all(|b| matches!(b, b'|' | b'-' | b':' | b' '));
                if separator {
                    continue;
                }
                if row.len() == width && !line.trim().is_empty() {
                    for (index, kind) in &columns {
                        let (s, e) = row[*index];
                        if e > s && valid(kind, &input[s..e]) {
                            push(out, kind, input, s, e);
                        }
                    }
                    continue;
                }
                columns.clear();
            }
            // Header candidate.
            let Some(d) = (*b"\t|,").into_iter().find(|d| line.as_bytes().contains(d)) else {
                continue;
            };
            fields(line, at, d, &mut header);
            if header.len() < 2 {
                continue;
            }
            let named: Vec<(usize, &'static str, bool)> = header
                .iter()
                .enumerate()
                .filter_map(|(i, (s, e))| {
                    column_kind(&input[*s..*e]).map(|(k, strong)| (i, k, strong))
                })
                .collect();
            // Every header cell is a short identifier-like word, and one column is strong.
            let identifier_like = header.iter().all(|(s, e)| {
                let cell = &input[*s..*e];
                !cell.is_empty()
                    && cell.len() <= 40
                    && cell.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'_' | b' ' | b'-' | b'.' | b'#')
                    })
            });
            if identifier_like && named.iter().any(|(_, _, strong)| *strong) {
                columns = named.into_iter().map(|(i, k, _)| (i, k)).collect();
                width = header.len();
                delim = d;
            }
        }
    }

    fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        i
    }

    /// FHIR Patient-like JSON: `birthDate`, `identifier[].value` (SSN when the system names
    /// `ssn`, as `http://hl7.org/fhir/sid/us-ssn` does), `telecom[]` phone and email,
    /// `address[].line`, and `name` family and given. Read only when a `resourceType` of
    /// Patient, RelatedPerson or Person is present. Blocks come from one automaton pass and are
    /// read by a small hand parser: per-block regex calls cost ~26 ms per MiB of dense FHIR.
    pub fn fhir(input: &str, out: &mut Vec<PhiFinding>) {
        if !FHIR_PATIENT.is_match(input) {
            return;
        }
        for c in BIRTH_DATE.captures_iter(input) {
            let m = c.get(1).expect("group");
            push(out, "dob", input, m.start(), m.end());
        }
        let bytes = input.as_bytes();
        // Left to right, never overlapping: a block starting inside the previous region is
        // skipped, so 1 MiB of unclosed `"identifier":[` stays linear.
        let mut consumed_to = 0usize;
        for m in FHIR_BLOCK_KEYS.find_iter(input) {
            if m.start() < consumed_to {
                continue;
            }
            let colon = skip_ws(bytes, m.end());
            if bytes.get(colon) != Some(&b':') {
                continue;
            }
            let bracket = skip_ws(bytes, colon + 1);
            if bytes.get(bracket) != Some(&b'[') {
                continue;
            }
            let open = bracket + 1;
            // The fallback end is a byte count: round it down to a char boundary, or a
            // multibyte character straddling it panics the slice below (hostile review B1).
            let close = matching_bracket(input, bracket)
                .unwrap_or_else(|| input.floor_char_boundary(input.len().min(open + 8192)));
            consumed_to = close;
            let region = &input[open..close.max(open)];
            match &input[m.start() + 1..m.end() - 1] {
                "identifier" => {
                    for (at, object) in split_objects(region) {
                        let kind = if object.contains("ssn") { "ssn" } else { "mrn" };
                        each_field(input, out, open + at, object, "value", kind);
                    }
                }
                "telecom" => {
                    for (at, object) in split_objects(region) {
                        let kind = if object.contains("\"email\"") {
                            "email"
                        } else {
                            "phone"
                        };
                        each_field(input, out, open + at, object, "value", kind);
                    }
                }
                "address" => each_field(input, out, open, region, "line", "street-address"),
                "name" => {
                    each_field(input, out, open, region, "family", "patient-name");
                    each_field(input, out, open, region, "given", "patient-name");
                }
                _ => {}
            }
        }
    }

    /// Byte index of the bracket matching the one at `open`, bounded to 8 KiB, skipping strings.
    fn matching_bracket(input: &str, open: usize) -> Option<usize> {
        let bytes = input.as_bytes();
        let mut depth = 0i32;
        let mut in_string = false;
        let end = (open + 8192).min(bytes.len());
        let mut i = open;
        while i < end {
            let b = bytes[i];
            if in_string {
                if b == b'\\' {
                    i += 1;
                } else if b == b'"' {
                    in_string = false;
                }
            } else {
                match b {
                    b'"' => in_string = true,
                    b'[' | b'{' => depth += 1,
                    b']' | b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(i);
                        }
                    }
                    _ => {}
                }
            }
            i += 1;
        }
        None
    }

    /// Top-level `{...}` objects inside an array region: (offset within region, text).
    fn split_objects(region: &str) -> Vec<(usize, &str)> {
        let mut objects = Vec::new();
        let bytes = region.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'{' {
                let close = matching_bracket(region, i).unwrap_or(bytes.len() - 1);
                objects.push((i, &region[i..=close.min(bytes.len() - 1)]));
                i = close + 1;
            } else {
                i += 1;
            }
        }
        objects
    }

    /// Every string under `"field":` (one string, or an array of strings) in `region`.
    fn each_field(
        input: &str,
        out: &mut Vec<PhiFinding>,
        base: usize,
        region: &str,
        field: &str,
        kind: &'static str,
    ) {
        let key = format!("\"{field}\"");
        let bytes = region.as_bytes();
        let mut from = 0;
        while let Some(pos) = region[from..].find(&key) {
            let after = from + pos + key.len();
            from = after;
            let colon = skip_ws(bytes, after);
            if bytes.get(colon) != Some(&b':') {
                continue;
            }
            let mut i = skip_ws(bytes, colon + 1);
            let in_array = bytes.get(i) == Some(&b'[');
            if in_array {
                i += 1;
            }
            loop {
                i = skip_ws(bytes, i);
                if bytes.get(i) != Some(&b'"') {
                    break;
                }
                let start = i + 1;
                let mut end = start;
                while end < bytes.len() && bytes[end] != b'"' && end - start <= 256 {
                    end += if bytes[end] == b'\\' { 2 } else { 1 };
                }
                let end = end.min(bytes.len());
                if region.get(start..end).is_some_and(|v| v.trim().len() >= 2) {
                    push(out, kind, input, base + start, base + end);
                }
                i = end + 1;
                if !in_array {
                    break;
                }
                i = skip_ws(bytes, i);
                if bytes.get(i) == Some(&b',') {
                    i += 1;
                } else {
                    break;
                }
            }
            from = from.max(i.min(bytes.len()));
        }
    }
}

/// Keep the longest finding where findings overlap (an SSN inside a labelled SSN, a phone
/// inside an address). Accepted spans are disjoint, so neighbour checks suffice.
fn resolve_overlaps(mut out: Vec<PhiFinding>) -> Vec<PhiFinding> {
    // Sorted by start (longest first on ties), accepted spans stay disjoint, so a new finding
    // can only overlap the last accepted one: one linear sweep.
    // Stable sort: detectors emit sorted runs, which the run-detecting sort merges cheaply.
    out.sort_by_key(|f| (f.start, std::cmp::Reverse(f.end - f.start)));
    let mut kept: Vec<PhiFinding> = Vec::with_capacity(out.len());
    for f in out {
        match kept.last() {
            Some(last) if f.start < last.end => {
                if f.end - f.start > last.end - last.start {
                    kept.pop();
                    kept.push(f);
                }
            }
            _ => kept.push(f),
        }
    }
    kept
}

/// Replace each PHI span with `[PHI withheld]` (P-16: no fingerprint, so nothing derived from
/// the individual leaves the machine).
pub fn withhold(input: &str, findings: &[PhiFinding]) -> String {
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0;
    for f in findings {
        out.push_str(&input[cursor..f.start]);
        out.push_str("[PHI withheld]");
        cursor = f.end;
    }
    out.push_str(&input[cursor..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(text: &str) -> Vec<&'static str> {
        scan_phi(text, PhiOptions::default())
            .iter()
            .map(|f| f.kind)
            .collect()
    }

    #[test]
    fn ssn_rules() {
        assert_eq!(kinds("SSN 219-09-9999 on file"), vec!["ssn"]);
        assert_eq!(kinds("ssn: 219099999"), vec!["ssn"]);
        assert!(kinds("part 000-12-3456 and 666-12-3456 and 912-12-3456").is_empty());
        assert!(kinds("order 219-00-1234 x 219-09-0000").is_empty());
        assert!(kinds("order number 219099999 shipped").is_empty());
        assert!(kinds("219-09 9999").is_empty(), "mixed separators");
    }

    #[test]
    fn npi_needs_luhn_and_context() {
        // 1234567893 is the CMS documentation example that passes the 80840 Luhn check.
        assert_eq!(kinds("Prescriber NPI: 1234567893"), vec!["npi"]);
        assert!(kinds("NPI: 1234567890").is_empty(), "bad check digit");
        assert!(
            kinds("tracking 1234567893 shipped").is_empty(),
            "no context"
        );
    }

    #[test]
    fn mrn_dob_mbi_icd() {
        assert_eq!(kinds("MRN: A1234567"), vec!["mrn"]);
        assert_eq!(kinds("Medical Record Number 00482913"), vec!["mrn"]);
        assert_eq!(kinds("DOB: 03/14/1962"), vec!["dob"]);
        assert_eq!(kinds("date of birth March 4, 1958"), vec!["dob"]);
        assert_eq!(
            kinds("Patient Jane Roe, 04/12/1980, seen today"),
            vec!["dob"]
        );
        assert_eq!(kinds("Medicare 1EG4-TE5-MK73"), vec!["medicare-mbi"]);
        assert_eq!(kinds("Diagnosis: E11.9 type 2"), vec!["icd10"]);
        assert!(kinds("part E11.9 in stock").is_empty());
        assert!(kinds("released 2024-01-05").is_empty(), "ordinary date");
    }

    #[test]
    fn contacts_need_clinical_context() {
        assert!(kinds("Contact support at help@acme.test or (212) 555-0147").is_empty());
        let k = kinds("Patient callback (212) 555-0147, email jane.roe@mail.test");
        assert_eq!(k, vec!["phone", "email"]);
        assert_eq!(
            kinds("Patient lives at 1234 Elm Street, Springfield, IL 62701"),
            vec!["street-address"]
        );
        let opts = PhiOptions { phi_path: true };
        assert_eq!(scan_phi("help@acme.test", opts).len(), 1, "phi_paths file");
    }

    #[test]
    fn adjacent_values_are_all_found() {
        let text = "SSN 219-09-9999 219-09-9998 219-09-9997";
        assert_eq!(kinds(text).len(), 3);
    }

    #[test]
    fn withhold_replaces_spans_without_fingerprints() {
        let text = "Patient Jane Roe DOB: 03/14/1962 MRN: A1234567";
        let findings = scan_phi(text, PhiOptions::default());
        let out = withhold(text, &findings);
        assert_eq!(
            out,
            "Patient Jane Roe DOB: [PHI withheld] MRN: [PHI withheld]"
        );
        assert!(!format!("{findings:?}").contains("A1234567"));
    }

    #[test]
    fn multibyte_input_never_panics() {
        let text = "patient é漢字🙂 DOB: 03/14/1962 🙂 (555) 010-0199 é@é.é";
        let _ = scan_phi(text, PhiOptions { phi_path: true });
    }

    #[test]
    fn broader_dob_mrn_and_icd_forms() {
        assert_eq!(kinds("DOB: 14-Mar-1962"), vec!["dob"]);
        assert_eq!(kinds("DOB 03141962"), vec!["dob"]);
        assert_eq!(kinds("Seen in clinic: Roe, Jane 03/14/1962"), vec!["dob"]);
        assert!(
            kinds("Invoice for Jane Roe 03/14/2024").is_empty(),
            "no clinical context"
        );
        assert_eq!(kinds("MRN#: 00482913"), vec!["mrn"]);
        assert_eq!(kinds("Medical Record No.: 7781234"), vec!["mrn"]);
        assert_eq!(kinds("Patient ID 55120934"), vec!["mrn"]);
        let list = "Diagnoses (ICD-10) reviewed with the care team today in detail: E11.9, I10, J45.909, F32.1";
        assert_eq!(kinds(list), vec!["icd10", "icd10", "icd10", "icd10"]);
    }

    #[test]
    fn hl7_pid_fields() {
        let msg = "MSH|^~\\&|EPIC|HOSP|||202411081200||ADT^A01|123|P|2.5\rPID|1||00482913^^^HOSP^MR||ROE^JANE^Q||19620314|F|||1234 ELM ST^^SPRINGFIELD^IL^62701||(217)555-0147|||||||219-09-9999\rPV1|1|I|";
        let found = scan_phi(msg, PhiOptions::default());
        let get = |k: &str| {
            found
                .iter()
                .filter(|f| f.kind == k)
                .map(|f| f.value(msg).to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(get("mrn"), vec!["00482913"]);
        assert_eq!(get("patient-name"), vec!["ROE", "JANE"]);
        assert_eq!(get("dob"), vec!["19620314"]);
        assert_eq!(get("street-address"), vec!["1234 ELM ST"]);
        assert_eq!(get("phone"), vec!["(217)555-0147"]);
        assert_eq!(get("ssn"), vec!["219-09-9999"]);
    }

    #[test]
    fn fhir_patient_fields() {
        let json = r#"{"resourceType":"Patient","identifier":[{"system":"urn:oid:1.2.3","value":"MRN7781234"},{"system":"http://hl7.org/fhir/sid/us-ssn","value":"219-09-9999"}],"name":[{"family":"Roe","given":["Jane","Q"]}],"telecom":[{"system":"phone","value":"(217) 555-0147"},{"system":"email","value":"jane.roe@mail.test"}],"birthDate":"1962-03-14","address":[{"line":["1234 Elm Street","Apt 2"],"city":"Springfield"}]}"#;
        let found = scan_phi(json, PhiOptions::default());
        let kinds: Vec<&str> = found.iter().map(|f| f.kind).collect();
        for k in [
            "mrn",
            "ssn",
            "patient-name",
            "phone",
            "email",
            "dob",
            "street-address",
        ] {
            assert!(kinds.contains(&k), "{k} missing from {kinds:?}");
        }
        assert!(found.iter().any(|f| f.value(json) == "1234 Elm Street"));
        // Not a Patient resource: nothing structural is read.
        assert!(
            scan_phi(
                // `birthDate` is now a label anywhere (a key names its value), so the
                // structural negative uses a key that is not a PHI label.
                r#"{"resourceType":"Organization","date":"1962-03-14"}"#,
                PhiOptions::default()
            )
            .is_empty()
        );
    }

    fn count(text: &str, kind: &str) -> usize {
        kinds(text).iter().filter(|k| **k == kind).count()
    }

    /// Teardown B idea 1 and the v3 miss classes: a JSON or YAML key is a label.
    #[test]
    fn json_and_yaml_keys_label_their_values() {
        let json = r#"{"op":"sync","mrn":"QX40172","dob":"1950-07-04","dateOfBirth":"07/04/1950","patientId":"P5503921"}"#;
        assert_eq!(count(json, "mrn"), 2, "{:?}", kinds(json));
        assert_eq!(count(json, "dob"), 2, "{:?}", kinds(json));
        assert_eq!(kinds("dob: 1950-07-04"), vec!["dob"]);
        assert_eq!(kinds("  \"MRN\": \"988201744\","), vec!["mrn"]);
        let codes = r#"{"diagnosisCodes": ["E78.5", "I10", "K21.9"]}"#;
        assert_eq!(count(codes, "icd10"), 3, "{:?}", kinds(codes));
        assert!(kinds(r#"{"build":"2024-01-05","version":"E11.9"}"#).is_empty());
    }

    /// Teardown B idea 1: a table header names the column, so every row below it is labelled.
    #[test]
    fn table_columns_label_their_rows() {
        let csv = "mrn,last_name,first_name,dob,dx_code\nQX40172,Roe,Jane,07/04/1950,E78.5\nRT88120,Poe,Ann,1961-02-03,K21.9\n";
        assert_eq!(count(csv, "mrn"), 2, "{:?}", kinds(csv));
        assert_eq!(count(csv, "dob"), 2);
        assert_eq!(count(csv, "icd10"), 2);
        assert_eq!(count(csv, "patient-name"), 4);
        let quoted = "patient_id,name,dob\n\"A55120934\",\"Roe, Jane\",03/14/1962\n";
        assert_eq!(count(quoted, "mrn"), 1, "{:?}", kinds(quoted));
        assert_eq!(count(quoted, "dob"), 1);
        let tsv = "patient_id\tdob\tphone\nKS7470\t11/12/2003\t(617) 555-0141\n";
        assert_eq!(count(tsv, "mrn"), 1);
        assert_eq!(count(tsv, "phone"), 1);
        let md = "| MRN | DOB |\n|---|---|\n| QX40172 | 1950-07-04 |\n";
        assert_eq!(count(md, "mrn"), 1, "{:?}", kinds(md));
        assert_eq!(count(md, "dob"), 1);
        // No PHI column in the header: nothing is read.
        assert!(kinds("sku,price,date\nAB12345,9.99,2024-01-05\n").is_empty());
        // A value that fails the column's validator is not taken.
        assert!(kinds("mrn,dob\nn/a,unknown\n").is_empty());
    }

    /// Dotted ICD-10 codes in clinical text, and the SOAP `A:` line, count as diagnosis context.
    #[test]
    fn dotted_icd_codes_in_clinical_text() {
        assert_eq!(
            kinds("A: J18.9 Pneumonia, unspecified organism"),
            vec!["icd10"]
        );
        assert_eq!(
            kinds("Patient called about the new prescription for E03.9 today"),
            vec!["icd10"]
        );
        assert_eq!(
            count("Assessment: K21.9 - GERD; M17.11 - Unilateral OA", "icd10"),
            2
        );
        assert!(kinds("the B12 level was low on the lab panel").is_empty());
        assert!(kinds("firmware version E11.9 released for the router").is_empty());
    }

    #[test]
    fn hl7_dg1_diagnosis_code() {
        let msg = "MSH|^~\\&|EPIC|HOSP|||202411081200||ADT^A08|9|P|2.5\rDG1|1||G43.909^Migraine, unspecified^I10|||F\r";
        let found = scan_phi(msg, PhiOptions::default());
        assert!(
            found
                .iter()
                .any(|f| f.kind == "icd10" && f.value(msg) == "G43.909"),
            "{found:?}"
        );
    }

    /// Hostile review B1: an unterminated FHIR array followed by multibyte text panicked.
    #[test]
    fn unterminated_fhir_with_multibyte_text_does_not_panic() {
        let text = format!(
            r#"{{"resourceType":"Patient","name":[x{}"#,
            "é".repeat(5000)
        );
        let _ = scan_phi(&text, PhiOptions::default());
    }

    /// Randomised inputs built from every structured and labelled form, mixed with multibyte
    /// text: no slice may panic (the old test was one 55-byte string).
    #[test]
    fn random_structured_inputs_never_panic() {
        let pieces = [
            r#"{"resourceType":"Patient","#,
            r#""identifier":["#,
            r#""telecom":["#,
            r#""name":["#,
            r#""address":["#,
            r#""value":"#,
            r#""birthDate":""#,
            "PID|",
            "DG1|1||",
            "NK1|",
            "|",
            "^",
            "~",
            "\r",
            "\n",
            "mrn,dob,icd10\n",
            "| MRN | DOB |\n",
            ",",
            "\t",
            "\"",
            "é",
            "漢字",
            "🙂",
            "MRN: ",
            "DOB ",
            "A: ",
            "E11.9",
            "03/14/1962",
            "{",
            "}",
            "[",
            "]",
            "patient ",
            "219-09-9999",
            "x",
        ];
        let mut seed: u64 = 0xDEAD_BEEF_CAFE_F00D;
        for _ in 0..20_000 {
            let mut input = String::new();
            for _ in 0..(seed % 40) {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                input.push_str(pieces[(seed % pieces.len() as u64) as usize]);
            }
            let _ = scan_phi(&input, PhiOptions { phi_path: true });
        }
    }
}
