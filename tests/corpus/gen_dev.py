#!/usr/bin/env python3
"""Development corpus for the Lockrail engine (PLAN.md Phase 3E).

Written by the implementer and used for tuning. The held-out corpus in tests/heldout/ is
generated blind by a separate agent and is never used for tuning. Seeded; run with
`python3 -I tests/corpus/gen_dev.py > tests/corpus/dev.jsonl`.
"""
import base64, json, random, string

R = random.Random(7_2026_11_08)
AL = string.ascii_letters + string.digits
HEX = "0123456789abcdef"

def rs(n, alphabet=AL):
    return "".join(R.choice(alphabet) for _ in range(n))

def luhn_ok(npi):
    digits = [int(c) for c in "80840" + npi]
    s = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9: d -= 9
        s += d
    return s % 10 == 0

def npi():
    while True:
        cand = "1" + rs(9, string.digits)
        if luhn_ok(cand): return cand

def ssn():
    while True:
        a, g, s = R.randint(1, 899), R.randint(1, 99), R.randint(1, 9999)
        if a != 666: return f"{a:03d}-{g:02d}-{s:04d}"

MBI_A = "ACDEFGHJKMNPQRTUVWXY"
def mbi():
    an = MBI_A + string.digits
    return (R.choice("123456789") + R.choice(MBI_A) + R.choice(an) + R.choice(string.digits)
            + R.choice(MBI_A) + R.choice(an) + R.choice(string.digits)
            + R.choice(MBI_A) + R.choice(MBI_A) + rs(2, string.digits))

SECRETS = {
    "openai-key": lambda: "sk-proj-" + rs(40) if R.random() < .5 else "sk-" + rs(48),
    "anthropic-key": lambda: "sk-ant-api03-" + rs(80, AL + "-_") + "AA",
    "github-token": lambda: R.choice(["ghp_", "gho_", "ghs_", "ghu_"]) + rs(36),
    "aws-access-key-id": lambda: "AKIA" + rs(16, string.ascii_uppercase + "234567"),
    "slack-token": lambda: R.choice(["xoxb-", "xoxp-"]) + rs(11, string.digits) + "-" + rs(12, string.digits) + "-" + rs(24),
    "stripe-key": lambda: "sk_live_" + rs(40),
    "google-api-key": lambda: "AIza" + rs(35, AL + "-_"),
    "npm-token": lambda: "npm_" + rs(36),
    "jwt": lambda: "eyJ" + rs(30, AL + "_-") + "." + "eyJ" + rs(40, AL + "_-") + "." + rs(43, AL + "_-"),
    "database-url": lambda: f"postgres://app:{rs(16)}@db.internal:5432/main",
    "bearer-token": lambda: rs(40, AL + "._-"),
    "private-key": lambda: "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(rs(64, AL + "+/") for _ in range(6)) + "\n-----END RSA PRIVATE KEY-----",
    "twilio": lambda: rs(32, HEX),
    "azure-storage-key": lambda: rs(86, AL + "+/") + "==",
}
SECRET_TEMPLATES = [
    "export {NAME}={v}",
    "{NAME}={v}\nDEBUG=false",
    "Can you check why this fails? curl -H 'x-key: {v}' https://api.example.test/v1",
    "config:\n  credentials:\n    value: \"{v}\"\n",
    "const client = new Client(\"{v}\");",
    "I pasted the wrong thing earlier, the real one is {v} please fix the script",
    "os.environ.setdefault('{NAME}', '{v}')",
]

PHI = {
    "ssn": lambda: ssn(),
    "npi": lambda: npi(),
    "mrn": lambda: R.choice(["A", "MR", ""]) + rs(7, string.digits),
    "dob": lambda: f"{R.randint(1,12):02d}/{R.randint(1,28):02d}/{R.randint(1935,2005)}",
    "medicare-mbi": lambda: mbi(),
    "icd10": lambda: R.choice(["E11.9", "I10", "J45.909", "F32.1", "M54.5", "K21.9"]),
    "phone": lambda: f"({R.choice(['212','415','617','312'])}) 555-01{R.randint(0,99):02d}",
    "email": lambda: f"{rs(6, string.ascii_lowercase)}.{rs(5, string.ascii_lowercase)}@mail.test",
    "street-address": lambda: f"{R.randint(10,9999)} {R.choice(['Oak','Maple','Cedar','Pine'])} {R.choice(['Street','Ave','Road','Lane'])}, {R.choice(['Springfield','Riverton','Fairview'])}, {R.choice(['IL','OR','TX'])} {R.randint(10000,99999)}",
}
PHI_TEMPLATES = {
    "ssn": ["Patient SSN: {v}", "ssn {v} on the intake form"],
    "npi": ["Prescriber NPI {v}", "rendering provider npi: {v}"],
    "mrn": ["MRN: {v}", "Medical Record Number {v} for follow-up", "MRN#: {v}", "Patient ID {v} admitted"],
    "dob": ["DOB: {v}", "Patient Jane Roe, {v}, presented with cough", "date of birth {v}", "Seen in clinic today: Doe, John {v}"],
    "medicare-mbi": ["Medicare ID {v}", "MBI: {v}"],
    "icd10": ["Diagnosis: {v}", "Assessment: {v} stable"],
    "phone": ["Patient callback {v}", "Pt mobile {v}, MRN pending"],
    "email": ["Patient portal email {v}", "send discharge summary to {v} (patient)"],
    "street-address": ["Patient lives at {v}", "Home address on chart: {v}"],
}

BENIGN = [
    lambda: f"commit {rs(40, HEX)} merged",
    lambda: f"request id {rs(8,HEX)}-{rs(4,HEX)}-{rs(4,HEX)}-{rs(4,HEX)}-{rs(12,HEX)}",
    lambda: f"sha256:{rs(64, HEX)}",
    lambda: f"version {R.randint(0,9)}.{R.randint(0,30)}.{R.randint(0,99)} released on 2024-0{R.randint(1,9)}-1{R.randint(0,9)}",
    lambda: "OPENAI_API_KEY=sk-proj-xxxxxxxxxxxxxxxxxxxx",
    lambda: "api_key = os.environ[\"API_KEY\"]",
    lambda: "token = get_token()",
    lambda: "password = ''",
    lambda: "AKIAIOSFODNN7EXAMPLE",
    lambda: f"Contact sales at sales@{rs(5, string.ascii_lowercase)}.test or (415) 555-01{R.randint(0,99):02d}",
    lambda: f"Ship to {R.randint(10,999)} Market Street, San Francisco, CA 94105 for order {rs(9, string.digits)}",
    lambda: f"order {rs(9, string.digits)} and invoice {rs(10, string.digits)}",
    lambda: "part number E11-9A in stock, css class .i10-grid",
    lambda: "postgres://localhost:5432/app",
    lambda: f"img: data:image/png;base64,{base64.b64encode(bytes(R.getrandbits(8) for _ in range(60))).decode()}",
    lambda: f"color: #{rs(6, HEX)}; margin: 0 auto;",
    lambda: "lockrail://secret/openai-key/h_" + rs(32, HEX),
    lambda: "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
    lambda: "The patient education handout explains how to take medication with food.",
    lambda: f"integrity sha512-{base64.b64encode(bytes(R.getrandbits(8) for _ in range(64))).decode()}",
    lambda: "-----BEGIN PUBLIC KEY-----\n" + rs(64, AL + "+/") + "\n-----END PUBLIC KEY-----",
    lambda: "-----BEGIN CERTIFICATE-----\n" + rs(64, AL + "+/") + "\n-----END CERTIFICATE-----",
    lambda: "-----BEGIN PGP SIGNATURE-----\n" + rs(64, AL + "+/") + "\n-----END PGP SIGNATURE-----",
    lambda: f"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{rs(43, AL + '+/')} dev@laptop",
    lambda: "DATABASE_URL=postgres://postgres@localhost:5432/app",
    lambda: "DATABASE_URL=postgres://app:${DB_PASSWORD}@db:5432/app",
    lambda: "Authorization: Bearer YOUR_TOKEN_HERE",
    lambda: "API_KEY=YOUR_API_KEY_HERE",
    lambda: "password = userPassword",
    lambda: "token: settings.apiToken",
    lambda: "client_secret = REPLACE_ME",
]

out = []
n = 0
for kind, gen in SECRETS.items():
    for i in range(10):
        v = gen()
        name = kind.upper().replace("-", "_")
        if kind == "bearer-token":
            text = f"curl -H 'Authorization: Bearer {v}' https://api.example.test"
        elif kind == "twilio":
            text = f"TWILIO_ACCOUNT_SID=AC{rs(32, HEX)}\nTWILIO_AUTH_TOKEN={v}"
        elif kind == "azure-storage-key":
            text = f"DefaultEndpointsProtocol=https;AccountName=acct{i};AccountKey={v};EndpointSuffix=core.windows.net"
        elif kind == "private-key":
            text = f"here is the key file:\n{v}\nthanks"
        else:
            text = R.choice(SECRET_TEMPLATES).format(NAME=name, v=v)
        n += 1
        out.append({"id": f"dev-s{n}", "category": "secret", "text": text,
                    "expect": [{"class": "secret", "type": kind, "value": v}]})
for kind, gen in PHI.items():
    for i in range(10):
        v = gen()
        text = R.choice(PHI_TEMPLATES[kind]).format(v=v)
        n += 1
        out.append({"id": f"dev-p{n}", "category": "phi", "text": text,
                    "expect": [{"class": "phi", "type": kind, "value": v}]})
for i in range(120):
    n += 1
    out.append({"id": f"dev-b{n}", "category": "benign", "text": BENIGN[i % len(BENIGN)](), "expect": []})
# Structured payloads (HL7 v2 PID, FHIR Patient), written from the published layouts.
for i in range(10):
    mrn, dob, ss = rs(8, string.digits), f"19{R.randint(30,99)}{R.randint(1,12):02d}{R.randint(1,28):02d}", ssn()
    phone = f"(312)555-01{R.randint(0,99):02d}"
    street = f"{R.randint(10,9999)} OAK ST"
    hl7 = (f"MSH|^~\\&|EHR|CLINIC|||20241108||ADT^A04|{i}|P|2.5\r"
           f"PID|1||{mrn}^^^CLINIC^MR||DOE^JOHN||{dob}|M|||{street}^^RIVERTON^OR^97000||{phone}|||||||{ss}\r")
    n += 1
    out.append({"id": f"dev-h{n}", "category": "phi", "text": hl7, "expect": [
        {"class": "phi", "type": "mrn", "value": mrn}, {"class": "phi", "type": "dob", "value": dob},
        {"class": "phi", "type": "ssn", "value": ss}, {"class": "phi", "type": "phone", "value": phone},
        {"class": "phi", "type": "street-address", "value": street}]})
    bd = f"19{R.randint(30,99)}-{R.randint(1,12):02d}-{R.randint(1,28):02d}"
    email = f"{rs(5, string.ascii_lowercase)}@mail.test"
    fhir = json.dumps({"resourceType": "Patient", "identifier": [{"system": "urn:oid:2.16.1", "value": mrn}],
                       "name": [{"family": "Doe", "given": ["John"]}],
                       "telecom": [{"system": "phone", "value": phone}, {"system": "email", "value": email}],
                       "birthDate": bd, "address": [{"line": [street.title()], "city": "Riverton"}]})
    n += 1
    out.append({"id": f"dev-f{n}", "category": "phi", "text": fhir, "expect": [
        {"class": "phi", "type": "mrn", "value": mrn}, {"class": "phi", "type": "dob", "value": bd},
        {"class": "phi", "type": "phone", "value": phone}, {"class": "phi", "type": "email", "value": email},
        {"class": "phi", "type": "street-address", "value": street.title()}]})
for case in out:
    print(json.dumps(case))
