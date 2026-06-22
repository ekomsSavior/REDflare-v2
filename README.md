# REDflare v2

REDflare v2 is a standalone, scope-first framework for authorized network and web application reconnaissance and security assessment. It combines native service discovery, application mapping, evidence correlation, and visual investigation in one standards-backed workflow.

<img width="451" height="83" alt="Screenshot_20260621_190741" src="https://github.com/user-attachments/assets/f1a57df0-ff4a-4c27-ba93-c118d429ddf6" />



## What v2 adds

- A bounded same-origin crawler for links, forms, and execution paths
- Native TCP discovery, protocol identification, exact-version fingerprinting, and host-role inference
- Native TLS trust, certificate, protocol, cipher, SNI, ALPN, compression, and certificate-reuse assessment across discovered TLS services
- Form parameter, HTTP method, content type, and authentication-requirement mapping
- JavaScript route extraction from same-origin script assets
- OpenAPI 2.x and 3.x endpoint and parameter ingestion
- Explicit opt-in GraphQL schema introspection with bounded response sizes
- Native browser request/response ingestion and runtime evidence
- Sensitive-data exposure checks across HTML, JavaScript bundles, and mapped GET responses
- Exact-version component fingerprinting with live NVD CVE correlation and CVSS context
- Stable `RFV2-*` test IDs mapped to OWASP WSTG v4.2, ASVS 5.0.0, CWE, and OWASP API Security 2023
- Per-run `attack_surface.json` and `test_registry.json` artifacts
- Offline visual investigation console with CVE nodes, grouped evidence, URL pagination, and force/tree/radial layouts

## Current capabilities

- Optional JSON allowlist and explicit public-target gate
- Per-run manifests, module output, JSONL findings, summaries, artifacts, and HTML reports
- Native DNS and service-wide TLS assessment with controlled continuation after recorded trust failures
- HTTP status, redirect, response metadata, and security-header analysis
- Rate-limited path discovery with wildcard-response filtering
- Correlation of related observations into higher-confidence findings
- Native browser-runtime capture derived from GATEkeeper
- Native unauthenticated-surface triage derived from noauth_finder
- Native repository secret intelligence derived from REAPER
- Standard-library-only core; no required runtime dependencies

## Run locally

The bundled launcher uses the system Python and requires no installation:

```bash
git clone https://github.com/ekomsSavior/REDflare-v2.git
cd REDflare-v2
./bin/redflare --help
```

Optional editable installation (requires the operating system's `python3-venv` package):

```bash
cd REDflare-v2
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/redflare --help
```

## Quick start

Run only against systems you own or have explicit written authorization to test.

Launch REDflare with no arguments for the guided interface:

```bash
./bin/redflare
```

<img width="466" height="230" alt="Screenshot_20260621_093338" src="https://github.com/user-attachments/assets/f247410f-dcba-4674-b825-d23972c4521a" />

The main menu also discovers recent runs and launches the visual investigation
console without requiring command-line flags. Both ordinary paths and local
`file:///...` URLs are accepted.
After a guided scan, REDflare offers to open that exact completed run immediately.

The wizard walks through:

1. Full, web, or quick assessment mode
2. One or more targets, or a target-list file
3. Optional strict JSON scope file
4. Explicit authorization and public-scope confirmation
5. Browser/service-probing permission for full mode
6. Output, concurrency, timeout, rate, and path settings
7. Optional wordlist and associated GitHub repositories

Full mode runs the complete pipeline automatically for each target:

```text
Native TCP discovery → protocol identification → native TLS assessment → host-role inference
        → HTTP headers → surface/forms/redirects → application mapping
        → path discovery → native browser capture → native no-auth triage
        → NVD CVE correlation → sensitive-exposure analysis → correlation
        → optional native repository intelligence → unified report
```

Flags remain available for repeatable automation and CI workflows.

During a run, REDflare streams stage transitions, DNS/TLS results, HTTP status,
surface counts, path-probe progress, normalized browser request/response events,
elapsed times, and failures. Sub-tool banners and per-tool summaries are suppressed;
raw module evidence remains in the evidence folder. Reporting appears once, after the
complete pipeline finishes, as a full module-by-module assessment dossier. The
terminal and HTML reports include every module's observations, findings, errors,
timing, and artifact paths followed by consolidated, deduplicated findings.

```bash
./bin/redflare modules
./bin/redflare doctor
./bin/redflare tests

./bin/redflare scan http://127.0.0.1:8000 \
  --authorized \
  --profile web
```

## Visual investigation console

Open any completed REDflare run as a local, read-only graph workspace:

```bash
./bin/redflare visualize runs/run_20260620_120000
```
<img width="861" height="927" alt="IMG_4927" src="https://github.com/user-attachments/assets/2afdf195-91b2-40d5-86b7-daeae056834c" />

The console binds only to `127.0.0.1`, reads existing run artifacts, and does not
send assessment data to a cloud service. It includes:

- Force-directed, hierarchy-tree, and radial layouts
- Typed nodes for targets, network hosts, services, technologies, endpoints, parameters, schemas, findings, exposures, CVEs, and standards
- Search across URLs, evidence, parameters, severities, and test IDs
- Per-layer filtering and connected-node highlighting
- Zoom, pan, drag, fit-to-view, and keyboard-accessible node inspection
- A grouped evidence panel with collapsible sections, deduplicated/paginated URLs, and copy control
Choose a different loopback port or suppress automatic browser launch:

```bash
./bin/redflare visualize runs/run_20260620_120000 --port 9000 --no-browser
```

Tune application mapping limits explicitly:

```bash
./bin/redflare scan https://authorized.example \
  --authorized --allow-public --profile web \
  --max-crawl-pages 50 --max-crawl-depth 3 \
  --max-scripts 30 --max-schema-documents 10
```

GraphQL introspection is disabled by default and requires a separate opt-in:

```bash
./bin/redflare scan https://authorized.example \
  --authorized --allow-public --profile web \
  --graphql-introspection
```

Run REDflare's native repository intelligence:

```bash
export GITHUB_TOKEN="your_token"
./bin/redflare intel \
  --authorized \
  --repo https://github.com/owner/repository
```

Public targets require an additional acknowledgement:

```bash
./bin/redflare scan https://authorized.example \
  --authorized \
  --allow-public \
  --profile web
```

## Scope files

Use a JSON scope file to prevent accidental target drift:

```json
{
  "allowed_hosts": ["app.example.test", "api.example.test"],
  "allow_public": false
}
```

```bash
./bin/redflare scan https://app.example.test \
  --authorized \
  --scope examples/scope.example.json
```

## Profiles

| Profile | Modules |
|---|---|
| `quick` | passive recon, HTTP headers, CVE correlation, and root-response exposure analysis |
| `web` | quick plus surface analysis, application mapping, path discovery, and mapped-response exposure analysis |
| `full` | web plus native network discovery, protocol identification, browser-runtime capture, and authorization triage |

Both `web` and `full` include application mapping. The `full` profile additionally runs REDflare's native browser-runtime and unauthenticated-surface modules and merges their evidence into the shared graph. No external GATEkeeper, noauth_finder, or REAPER installation is required. When Playwright/Chromium is available, the runtime module executes JavaScript in a real browser; otherwise it automatically uses REDflare's native HTTP runtime capture rather than skipping the module.

## Native network discovery

Full Assessment begins with scope-controlled TCP discovery, safe protocol identification,
exact-version fingerprinting, and confidence-scored host-role inference. Results are stored
as network-host, service, and technology nodes in the shared graph and feed exact versions
into CVE intelligence. Open ports are observations; REDflare creates a finding only when an
explicitly authorized enumeration check provides evidence of a risky condition.

The guided wizard offers Basic, Standard, Extended, and separately confirmed Complete
(1-65535) TCP depth. Automation can use `--network-depth`, `--ports`,
`--network-concurrency`, `--network-timeout`, and the separately authorized
`--service-enumeration` switch. Artifacts are written under
`artifacts/network_discovery/<target>/` as `port_scan.json`,
`service_enumeration.json`, and `fingerprints.json`.

## Native TLS assessment

Every profile validates the target certificate before HTTP collection. Full Assessment also
assesses every TLS service found by network discovery, including non-HTTP services such as
LDAPS, SMTPS, IMAPS, POP3S, Docker TLS, and WinRM TLS. REDflare records certificate trust,
self-signed/unknown-authority failures, SAN and hostname matching, validity, serial and
SHA-256 fingerprint, public-key and signature properties, negotiated TLS/cipher/ALPN,
compression, SNI behavior, TLS 1.0–1.3 support, TLS 1.2-and-earlier cipher support, weak
suites, and certificate reuse.

When enabled in the guided workflow, a trust failure is reported first and REDflare then
continues against only that same authorized TLS origin. The `transport_policy` result lists
every URL collected without trust validation. Use `--no-tls-continuation` to stop that retry
behavior or `--no-tls-cipher-enumeration` to omit the cipher sweep.

Protocol-aware identification currently covers HTTP/HTTPS and generic TLS, SSH, FTP,
SMTP, POP3, IMAP, SMB2, RDP, MySQL, PostgreSQL, VNC, and explicitly authorized Redis
PING. Additional known infrastructure ports are recorded with lower-confidence port
evidence until corroborated by banners, application evidence, or future protocol parsers.

Scope files may constrain resolved addresses and ports:

```json
{
  "allowed_hosts": ["app.example.test"],
  "allowed_networks": ["10.0.0.0/24"],
  "allow_public": false,
  "scan_ports": {"include": [22, 80, 443, 445], "exclude": [22]},
  "discovery_depth": "standard"
}
```

## CVE intelligence

Every profile passively identifies exact component versions disclosed in HTTP
headers, generator metadata, and common JavaScript/CSS asset names. Exact CPEs are
correlated with the NVD CVE API 2.0. Product names without versions are retained as
ordinary observations and do not produce speculative CVE findings.

Matches include the CVE ID, NVD description and status, CVSS score/vector,
fingerprint evidence, affected CPE, dates, and NVD/CVE/vendor references. They are
printed live, saved in `findings.jsonl` and module data, rendered as clickable links
in `report.html`, and represented as dedicated CVE nodes in the visual console.
NVD-provided CISA Known Exploited Vulnerabilities fields are highlighted when present.

Unauthenticated NVD access is deliberately paced to respect public API limits. REDflare
retries temporary 429/5xx and timeout failures, honors `Retry-After`, caches successful CPE
responses per run, preserves successful lookups, and reports CVE coverage as `complete`,
`partial`, or `unavailable` rather than treating an outage as zero CVEs.

For larger authorized portfolios, set an NVD API key before scanning:

```bash
export NVD_API_KEY="your-nvd-api-key"
./bin/redflare scan https://authorized.example --authorized --allow-public --profile web
```

For shell-history-safe configuration, put only the key in a user-readable file (`chmod 600`)
and use `--nvd-api-key-file /path/to/key` or `NVD_API_KEY_FILE`. Tune outage behavior with
`--nvd-timeout` and `--nvd-retries`; `./bin/redflare doctor` reports whether keyed or public
NVD access is configured without printing the secret.

Use `--max-cve-products` and `--max-cves-per-product` to tune collection volume.

## Sensitive-data exposure checks

Every profile checks in-scope responses for credential patterns, private keys,
credentialed database URLs, JWTs, recognized password-hash formats, sensitive
JavaScript assignments, and private/internal IP addresses. Web and full profiles
inspect the mapped GET surface, including same-origin JavaScript bundles and path
discovery hits.

Each match is printed during the run and included in the terminal dossier,
`report.html`, `findings.jsonl`, the module result, and a dedicated masked artifact:

```text
artifacts/sensitive_exposure/<host>/exposures.json
```

Credential and password-hash values are masked by design. Reports retain the
location, line number, redacted context, value preview, and a SHA-256 fingerprint
for verification and deduplication. Private/internal IP addresses are retained in
full because they are the disclosure evidence itself. A private IP appearing in a
response is reported as information disclosure; REDflare does not label it IDOR
without an authorization comparison proving object-level access failure.

Path discovery accepts any user-provided wordlist:

```bash
./bin/redflare scan http://127.0.0.1:8000 \
  --authorized \
  --profile web \
  --wordlist /path/to/paths.txt \
  --rate 2 \
  --max-paths 500
```

## Run layout

```text
runs/run_YYYYMMDD_HHMMSS/
├── manifest.json
├── findings.jsonl
├── summary.json
├── report.html
├── attack_surface.json
├── test_registry.json
├── modules/
└── artifacts/
```

Every module emits the same finding structure, including target, module, category, severity, confidence, description, evidence, tags, timestamp, and stable fingerprint.

## Testing

Tests use a local HTTP fixture and do not contact public infrastructure.

```bash
python3 -m unittest discover -v
python3 -m compileall -q redflare tests
```

## Standards registry

`redflare tests` prints the machine-readable registry. Every emitted finding from a registered check receives a stable test ID and versioned standards metadata. The registry intentionally pins WSTG v4.2 and ASVS 5.0.0 identifiers so future standards releases cannot silently change report meaning.

## Roadmap

- Add SQLite indexing, SARIF, and a local dashboard
- Add resume/checkpoint support and richer cross-module correlation
- Add signed plugin manifests and module capability declarations

## Disclaimer

REDflare is intended solely for authorized security testing, defensive research, and education. Users are responsible for defining and respecting legal scope.
