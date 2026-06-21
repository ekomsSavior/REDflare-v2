# REDflare v2

REDflare v2 is a scope-first orchestration framework for authorized web application reconnaissance and security assessment. It adds a shared attack-surface graph and a standards-backed test registry while preserving the original REDflare project unchanged.

<img width="457" height="105" alt="Screenshot_20260621_073244-1" src="https://github.com/user-attachments/assets/a98db72d-e00c-4651-a68a-fefb5b8d983b" />


## What v2 adds

- A bounded same-origin crawler for links, forms, and execution paths
- A deduplicated endpoint inventory shared by native modules and adapters
- Form parameter, HTTP method, content type, and authentication-requirement mapping
- JavaScript route extraction from same-origin script assets
- OpenAPI 2.x and 3.x endpoint and parameter ingestion
- Explicit opt-in GraphQL schema introspection with bounded response sizes
- Browser request/response ingestion from GATEkeeper reports
- Sensitive-data exposure checks across HTML, JavaScript bundles, and mapped GET responses
- Exact-version component fingerprinting with live NVD CVE correlation and CVSS context
- Stable `RFV2-*` test IDs mapped to OWASP WSTG v4.2, ASVS 5.0.0, CWE, and OWASP API Security 2023
- Per-run `attack_surface.json` and `test_registry.json` artifacts
- Offline visual investigation console with CVE nodes, grouped evidence, URL pagination, and force/tree/radial layouts

## Current capabilities

- Optional JSON allowlist and explicit public-target gate
- Per-run manifests, module output, JSONL findings, summaries, artifacts, and HTML reports
- Native DNS/TLS reconnaissance
- HTTP status, redirect, response metadata, and security-header analysis
- Rate-limited path discovery with wildcard-response filtering
- Correlation of related observations into higher-confidence findings
- Optional adapters for GATEkeeper and noauth_finder
- Repository secret-intelligence bridge to REAPER
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
DNS/TLS → HTTP headers → surface/forms/redirects → application mapping
        → path discovery → GATEkeeper browser capture → noauth_finder
        → NVD CVE correlation → sensitive-exposure analysis → correlation
        → optional REAPER repository intelligence → unified report
```

Flags remain available for repeatable automation and CI workflows.

During a run, REDflare streams stage transitions, DNS/TLS results, HTTP status,
surface counts, path-probe progress, normalized browser request/response events,
elapsed times, and failures. Sub-tool banners and per-tool summaries are suppressed;
raw adapter logs remain in the evidence folder. Reporting appears once, after the
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

The console binds only to `127.0.0.1`, reads existing run artifacts, and does not
send assessment data to a cloud service. It includes:

- Force-directed, hierarchy-tree, and radial layouts
- Typed nodes for targets, endpoints, parameters, schemas, findings, exposures, CVEs, and standards
- Search across URLs, evidence, parameters, severities, and test IDs
- Per-layer filtering and connected-node highlighting
- Zoom, pan, drag, fit-to-view, and keyboard-accessible node inspection
- A grouped evidence panel with collapsible sections, deduplicated/paginated URLs, and copy controls

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

Run repository intelligence through the existing REAPER binary:

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
| `full` | web plus GATEkeeper and noauth_finder adapters |

Both `web` and `full` include application mapping. The `full` profile additionally merges browser-observed network traffic into the shared graph.

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

Unauthenticated NVD access is deliberately paced to respect public API limits. For
larger authorized portfolios, set an NVD API key before scanning:

```bash
export NVD_API_KEY="your-nvd-api-key"
./bin/redflare scan https://authorized.example --authorized --allow-public --profile web
```

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

- Parse GATEkeeper and noauth_finder reports into native findings
- Add a REAPER global-intelligence adapter
- Add SQLite indexing, SARIF, and a local dashboard
- Add resume/checkpoint support and richer cross-module correlation
- Add signed plugin manifests and module capability declarations

## Disclaimer

REDflare is intended solely for authorized security testing, defensive research, and education. Users are responsible for defining and respecting legal scope.
