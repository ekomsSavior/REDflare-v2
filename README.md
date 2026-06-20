# REDflare v2

REDflare v2 is a scope-first orchestration framework for authorized web application reconnaissance and security assessment. It adds a shared attack-surface graph and a standards-backed test registry while preserving the original REDflare project unchanged.

## What v2 adds

- A bounded same-origin crawler for links, forms, and execution paths
- A deduplicated endpoint inventory shared by native modules and adapters
- Form parameter, HTTP method, content type, and authentication-requirement mapping
- JavaScript route extraction from same-origin script assets
- OpenAPI 2.x and 3.x endpoint and parameter ingestion
- Explicit opt-in GraphQL schema introspection with bounded response sizes
- Browser request/response ingestion from GATEkeeper reports
- Stable `RFV2-*` test IDs mapped to OWASP WSTG v4.2, ASVS 5.0.0, CWE, and OWASP API Security 2023
- Per-run `attack_surface.json` and `test_registry.json` artifacts

## Current capabilities

- Mandatory authorization acknowledgement before active scans
- Optional JSON allowlist and explicit public-target gate
- Per-run manifests, module output, JSONL findings, summaries, artifacts, and HTML reports
- Native DNS/TLS reconnaissance
- HTTP status, redirect, response metadata, and security-header analysis
- Rate-limited path discovery with wildcard-response filtering
- Correlation of related observations into higher-confidence findings
- Optional adapters for GATEkeeper and noauth_finder
- Repository secret-intelligence bridge to REAPER
- Standard-library-only core; no required runtime dependencies

REDflare intentionally excludes denial-of-service, flooding, spam, disruption, credential validation, and destructive actions.

## Source-tool map

| REDflare capability | Existing project |
|---|---|
| GitHub secret intelligence | REAPER |
| Path discovery concepts | Sentinel |
| Unauthenticated service triage | noauth_finder |
| Browser/runtime evidence | GATEkeeper |
| DNS, TLS, redirects, and form-analysis concepts | PHISH_HUNTER_PRO `deep_recon.py` |

The source repositories remain untouched. REDflare either implements a clean native module or invokes an existing tool through an adapter.

## Run locally

The bundled launcher uses the system Python and requires no installation:

```bash
git clone https://github.com/ekomsSavior/REDflare.git
cd REDflare
./bin/redflare --help
```

Optional editable installation (requires the operating system's `python3-venv` package):

```bash
cd REDflare
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
DNS/TLS → HTTP headers → surface/forms/redirects → path discovery
        → GATEkeeper browser capture → noauth_finder → correlation
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
| `quick` | passive recon, HTTP headers |
| `web` | quick plus surface analysis, application mapping, and path discovery |
| `full` | web plus GATEkeeper and noauth_finder adapters |

Both `web` and `full` include application mapping. The `full` profile additionally merges browser-observed network traffic into the shared graph.

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
