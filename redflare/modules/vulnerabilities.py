from __future__ import annotations

import json
import os
import re
import socket
import stat
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

from redflare.core.models import Finding, ModuleResult, Target

from .base import Module, ModuleContext
from .http import request


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DETAIL = "https://nvd.nist.gov/vuln/detail/"
CVE_DETAIL = "https://www.cve.org/CVERecord?id="
_NVD_LOCK = threading.Lock()
_LAST_NVD_REQUEST = 0.0


@dataclass(frozen=True)
class Fingerprint:
    product: str
    version: str
    vendor: str
    cpe_product: str
    source: str
    evidence: str

    @property
    def cpe(self) -> str:
        version = urllib.parse.quote(self.version, safe="._-")
        return f"cpe:2.3:a:{self.vendor}:{self.cpe_product}:{version}:*:*:*:*:*:*:*"


PRODUCTS = {
    "apache": ("Apache HTTP Server", "apache", "http_server"),
    "nginx": ("nginx", "f5", "nginx"),
    "openresty": ("OpenResty", "openresty", "openresty"),
    "microsoft-iis": ("Microsoft IIS", "microsoft", "internet_information_services"),
    "php": ("PHP", "php", "php"),
    "jquery": ("jQuery", "jquery", "jquery"),
    "bootstrap": ("Bootstrap", "getbootstrap", "bootstrap"),
    "wordpress": ("WordPress", "wordpress", "wordpress"),
    "drupal": ("Drupal", "drupal", "drupal"),
    "joomla": ("Joomla", "joomla", r"joomla\!"),
    "openssh": ("OpenSSH", "openbsd", "openssh"),
    "mysql": ("MySQL", "oracle", "mysql"),
    "postgresql": ("PostgreSQL", "postgresql", "postgresql"),
    "redis": ("Redis", "redis", "redis"),
    "mongodb": ("MongoDB", "mongodb", "mongodb"),
    "microsoft sql server": ("Microsoft SQL Server", "microsoft", "sql_server"),
}

HEADER_PATTERNS = (
    ("server", re.compile(r"\b(Apache|nginx|openresty|Microsoft-IIS)/([0-9][0-9A-Za-z._-]*)", re.I)),
    ("x-powered-by", re.compile(r"\b(PHP)/([0-9][0-9A-Za-z._-]*)", re.I)),
)
BODY_PATTERNS = (
    ("html-generator", re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']\s*(WordPress|Drupal|Joomla!?)\s+([0-9][0-9A-Za-z._-]*)', re.I)),
    ("html-generator", re.compile(r'<meta[^>]+content=["\']\s*(WordPress|Drupal|Joomla!?)\s+([0-9][0-9A-Za-z._-]*)["\'][^>]+name=["\']generator["\']', re.I)),
    ("asset-url", re.compile(r"(?:jquery)[-.]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js", re.I)),
    ("asset-url", re.compile(r"(?:bootstrap)[-.]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.(?:js|css)", re.I)),
)


def fingerprint_response(headers: dict[str, str], body: bytes) -> list[Fingerprint]:
    found: dict[tuple[str, str], Fingerprint] = {}
    for header, pattern in HEADER_PATTERNS:
        value = headers.get(header, "")
        for match in pattern.finditer(value):
            key = match.group(1).lower()
            _add_fingerprint(found, key, match.group(2), f"header:{header}", match.group(0))

    text = body.decode("utf-8", errors="replace")
    for source, pattern in BODY_PATTERNS:
        for match in pattern.finditer(text):
            if pattern.groups == 2:
                key, version = match.group(1).lower().rstrip("!"), match.group(2)
            else:
                key = "jquery" if "jquery" in match.group(0).lower() else "bootstrap"
                version = match.group(1)
            _add_fingerprint(found, key, version, source, match.group(0)[:180])
    return sorted(found.values(), key=lambda item: (item.product.lower(), item.version))


def _add_fingerprint(found: dict[tuple[str, str], Fingerprint], key: str, version: str, source: str, evidence: str) -> None:
    definition = PRODUCTS.get(key)
    if not definition or not re.fullmatch(r"[0-9][0-9A-Za-z._-]{0,63}", version):
        return
    product, vendor, cpe_product = definition
    found.setdefault((product, version), Fingerprint(product, version, vendor, cpe_product, source, evidence))


class NVDLookupError(RuntimeError):
    pass


def load_nvd_api_key(path: str | None = None) -> str:
    value = os.environ.get("NVD_API_KEY", "").strip()
    if value or not path:
        return value
    key_path = Path(path).expanduser()
    mode = stat.S_IMODE(key_path.stat().st_mode)
    if mode & 0o077:
        raise PermissionError(f"NVD API key file must not be group/world accessible: {key_path}")
    return key_path.read_text(encoding="utf-8").strip()


def query_nvd(fingerprint: Fingerprint, timeout: float, limit: int, *, api_key: str = "", retries: int = 3) -> list[dict[str, Any]]:
    query = urllib.parse.urlencode({"virtualMatchString": fingerprint.cpe, "resultsPerPage": min(limit, 100)} )
    headers = {"User-Agent": "REDflare-v2/2.1 authorized-assessment"}
    api_key = api_key or os.environ.get("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key
    req = urllib.request.Request(f"{NVD_API}?{query}", headers=headers)
    retryable = {429, 500, 502, 503, 504}; last_error = None
    for attempt in range(max(0, retries) + 1):
        try:
            global _LAST_NVD_REQUEST
            with _NVD_LOCK:
                delay = 0.7 if api_key else 6.1
                wait = delay - (time.monotonic() - _LAST_NVD_REQUEST)
                if wait > 0: time.sleep(wait)
                with urllib.request.urlopen(req, timeout=timeout) as response: payload = json.load(response)
                _LAST_NVD_REQUEST = time.monotonic()
            return [item.get("cve", {}) for item in payload.get("vulnerabilities", [])[:limit] if item.get("cve")]
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code not in retryable or attempt >= retries: break
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            time.sleep(retry_delay(retry_after, attempt))
        except (TimeoutError, socket.timeout, urllib.error.URLError) as exc:
            last_error = exc
            if attempt >= retries: break
            time.sleep(min(2 ** attempt, 30))
    raise NVDLookupError(f"NVD unavailable after {max(0, retries) + 1} attempt(s): {type(last_error).__name__}: {last_error}")


def retry_delay(value: str | None, attempt: int) -> float:
    if value:
        try: return min(60.0, max(0.0, float(value)))
        except ValueError:
            try:
                delay = (parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds()
                return min(60.0, max(0.0, delay))
            except (TypeError, ValueError): pass
    return min(2 ** attempt, 30)


def _english_description(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions") or []
    return next((item.get("value", "") for item in descriptions if item.get("lang") == "en"), "No English NVD description available.")


def _cvss(cve: dict[str, Any]) -> tuple[float | None, str, str]:
    metrics = cve.get("metrics") or {}
    for family in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(family) or []
        if not values:
            continue
        data = values[0].get("cvssData") or {}
        score = data.get("baseScore")
        severity = str(data.get("baseSeverity") or values[0].get("baseSeverity") or "unknown").lower()
        return (float(score) if score is not None else None, severity, str(data.get("vectorString") or ""))
    return None, "unknown", ""


def _severity(value: str, score: float | None) -> str:
    if value in {"critical", "high", "medium", "low"}:
        return value
    if score is None:
        return "info"
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"


def _references(cve: dict[str, Any], cve_id: str) -> list[str]:
    preferred = [str(item.get("url")) for item in cve.get("references") or [] if item.get("url")]
    return list(dict.fromkeys([f"{NVD_DETAIL}{cve_id}", f"{CVE_DETAIL}{cve_id}", *preferred]))[:12]


class CVEIntelligenceModule(Module):
    name = "cve_intelligence"
    description = "Fingerprint disclosed component versions and correlate exact CPEs with NVD CVE records"

    def run(self, target: Target, context: ModuleContext) -> ModuleResult:
        started = time.monotonic()
        result = ModuleResult(self.name, target.url)
        try:
            context.emit(target.url, self.name, "progress", "Fingerprinting disclosed component versions")
            response = context.http_request(target.url, context.timeout, method="GET", max_body=1_000_000)
            fingerprints = fingerprint_response(response.headers, response.body)
            mapped_urls = context.surface_graph.request_urls(target.url, "GET")
            fingerprints.extend(fingerprint_response({}, "\n".join(mapped_urls).encode()))
            network = (context.surface_graph.snapshot().get("targets", {}).get(target.url, {}).get("network_hosts", []))
            for host in network:
                for service in host.get("services", []):
                    product = str(service.get("product") or "").strip(); version = str(service.get("version") or "").strip()
                    key = product.lower()
                    if key in PRODUCTS and version:
                        canonical, vendor, cpe_product = PRODUCTS[key]
                        fingerprints.append(Fingerprint(canonical, version, vendor, cpe_product, "network-service",
                                                        str(service.get("banner") or service.get("evidence") or "protocol identification")[:180]))
            fingerprints = list({(item.product, item.version): item for item in fingerprints}.values())
            fingerprints.sort(key=lambda item: (item.product.lower(), item.version))
            fingerprints = fingerprints[: context.max_cve_products]
            result.observations["fingerprints"] = [item.__dict__ | {"cpe": item.cpe} for item in fingerprints]
            result.observations["source"] = "NVD CVE API 2.0"
            api_key = load_nvd_api_key(context.nvd_api_key_file)
            result.observations["nvd_api_key_configured"] = bool(api_key)
            directory = context.artifact_dir / self.name / target.host
            directory.mkdir(parents=True, exist_ok=True)
            cache_path = directory / "nvd_cache.json"
            try: cache = json.loads(cache_path.read_text(encoding="utf-8")) if cache_path.exists() else {}
            except (OSError, json.JSONDecodeError): cache = {}
            context.seed_nvd_cache(cache)
            coverage = []
            if not fingerprints:
                context.emit(target.url, self.name, "info", "No exact component versions were disclosed; CVE correlation skipped")
            for fingerprint in fingerprints:
                context.emit(target.url, self.name, "progress", f"Checking {fingerprint.product} {fingerprint.version} against NVD")
                try:
                    records, cached = context.cached_nvd_lookup(
                        fingerprint.cpe,
                        lambda: query_nvd(fingerprint, context.nvd_timeout, context.max_cves_per_product,
                                          api_key=api_key, retries=context.nvd_retries),
                    )
                    cache[fingerprint.cpe] = records; source = "run-cache" if cached else "nvd"
                    coverage.append({"product": fingerprint.product, "version": fingerprint.version, "status": "complete", "source": source})
                except Exception as exc:
                    result.errors.append(f"NVD lookup failed for {fingerprint.product} {fingerprint.version}: {type(exc).__name__}: {exc}")
                    coverage.append({"product": fingerprint.product, "version": fingerprint.version, "status": "unavailable", "error": str(exc)})
                    context.emit(target.url, self.name, "error", result.errors[-1])
                    continue
                for cve in records:
                    cve_id = str(cve.get("id") or "")
                    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id) or str(cve.get("vulnStatus")).lower() == "rejected":
                        continue
                    score, cvss_severity, vector = _cvss(cve)
                    severity = _severity(cvss_severity, score)
                    known_exploited = bool(cve.get("cisaExploitAdd"))
                    if known_exploited and severity in {"info", "low", "medium"}:
                        severity = "high"
                    links = _references(cve, cve_id)
                    evidence = {
                        "cve": cve_id,
                        "product": fingerprint.product,
                        "version": fingerprint.version,
                        "detected_by": fingerprint.source,
                        "fingerprint_evidence": fingerprint.evidence,
                        "matched_cpe": fingerprint.cpe,
                        "cvss_score": score,
                        "cvss_vector": vector,
                        "published": cve.get("published"),
                        "last_modified": cve.get("lastModified"),
                        "references": links,
                        "nvd_status": cve.get("vulnStatus"),
                        "cisa_known_exploited": known_exploited,
                        "cisa_kev_added": cve.get("cisaExploitAdd"),
                        "cisa_action_due": cve.get("cisaActionDue"),
                        "cisa_required_action": cve.get("cisaRequiredAction"),
                    }
                    finding = Finding(
                        context.run_id, target.url, self.name, "known-vulnerable-component",
                        f"{cve_id} affects disclosed {fingerprint.product} {fingerprint.version}",
                        severity, 0.9, _english_description(cve), evidence,
                        ["cve", "component", "known-vulnerability", fingerprint.product.lower().replace(" ", "-")],
                        remediation="Confirm the component inventory, review the vendor advisory, and upgrade to a non-affected supported release.",
                    )
                    finding.standards["CVE"] = [{"id": cve_id, "url": links[0], "version": str(cve.get("published") or "")[:4]}]
                    result.findings.append(finding)
                    context.emit(target.url, self.name, "finding", f"{cve_id} | {severity.upper()} | {fingerprint.product} {fingerprint.version}")
            cache_path.write_text(json.dumps(cache, indent=2, sort_keys=True), encoding="utf-8")
            result.artifacts.append(str(cache_path))
            complete = sum(item["status"] == "complete" for item in coverage)
            result.observations["coverage"] = coverage
            result.observations["coverage_status"] = ("not_applicable" if not fingerprints else "complete" if complete == len(fingerprints)
                                                      else "partial" if complete else "unavailable")
            result.observations["cves_found"] = len(result.findings)
        except Exception as exc:
            result.status = "error"
            result.errors.append(f"{type(exc).__name__}: {exc}")
        result.duration_seconds = round(time.monotonic() - started, 4)
        return result
