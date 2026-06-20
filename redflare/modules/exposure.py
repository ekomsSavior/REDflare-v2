from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from redflare.core.models import Finding, ModuleResult, Target
from redflare.core.surface_graph import redact_url
from .base import Module, ModuleContext
from .http import request


@dataclass(frozen=True)
class ExposureRule:
    name: str
    pattern: re.Pattern[str]
    severity: str
    value_group: int = 0
    validator: Callable[[str], bool] | None = None


def _not_placeholder(value: str) -> bool:
    lowered = value.lower()
    placeholders = (
        "example", "placeholder", "changeme", "change_me", "your_", "your-",
        "dummy", "sample", "xxxx", "process.env", "undefined", "<redacted>",
    )
    if any(item in lowered for item in placeholders):
        return False
    if len(value) < 12 or len(set(value)) < 6:
        return False
    return _entropy(value) >= 3.0


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for character in value:
        counts[character] = counts.get(character, 0) + 1
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def _valid_labeled_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if address.is_loopback or address.is_link_local or address.is_unspecified or address.is_multicast:
        return False
    documentation = tuple(
        ipaddress.ip_network(item)
        for item in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
    )
    return not any(address in network for network in documentation)


EXPOSURE_RULES = (
    ExposureRule(
        "labeled IP address",
        re.compile(
            r'''(?ix)["']?(?:client[_-]?ip|ip[_-]?address|remote[_-]?addr|origin[_-]?ip|server[_-]?ip|internal[_-]?ip)["']?\s*[:=]\s*["']?((?:\d{1,3}\.){3}\d{1,3})["']?'''
        ),
        "medium",
        1,
        _valid_labeled_ip,
    ),
    ExposureRule("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "critical"),
    ExposureRule("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b"), "critical"),
    ExposureRule("OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"), "critical"),
    ExposureRule("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"), "critical"),
    ExposureRule("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "high"),
    ExposureRule(
        "credentialed service URL",
        re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:'\"]+:[^\s@'\"]+@[^\s'\"]+", re.I),
        "critical",
    ),
    ExposureRule(
        "private key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "critical",
    ),
    ExposureRule(
        "bcrypt password hash",
        re.compile(r"\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}"),
        "high",
    ),
    ExposureRule(
        "Argon2 password hash",
        re.compile(r"\$argon2(?:id|i|d)\$v=\d+\$[^\s'\"]+"),
        "high",
    ),
    ExposureRule(
        "PBKDF2 password hash",
        re.compile(r"\bpbkdf2_(?:sha256|sha1)\$\d+\$[^\s$'\"]+\$[^\s'\"]+", re.I),
        "high",
    ),
    ExposureRule(
        "password hash",
        re.compile(
            r'''(?ix)["']?(?:password[_-]?hash|passwd[_-]?hash|pwd[_-]?hash)["']?\s*[:=]\s*["']([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})["']'''
        ),
        "high",
        1,
    ),
    ExposureRule(
        "embedded secret assignment",
        re.compile(
            r'''(?ix)["']?(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|database[_-]?url|encryption[_-]?key|password|passwd|secret)["']?\s*[:=]\s*["']([^"'\r\n]{12,512})["']'''
        ),
        "high",
        1,
        _not_placeholder,
    ),
)

IPV4_CANDIDATE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(value) for value in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
TEXT_TYPES = ("text/", "javascript", "json", "xml", "yaml", "graphql")


class SensitiveExposureModule(Module):
    name = "sensitive_exposure"
    description = "Inspect in-scope HTML, JavaScript, and GET responses for exposed secrets and sensitive data"

    def run(self, target: Target, context: ModuleContext) -> ModuleResult:
        started = time.monotonic()
        result = ModuleResult(self.name, target.url)
        endpoints = self._candidate_endpoints(target, context)
        evidence: list[dict] = []
        seen: set[tuple[str, str]] = set()
        scanned = 0

        for endpoint in endpoints[: context.max_exposure_endpoints]:
            if len(evidence) >= context.max_exposure_findings:
                break
            context.emit(target.url, self.name, "progress", f"Inspecting {endpoint}")
            try:
                response = request(
                    endpoint,
                    context.timeout,
                    max_body=context.max_exposure_body_bytes,
                    allowed_origin=(target.host, target.port),
                )
            except Exception as exc:
                result.errors.append(f"{endpoint}: {type(exc).__name__}: {exc}")
                continue
            content_type = response.headers.get("content-type", "").lower()
            if not self._is_text(content_type, response.body):
                continue
            scanned += 1
            text = response.body.decode("utf-8", errors="replace")
            for match in self.detect(text, response.url):
                key = (match["url"], match["fingerprint"])
                if key in seen:
                    continue
                seen.add(key)
                evidence.append(match)
                context.emit(
                    target.url,
                    self.name,
                    "finding",
                    f"{match['type']} exposed at {match['url']}:{match['line']} — {match['value_preview']}",
                )
                result.findings.append(self._finding(context, target, match))
                if len(evidence) >= context.max_exposure_findings:
                    break

        artifact = self._write_artifact(target, context, evidence, scanned, len(endpoints))
        result.artifacts.append(str(artifact))
        result.observations.update(
            {
                "candidate_endpoints": len(endpoints),
                "responses_scanned": scanned,
                "exposures_found": len(evidence),
                "evidence_policy": "Sensitive values are masked; SHA-256 fingerprints support verification and deduplication.",
            }
        )
        result.duration_seconds = round(time.monotonic() - started, 4)
        return result

    @staticmethod
    def _candidate_endpoints(target: Target, context: ModuleContext) -> list[str]:
        values = {target.url}
        for url in context.surface_graph.request_urls(target.url, "GET"):
            if "{" not in url and SensitiveExposureModule._same_origin(target, url):
                values.add(url)
        return sorted(values, key=lambda value: (value != target.url, value))

    @staticmethod
    def _same_origin(target: Target, url: str) -> bool:
        parsed = urlparse(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return parsed.scheme in {"http", "https"} and parsed.hostname == target.host and port == target.port

    @staticmethod
    def _is_text(content_type: str, body: bytes) -> bool:
        if any(marker in content_type for marker in TEXT_TYPES):
            return True
        sample = body[:2000]
        return bool(sample) and b"\x00" not in sample and sum(32 <= byte < 127 or byte in b"\r\n\t" for byte in sample) / len(sample) > 0.8

    @classmethod
    def detect(cls, text: str, url: str) -> list[dict]:
        matches: list[dict] = []
        for rule in EXPOSURE_RULES:
            for found in rule.pattern.finditer(text):
                value = found.group(rule.value_group)
                if rule.validator and not rule.validator(value):
                    continue
                matches.append(cls._evidence(text, url, rule.name, rule.severity, value, found.start(rule.value_group)))
        for found in IPV4_CANDIDATE.finditer(text):
            value = found.group(0)
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if not address.is_private or address.is_loopback or address.is_link_local or address.is_unspecified:
                continue
            if any(address in network for network in DOCUMENTATION_NETWORKS):
                continue
            matches.append(cls._evidence(text, url, "private/internal IP address", "medium", value, found.start()))
        return matches

    @staticmethod
    def _evidence(text: str, url: str, kind: str, severity: str, value: str, offset: int) -> dict:
        line = text.count("\n", 0, offset) + 1
        line_start = text.rfind("\n", 0, offset) + 1
        line_end = text.find("\n", offset)
        if line_end < 0:
            line_end = len(text)
        preview = mask_value(value, kind)
        context = redact_line(text[line_start:line_end].strip())
        fingerprint = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]
        return {
            "type": kind,
            "severity": severity,
            "url": redact_url(url),
            "line": line,
            "value_preview": preview,
            "fingerprint": f"sha256:{fingerprint}",
            "context": context[:320],
        }

    @staticmethod
    def _finding(context: ModuleContext, target: Target, evidence: dict) -> Finding:
        return Finding(
            context.run_id,
            target.url,
            SensitiveExposureModule.name,
            "sensitive-data-exposure",
            f"Potential {evidence['type']} exposed in a web response",
            evidence["severity"],
            0.9 if evidence["severity"] in {"critical", "high"} else 0.75,
            "An in-scope response exposed data matching a sensitive-data signature. Verify intent and revoke or rotate credentials when applicable.",
            evidence,
            ["information-disclosure", "secrets", "web-response"],
            remediation="Remove sensitive values from client-accessible responses and bundles, rotate exposed credentials, and enforce server-side authorization and response filtering.",
        )

    @staticmethod
    def _write_artifact(
        target: Target, context: ModuleContext, evidence: list[dict], scanned: int, candidates: int
    ) -> Path:
        directory = context.artifact_dir / SensitiveExposureModule.name / target.host
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "exposures.json"
        path.write_text(
            json.dumps(
                {
                    "target": target.url,
                    "candidate_endpoints": candidates,
                    "responses_scanned": scanned,
                    "exposures": evidence,
                    "values_masked": True,
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        return path


def mask_value(value: str, kind: str) -> str:
    if "IP address" in kind:
        return value
    if "private key" in kind.lower():
        return value
    if len(value) <= 10:
        return "***MASKED***"
    visible = 6 if "hash" in kind.lower() else 4
    return f"{value[:visible]}…{value[-visible:]}"


def redact_line(line: str) -> str:
    replacements: dict[str, str] = {}
    for rule in EXPOSURE_RULES:
        for found in rule.pattern.finditer(line):
            value = found.group(rule.value_group)
            if rule.validator and not rule.validator(value):
                continue
            replacements[value] = mask_value(value, rule.name)
    for value in sorted(replacements, key=len, reverse=True):
        line = line.replace(value, replacements[value])
    return line[:320]
