from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import json
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class Target:
    url: str
    host: str
    scheme: str
    port: int

    @property
    def authority(self) -> str:
        default = (self.scheme == "http" and self.port == 80) or (
            self.scheme == "https" and self.port == 443
        )
        return self.host if default else f"{self.host}:{self.port}"


@dataclass
class Finding:
    run_id: str
    target: str
    module: str
    category: str
    title: str
    severity: str
    confidence: float
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=utc_now)
    id: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            evidence = json.dumps(self.evidence, sort_keys=True, default=str)
            material = "\x00".join([self.target, self.module, self.category, self.title, evidence])
            self.id = sha256(material.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ModuleResult:
    module: str
    target: str
    status: str = "completed"
    findings: list[Finding] = field(default_factory=list)
    observations: dict[str, Any] = field(default_factory=dict)
    artifacts: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["findings"] = [finding.to_dict() for finding in self.findings]
        return value
