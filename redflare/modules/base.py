from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
from typing import Callable
from typing import Any
from urllib.parse import urlparse

from redflare.core.models import ModuleResult, Target
from redflare.core.surface_graph import AttackSurfaceGraph


@dataclass
class ModuleContext:
    run_id: str
    artifact_dir: Path
    timeout: float = 8.0
    rate: float = 2.0
    wordlist: str | None = None
    max_paths: int = 100
    max_crawl_pages: int = 30
    max_crawl_depth: int = 2
    max_scripts: int = 20
    max_schema_documents: int = 8
    max_exposure_endpoints: int = 75
    max_exposure_findings: int = 100
    max_exposure_body_bytes: int = 2_000_000
    max_cve_products: int = 12
    max_cves_per_product: int = 100
    network_depth: str = "standard"
    network_ports: tuple[int, ...] = ()
    network_addresses: tuple[str, ...] = ()
    network_allowed_networks: tuple[object, ...] = ()
    network_port_include: tuple[int, ...] = ()
    network_port_exclude: tuple[int, ...] = ()
    network_enumeration: bool = False
    network_concurrency: int = 64
    network_timeout: float = 0.75
    continue_after_tls_failure: bool = True
    tls_cipher_enumeration: bool = True
    nvd_api_key_file: str | None = None
    nvd_timeout: float = 20.0
    nvd_retries: int = 3
    graphql_introspection: bool = False
    allow_public: bool = False
    surface_graph: AttackSurfaceGraph = field(default_factory=AttackSurfaceGraph)
    reporter: Callable[[str, str, str, str], None] | None = None
    _unverified_tls_origins: set[tuple[str, int]] = field(default_factory=set, repr=False)
    _transport_lock: RLock = field(default_factory=RLock, repr=False)
    _unverified_evidence_urls: set[str] = field(default_factory=set, repr=False)
    _nvd_cache: dict[str, list[dict[str, Any]]] = field(default_factory=dict, repr=False)
    _nvd_cache_lock: RLock = field(default_factory=RLock, repr=False)

    def emit(self, target: str, module: str, kind: str, message: str) -> None:
        if self.reporter:
            self.reporter(target, module, kind, message)

    def allow_unverified_tls(self, host: str, port: int) -> None:
        with self._transport_lock:
            self._unverified_tls_origins.add((host.lower(), port))

    def tls_verification_required(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            return True
        origin = (parsed.hostname.lower(), parsed.port or 443)
        with self._transport_lock:
            return origin not in self._unverified_tls_origins

    def http_request(self, url: str, *args, **kwargs):
        from redflare.modules.http import request

        kwargs.setdefault("verify_tls", self.tls_verification_required(url))
        if not kwargs["verify_tls"] and "allowed_origin" not in kwargs:
            parsed = urlparse(url)
            kwargs["allowed_origin"] = (parsed.hostname, parsed.port or 443)
        response = request(url, *args, **kwargs)
        if not response.tls_verified:
            with self._transport_lock: self._unverified_evidence_urls.add(response.url)
        return response

    def transport_snapshot(self) -> dict:
        with self._transport_lock:
            return {"controlled_tls_continuation": self.continue_after_tls_failure,
                    "unverified_tls_origins": [f"{host}:{port}" for host, port in sorted(self._unverified_tls_origins)],
                    "evidence_collected_without_trust_validation": sorted(self._unverified_evidence_urls)}

    def cached_nvd_lookup(self, key: str, loader) -> tuple[list[dict[str, Any]], bool]:
        with self._nvd_cache_lock:
            if key in self._nvd_cache:
                return self._nvd_cache[key], True
            value = loader()
            self._nvd_cache[key] = value
            return value, False

    def seed_nvd_cache(self, values: dict[str, list[dict[str, Any]]]) -> None:
        with self._nvd_cache_lock:
            for key, value in values.items():
                if isinstance(value, list): self._nvd_cache.setdefault(key, value)


class Module(ABC):
    name: str
    description: str

    @abstractmethod
    def run(self, target: Target, context: ModuleContext) -> ModuleResult:
        raise NotImplementedError
