from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

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
    graphql_introspection: bool = False
    allow_public: bool = False
    surface_graph: AttackSurfaceGraph = field(default_factory=AttackSurfaceGraph)
    reporter: Callable[[str, str, str, str], None] | None = None

    def emit(self, target: str, module: str, kind: str, message: str) -> None:
        if self.reporter:
            self.reporter(target, module, kind, message)


class Module(ABC):
    name: str
    description: str

    @abstractmethod
    def run(self, target: Target, context: ModuleContext) -> ModuleResult:
        raise NotImplementedError
