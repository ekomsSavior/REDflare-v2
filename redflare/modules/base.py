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
