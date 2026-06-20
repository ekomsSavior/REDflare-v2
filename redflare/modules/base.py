from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from redflare.core.models import ModuleResult, Target


@dataclass
class ModuleContext:
    run_id: str
    artifact_dir: Path
    timeout: float = 8.0
    rate: float = 2.0
    wordlist: str | None = None
    max_paths: int = 100
    allow_public: bool = False
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
