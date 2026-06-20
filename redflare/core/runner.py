from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from datetime import datetime, timezone

from redflare.modules.base import Module, ModuleContext
from .correlation import correlate
from .models import ModuleResult, Target
from .storage import RunStore


class Runner:
    def __init__(self, store: RunStore, modules: list[Module], context: ModuleContext, workers: int = 2):
        self.store = store
        self.modules = modules
        self.context = context
        self.workers = max(1, workers)

    def run(self, targets: list[Target]) -> tuple[list[ModuleResult], dict]:
        self.store.write_manifest(
            {
                "run_id": self.store.run_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "targets": [asdict(target) for target in targets],
                "modules": [module.name for module in self.modules],
                "authorized_acknowledgement": True,
            }
        )
        results: list[ModuleResult] = []
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            future_map = {
                executor.submit(self._run_target_pipeline, target): target for target in targets
            }
            for future in as_completed(future_map):
                target = future_map[future]
                try:
                    target_results = future.result()
                except Exception as exc:
                    target_results = [ModuleResult(
                        "pipeline",
                        target.url,
                        status="error",
                        errors=[f"{type(exc).__name__}: {exc}"],
                    )]
                for result in target_results:
                    results.append(result)
                    self.store.write_result(result)
        correlated = correlate(self.store.run_id, results)
        for result in correlated:
            results.append(result)
            self.store.write_result(result)
        return results, self.store.finalize(results)

    def _run_target_pipeline(self, target: Target) -> list[ModuleResult]:
        results = []
        for module in self.modules:
            self.context.emit(target.url, module.name, "start", module.description)
            try:
                result = module.run(target, self.context)
            except Exception as exc:
                result = ModuleResult(
                    module.name,
                    target.url,
                    status="error",
                    errors=[f"{type(exc).__name__}: {exc}"],
                )
            kind = "success" if result.status == "completed" else result.status
            message = f"finished in {result.duration_seconds:.2f}s; findings={len(result.findings)}"
            if result.errors:
                message += f"; {result.errors[-1]}"
            self.context.emit(target.url, module.name, kind, message)
            results.append(result)
        return results
