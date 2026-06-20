from __future__ import annotations

import random
import string
import time
from pathlib import Path
from urllib.parse import urljoin

from redflare.core.models import Finding, ModuleResult, Target
from .base import Module, ModuleContext
from .http import request


DEFAULT_PATHS = [
    "admin", "login", "dashboard", "api", "api/health", "graphql",
    "swagger", "openapi.json", ".env", "config.json", "metrics", "actuator/health",
]
SENSITIVE = {"admin", "dashboard", ".env", "config.json", "metrics", "graphql", "openapi.json"}


class PathDiscoveryModule(Module):
    name = "path_discovery"
    description = "Rate-limited path discovery with wildcard response filtering"

    def run(self, target: Target, context: ModuleContext) -> ModuleResult:
        started = time.monotonic()
        result = ModuleResult(self.name, target.url)
        paths = load_paths(context.wordlist)[: context.max_paths]
        interval = 1 / context.rate if context.rate > 0 else 0
        try:
            context.emit(target.url, self.name, "progress", f"Loading {len(paths)} paths; rate={context.rate:g}/s")
            random_path = "redflare-" + "".join(random.choice(string.ascii_lowercase) for _ in range(18))
            baseline = request(urljoin(target.url.rstrip("/") + "/", random_path), context.timeout)
            baseline_signature = (baseline.status, len(baseline.body))
            context.emit(target.url, self.name, "info", f"Wildcard baseline: status={baseline.status} bytes={len(baseline.body)}")
            hits = []
            progress_every = max(1, min(25, len(paths) // 10 or 1))
            for index, path in enumerate(paths, start=1):
                if index == 1 or index % progress_every == 0 or index == len(paths):
                    context.emit(target.url, self.name, "progress", f"Probing {index}/{len(paths)}: /{path}")
                if interval:
                    time.sleep(interval)
                url = urljoin(target.url.rstrip("/") + "/", path.lstrip("/"))
                try:
                    response = request(url, context.timeout, max_body=250_000)
                except Exception as exc:
                    result.errors.append(f"{url}: {type(exc).__name__}: {exc}")
                    continue
                signature = (response.status, len(response.body))
                if signature == baseline_signature or response.status == 404:
                    continue
                hit = {"path": path, "url": url, "status": response.status, "bytes": len(response.body)}
                hits.append(hit)
                context.emit(target.url, self.name, "info", f"Response HTTP {response.status}: /{path} ({len(response.body)} bytes)")
                if response.status < 400:
                    severity = "medium" if path in SENSITIVE else "info"
                    result.findings.append(
                        Finding(
                            context.run_id,
                            target.url,
                            self.name,
                            "discovered-path",
                            f"Accessible path discovered: /{path}",
                            severity,
                            0.8,
                            f"The path returned HTTP {response.status} and differed from the wildcard baseline.",
                            hit,
                            ["discovery", "web"],
                        )
                    )
            result.observations.update({"paths_tested": len(paths), "wildcard_signature": baseline_signature, "hits": hits})
        except Exception as exc:
            result.status = "error"
            result.errors.append(f"{type(exc).__name__}: {exc}")
        result.duration_seconds = round(time.monotonic() - started, 4)
        return result


def load_paths(wordlist: str | None) -> list[str]:
    if not wordlist:
        return list(DEFAULT_PATHS)
    lines = Path(wordlist).read_text(encoding="utf-8").splitlines()
    seen = set()
    paths = []
    for line in lines:
        value = line.strip().lstrip("/")
        if value and not value.startswith("#") and value not in seen:
            seen.add(value)
            paths.append(value)
    return paths
