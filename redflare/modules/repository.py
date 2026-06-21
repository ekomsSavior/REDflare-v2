from __future__ import annotations

import base64
import json
import os
import urllib.parse
import urllib.request
from pathlib import Path

from .exposure import SensitiveExposureModule

SKIP_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".woff", ".ico", ".lock")


def normalize_repository(value: str) -> str:
    value = value.strip().removesuffix(".git")
    parsed = urllib.parse.urlsplit(value if "://" in value else "https://github.com/" + value)
    parts = [part for part in parsed.path.split("/") if part]
    if parsed.hostname != "github.com" or len(parts) != 2:
        raise ValueError(f"invalid GitHub repository {value!r}; expected owner/repository or GitHub URL")
    return f"{parts[0]}/{parts[1]}"


def _github(path: str, token: str, timeout: int) -> dict:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "REDflare-v2/native-repository-intelligence",
               "X-GitHub-Api-Version": "2022-11-28", "Authorization": f"Bearer {token}"}
    with urllib.request.urlopen(urllib.request.Request("https://api.github.com" + path, headers=headers), timeout=timeout) as response:
        return json.load(response)


def run_repository_intelligence(repositories: list[str], output: Path, timeout: int = 60) -> dict:
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token:
        return {"status": "error", "error": "GITHUB_TOKEN is required for native repository intelligence"}
    output.mkdir(parents=True, exist_ok=True); findings = []; scanned = 0; errors = []
    for raw in repositories:
        try:
            repo = normalize_repository(raw); metadata = _github(f"/repos/{repo}", token, timeout)
            branch = metadata.get("default_branch") or "main"
            tree = _github(f"/repos/{repo}/git/trees/{urllib.parse.quote(branch, safe='')}?recursive=1", token, timeout)
            if tree.get("truncated"): raise RuntimeError("repository tree truncated; refusing incomplete scan")
            for entry in tree.get("tree", []):
                path = str(entry.get("path") or "")
                if entry.get("type") != "blob" or path.lower().endswith(SKIP_SUFFIXES) or int(entry.get("size") or 0) > 1_000_000: continue
                blob = _github(f"/repos/{repo}/git/blobs/{entry['sha']}", token, timeout)
                if blob.get("encoding") != "base64": continue
                text = base64.b64decode(blob.get("content", "")).decode("utf-8", errors="replace"); scanned += 1
                url = f"https://github.com/{repo}/blob/{branch}/{path}"
                for evidence in SensitiveExposureModule.detect(text, url):
                    findings.append({"repository": repo, "branch": branch, "path": path, **evidence})
        except Exception as exc:
            errors.append(f"{raw}: {type(exc).__name__}: {exc}")
    artifact = output / "repository_findings.json"
    artifact.write_text(json.dumps({"findings": findings, "values_masked": True}, indent=2), encoding="utf-8")
    return {"status": "completed" if not errors else "error", "engine": "native-redflare", "repositories": len(repositories),
            "files_scanned": scanned, "findings": len(findings), "errors": errors, "output": str(artifact)}
