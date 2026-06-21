from __future__ import annotations

import hashlib
import json
import mimetypes
import threading
import webbrowser
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit


def _stable_id(kind: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]
    return f"{kind}:{digest}"


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    values = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            values.append(value)
    return values


def _canonical_url(value: str) -> str:
    parsed = urlsplit(value)
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path or '/'}"


def resolve_run_directory(value: str | Path) -> Path:
    raw = str(value).strip().strip('"\'')
    parsed = urlsplit(raw)
    if parsed.scheme == "file":
        if parsed.netloc not in {"", "localhost"}:
            raise ValueError("remote file URLs are not supported; use a local run directory")
        raw = unquote(parsed.path)
    return Path(raw).expanduser().resolve()


def build_visual_graph(run_directory: str | Path) -> dict[str, Any]:
    root = resolve_run_directory(run_directory)
    if not root.is_dir():
        raise ValueError(f"run directory does not exist: {root}")
    if not (root / "attack_surface.json").exists() and not (root / "findings.jsonl").exists():
        raise ValueError(f"not a REDflare run directory: {root}")
    surface = _read_json(root / "attack_surface.json", {"targets": {}, "summary": {}})
    findings = _read_jsonl(root / "findings.jsonl")
    module_results = [
        value
        for path in sorted((root / "modules").glob("*.json"))
        if isinstance((value := _read_json(path, {})), dict) and value
    ] if (root / "modules").is_dir() else []
    summary = _read_json(root / "summary.json", {})
    manifest = _read_json(root / "manifest.json", {})

    run_id = str(summary.get("run_id") or manifest.get("run_id") or root.name)
    run_node_id = _stable_id("run", run_id)
    nodes: dict[str, dict[str, Any]] = {
        run_node_id: {
            "id": run_node_id,
            "label": run_id,
            "type": "run",
            "info": {"run_directory": str(root), "summary": summary},
        }
    }
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    target_ids: dict[str, str] = {}
    endpoint_ids: dict[tuple[str, str], str] = {}
    module_ids: dict[tuple[str, str], str] = {}

    def add_node(node: dict[str, Any]) -> str:
        nodes.setdefault(node["id"], node)
        return node["id"]

    def add_edge(source: str, target: str, relation: str, label: str = "") -> None:
        if source not in nodes or target not in nodes:
            return
        key = (source, target, relation)
        edges.setdefault(
            key,
            {"id": _stable_id("edge", "\x00".join(key)), "source": source, "target": target, "type": relation, "label": label},
        )

    for target, data in sorted((surface.get("targets") or {}).items()):
        target_id = add_node(
            {
                "id": _stable_id("target", target),
                "label": urlsplit(target).netloc or target,
                "type": "target",
                "info": {"url": target},
            }
        )
        target_ids[target] = target_id
        add_edge(run_node_id, target_id, "contains")

        for endpoint in data.get("endpoints", []):
            url = str(endpoint.get("url") or "")
            if not url:
                continue
            endpoint_id = add_node(
                {
                    "id": _stable_id("endpoint", target + "\x00" + url),
                    "label": urlsplit(url).path or "/",
                    "type": "endpoint",
                    "info": endpoint,
                }
            )
            endpoint_ids[(target, _canonical_url(url))] = endpoint_id
            add_edge(target_id, endpoint_id, "serves")
            for parameter in endpoint.get("parameters", []):
                name = str(parameter.get("name") or "parameter")
                location = str(parameter.get("location") or "unknown")
                parameter_id = add_node(
                    {
                        "id": _stable_id("parameter", endpoint_id + "\x00" + location + "\x00" + name),
                        "label": name,
                        "type": "parameter",
                        "info": parameter,
                    }
                )
                add_edge(endpoint_id, parameter_id, "accepts", location)

        for document in data.get("documents", []):
            identity = json.dumps(document, sort_keys=True, default=str)
            document_id = add_node(
                {
                    "id": _stable_id("document", target + "\x00" + identity),
                    "label": str(document.get("title") or document.get("kind") or "schema"),
                    "type": "document",
                    "info": document,
                }
            )
            add_edge(target_id, document_id, "documents")

        for edge in data.get("edges", []):
            source = endpoint_ids.get((target, _canonical_url(str(edge.get("source") or ""))))
            destination = endpoint_ids.get((target, _canonical_url(str(edge.get("destination") or ""))))
            if source and destination:
                add_edge(source, destination, str(edge.get("relation") or "links"))

    for result in module_results:
        target = str(result.get("target") or "")
        module = str(result.get("module") or "module")
        module_id = add_node(
            {
                "id": _stable_id("module", target + "\x00" + module),
                "label": module.replace("_", " "),
                "type": "module",
                "info": result,
            }
        )
        module_ids[(target, module)] = module_id
        add_edge(target_ids.get(target, run_node_id), module_id, "executed")

    standard_nodes: dict[tuple[str, str], str] = {}
    for finding in findings:
        target = str(finding.get("target") or "")
        target_id = target_ids.get(target, run_node_id)
        category = str(finding.get("category") or "finding")
        node_type = "exposure" if category == "sensitive-data-exposure" else "finding"
        raw_finding_id = str(finding.get("id") or hashlib.sha256(json.dumps(finding, sort_keys=True).encode()).hexdigest()[:16])
        finding_id = add_node(
            {
                "id": "finding:" + raw_finding_id,
                "label": str(finding.get("title") or category),
                "type": node_type,
                "severity": str(finding.get("severity") or "info").lower(),
                "info": finding,
            }
        )
        evidence_url = str((finding.get("evidence") or {}).get("url") or "")
        endpoint_id = endpoint_ids.get((target, _canonical_url(evidence_url))) if evidence_url else None
        add_edge(endpoint_id or target_id, finding_id, "exposes" if node_type == "exposure" else "has_finding")
        module_id = module_ids.get((target, str(finding.get("module") or "")))
        if module_id:
            add_edge(module_id, finding_id, "reported")

        for family, references in (finding.get("standards") or {}).items():
            for reference in references or []:
                identifier = str(reference.get("id") or "")
                if not identifier:
                    continue
                key = (family, identifier)
                standard_id = standard_nodes.get(key)
                if not standard_id:
                    standard_id = add_node(
                        {
                            "id": _stable_id("standard", family + "\x00" + identifier),
                            "label": identifier,
                            "type": "cve" if family == "CVE" else "standard",
                            "info": {"family": family, **reference},
                        }
                    )
                    standard_nodes[key] = standard_id
                add_edge(finding_id, standard_id, "maps_to", family)

    node_list = list(nodes.values())
    edge_list = list(edges.values())
    type_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}
    for node in node_list:
        type_counts[node["type"]] = type_counts.get(node["type"], 0) + 1
        if node.get("severity"):
            severity = node["severity"]
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
    return {
        "schema_version": "1.0",
        "metadata": {
            "run_id": run_id,
            "run_directory": str(root),
            "nodes": len(node_list),
            "edges": len(edge_list),
            "type_counts": dict(sorted(type_counts.items())),
            "severity_counts": dict(sorted(severity_counts.items())),
        },
        "nodes": node_list,
        "edges": edge_list,
    }


@dataclass
class VisualServer:
    run_directory: str | Path
    port: int = 8765

    def __post_init__(self) -> None:
        self.run_directory = resolve_run_directory(self.run_directory)
        self.graph = build_visual_graph(self.run_directory)
        self.assets = files("redflare.web")
        handler = self._handler()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", self.port), handler)
        self.port = int(self.httpd.server_address[1])

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/"

    def _handler(self):
        graph = json.dumps(self.graph).encode("utf-8")
        assets = self.assets

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                path = self.path.split("?", 1)[0]
                if path == "/api/graph":
                    return self._send(graph, "application/json; charset=utf-8")
                asset_name = "index.html" if path == "/" else path.lstrip("/")
                if asset_name not in {"index.html", "app.js", "styles.css"}:
                    self.send_error(404)
                    return
                resource = assets.joinpath(asset_name)
                try:
                    data = resource.read_bytes()
                except (FileNotFoundError, OSError):
                    self.send_error(404)
                    return
                content_type = mimetypes.guess_type(asset_name)[0] or "application/octet-stream"
                self._send(data, content_type + ("; charset=utf-8" if content_type.startswith("text/") or content_type.endswith("javascript") else ""))

            def _send(self, data: bytes, content_type: str) -> None:
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *_args) -> None:
                return

        return Handler

    def serve(self, *, open_browser: bool = True) -> None:
        print(f"REDflare visual console: {self.url}")
        print(f"Run: {self.run_directory}")
        print("Press Ctrl+C to stop.")
        if open_browser:
            threading.Timer(0.2, lambda: webbrowser.open(self.url)).start()
        try:
            self.httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            self.httpd.server_close()
