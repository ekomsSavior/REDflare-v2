from __future__ import annotations

from dataclasses import dataclass, field
import re
from threading import RLock
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def canonical_url(url: str) -> str:
    parsed = urlsplit(url)
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, "", ""))


@dataclass
class SurfaceParameter:
    name: str
    location: str = "unknown"
    required: bool = False
    data_type: str = "unknown"
    sources: set[str] = field(default_factory=set)

    def merge(self, *, required: bool, data_type: str, source: str) -> None:
        self.required = self.required or required
        if self.data_type == "unknown" and data_type:
            self.data_type = data_type
        self.sources.add(source)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "location": self.location,
            "required": self.required,
            "data_type": self.data_type,
            "sources": sorted(self.sources),
        }


@dataclass
class SurfaceEndpoint:
    url: str
    observed_requests: set[tuple[str, str]] = field(default_factory=set)
    methods: set[str] = field(default_factory=set)
    content_types: set[str] = field(default_factory=set)
    authentication: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)
    status_codes: set[int] = field(default_factory=set)
    parameters: dict[str, SurfaceParameter] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "observed_urls": sorted({redact_url(value) for _, value in self.observed_requests}),
            "methods": sorted(self.methods),
            "content_types": sorted(self.content_types),
            "authentication": sorted(self.authentication),
            "sources": sorted(self.sources),
            "status_codes": sorted(self.status_codes),
            "parameters": [
                item.to_dict()
                for item in sorted(self.parameters.values(), key=lambda value: (value.location, value.name))
            ],
            "metadata": self.metadata,
        }


class AttackSurfaceGraph:
    """Thread-safe endpoint inventory shared by every module in a run."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._endpoints: dict[str, dict[str, SurfaceEndpoint]] = {}
        self._edges: dict[str, set[tuple[str, str, str]]] = {}
        self._documents: dict[str, list[dict[str, Any]]] = {}

    def add_endpoint(
        self,
        target: str,
        url: str,
        *,
        method: str = "GET",
        source: str,
        content_type: str | None = None,
        authentication: str | None = None,
        status: int | None = None,
        parameters: list[dict[str, Any]] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SurfaceEndpoint:
        normalized = canonical_url(url)
        with self._lock:
            endpoint = self._endpoints.setdefault(target, {}).setdefault(
                normalized, SurfaceEndpoint(normalized)
            )
            endpoint.methods.add(method.upper())
            endpoint.observed_requests.add(
                (method.upper(), urlunsplit((*urlsplit(url)[:4], "")))
            )
            endpoint.sources.add(source)
            if content_type:
                endpoint.content_types.add(content_type.split(";", 1)[0].strip().lower())
            if authentication:
                endpoint.authentication.add(authentication)
            if status is not None:
                endpoint.status_codes.add(int(status))
            for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True):
                self._merge_parameter(endpoint, name, "query", False, "string", source)
            for parameter in parameters or []:
                name = str(parameter.get("name") or "").strip()
                if name:
                    self._merge_parameter(
                        endpoint,
                        name,
                        str(parameter.get("location") or "unknown"),
                        bool(parameter.get("required", False)),
                        str(parameter.get("data_type") or parameter.get("type") or "unknown"),
                        source,
                    )
            if metadata:
                endpoint.metadata.update(metadata)
            return endpoint

    @staticmethod
    def _merge_parameter(
        endpoint: SurfaceEndpoint,
        name: str,
        location: str,
        required: bool,
        data_type: str,
        source: str,
    ) -> None:
        key = f"{location}:{name}"
        parameter = endpoint.parameters.setdefault(key, SurfaceParameter(name, location))
        parameter.merge(required=required, data_type=data_type, source=source)

    def add_edge(self, target: str, source_url: str, destination_url: str, relation: str) -> None:
        with self._lock:
            self._edges.setdefault(target, set()).add(
                (canonical_url(source_url), canonical_url(destination_url), relation)
            )

    def add_document(self, target: str, document: dict[str, Any]) -> None:
        with self._lock:
            documents = self._documents.setdefault(target, [])
            identity = (document.get("kind"), document.get("url"))
            if not any((item.get("kind"), item.get("url")) == identity for item in documents):
                documents.append(document)

    def endpoint_urls(self, target: str) -> list[str]:
        with self._lock:
            return sorted(self._endpoints.get(target, {}))

    def request_urls(self, target: str, method: str = "GET") -> list[str]:
        with self._lock:
            values = {
                observed
                for endpoint in self._endpoints.get(target, {}).values()
                for observed_method, observed in endpoint.observed_requests
                if method.upper() == observed_method
            }
            return sorted(values)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            targets: dict[str, Any] = {}
            for target, endpoints in sorted(self._endpoints.items()):
                edges = [
                    {"source": source, "destination": destination, "relation": relation}
                    for source, destination, relation in sorted(self._edges.get(target, set()))
                ]
                targets[target] = {
                    "endpoints": [endpoints[url].to_dict() for url in sorted(endpoints)],
                    "edges": edges,
                    "documents": list(self._documents.get(target, [])),
                }
            endpoint_count = sum(len(value["endpoints"]) for value in targets.values())
            parameter_count = sum(
                len(endpoint["parameters"])
                for value in targets.values()
                for endpoint in value["endpoints"]
            )
            return {
                "schema_version": "1.0",
                "summary": {
                    "targets": len(targets),
                    "endpoints": endpoint_count,
                    "parameters": parameter_count,
                    "edges": sum(len(value["edges"]) for value in targets.values()),
                    "documents": sum(len(value["documents"]) for value in targets.values()),
                },
                "targets": targets,
            }


def redact_url(url: str) -> str:
    parsed = urlsplit(url)
    sensitive = re.compile(r"(?:token|secret|password|passwd|api[_-]?key|auth|session|jwt)", re.I)
    query = urlencode(
        [
            (name, "<redacted>" if sensitive.search(name) else value)
            for name, value in parse_qsl(parsed.query, keep_blank_values=True)
        ]
    )
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))
