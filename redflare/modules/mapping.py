from __future__ import annotations

import json
import re
import time
from collections import deque
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

from redflare.core.models import Finding, ModuleResult, Target
from .base import Module, ModuleContext
from .http import request


OPENAPI_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/v3/api-docs",
)
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}
ROUTE_LITERAL = re.compile(r"[\"']((?:https?://[^\"']+)|(?:/[A-Za-z0-9_~!$&'()*+,;=:@%./?{}-]{2,}))['\"]")
FETCH_CALL = re.compile(r"fetch\s*\(\s*[\"']([^\"']+)[\"']", re.I)
AXIOS_CALL = re.compile(r"axios\.(get|post|put|patch|delete)\s*\(\s*[\"']([^\"']+)[\"']", re.I)


class MappingParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag in {"a", "area"} and values.get("href"):
            self.links.append(urljoin(self.base_url, values["href"] or ""))
        elif tag == "script" and values.get("src"):
            self.scripts.append(urljoin(self.base_url, values["src"] or ""))
        elif tag == "form":
            self._form = {
                "url": urljoin(self.base_url, values.get("action") or self.base_url),
                "method": (values.get("method") or "GET").upper(),
                "content_type": values.get("enctype") or "application/x-www-form-urlencoded",
                "parameters": [],
            }
            self.forms.append(self._form)
        elif tag in {"input", "select", "textarea", "button"} and self._form is not None:
            name = values.get("name")
            if name:
                self._form["parameters"].append(
                    {
                        "name": name,
                        "location": "query" if self._form["method"] == "GET" else "body",
                        "required": "required" in values,
                        "data_type": values.get("type") or tag,
                    }
                )

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None


class ApplicationMappingModule(Module):
    name = "application_mapping"
    description = "Build a shared endpoint graph from pages, forms, JavaScript, API schemas, and optional GraphQL metadata"

    def run(self, target: Target, context: ModuleContext) -> ModuleResult:
        started = time.monotonic()
        result = ModuleResult(self.name, target.url)
        pages_visited: list[str] = []
        scripts_seen: set[str] = set()
        schema_candidates = {urljoin(target.url.rstrip("/") + "/", path.lstrip("/")) for path in OPENAPI_PATHS}
        queue = deque([(target.url, 0, "seed")])
        queued = {target.url}

        try:
            while queue and len(pages_visited) < context.max_crawl_pages:
                page_url, depth, source = queue.popleft()
                if not self._same_origin(target, page_url):
                    continue
                context.emit(target.url, self.name, "progress", f"Mapping {page_url}")
                try:
                    response = request(
                        page_url,
                        context.timeout,
                        max_body=1_000_000,
                        allowed_origin=(target.host, target.port),
                    )
                except Exception as exc:
                    result.errors.append(f"{page_url}: {type(exc).__name__}: {exc}")
                    continue
                pages_visited.append(page_url)
                content_type = response.headers.get("content-type", "")
                context.surface_graph.add_endpoint(
                    target.url,
                    response.url,
                    method="GET",
                    source=source,
                    content_type=content_type,
                    status=response.status,
                )
                if not self._same_origin(target, response.url):
                    continue
                if "json" in content_type and self._looks_like_schema(response.body):
                    schema_candidates.add(response.url)
                if "html" not in content_type and b"<html" not in response.body[:1000].lower():
                    continue

                parser = MappingParser(response.url)
                parser.feed(response.body.decode("utf-8", errors="replace"))
                for form in parser.forms:
                    if not self._same_origin(target, form["url"]):
                        continue
                    context.surface_graph.add_endpoint(
                        target.url,
                        form["url"],
                        method=form["method"],
                        source="html-form",
                        content_type=form["content_type"],
                        authentication="credential-form" if any(
                            item["data_type"] == "password" for item in form["parameters"]
                        ) else "unknown",
                        parameters=form["parameters"],
                    )
                    context.surface_graph.add_edge(target.url, response.url, form["url"], "form")
                for link in parser.links:
                    if not self._same_origin(target, link):
                        continue
                    context.surface_graph.add_endpoint(target.url, link, source="html-link")
                    context.surface_graph.add_edge(target.url, response.url, link, "link")
                    if depth < context.max_crawl_depth and link not in queued:
                        queued.add(link)
                        queue.append((link, depth + 1, "crawl"))
                for script in parser.scripts:
                    if self._same_origin(target, script):
                        scripts_seen.add(script)
                        context.surface_graph.add_endpoint(target.url, script, source="html-script")
                        context.surface_graph.add_edge(target.url, response.url, script, "script")

            self._map_javascript(target, context, scripts_seen, result)
            self._map_openapi(target, context, schema_candidates, result)
            if context.graphql_introspection:
                self._map_graphql(target, context, result)

            snapshot = context.surface_graph.snapshot()["targets"].get(target.url, {})
            endpoints = snapshot.get("endpoints", [])
            result.observations.update(
                {
                    "pages_visited": pages_visited,
                    "scripts_analyzed": sorted(scripts_seen),
                    "endpoint_count": len(endpoints),
                    "document_count": len(snapshot.get("documents", [])),
                }
            )
            result.findings.append(
                Finding(
                    context.run_id,
                    target.url,
                    self.name,
                    "attack-surface-inventory",
                    "Application attack surface mapped",
                    "info",
                    1.0,
                    "REDflare built a deduplicated endpoint inventory from authorized application evidence.",
                    {
                        "endpoints": len(endpoints),
                        "pages_visited": len(pages_visited),
                        "scripts_analyzed": len(scripts_seen),
                        "documents": len(snapshot.get("documents", [])),
                    },
                    ["mapping", "inventory", "web"],
                )
            )
        except Exception as exc:
            result.status = "error"
            result.errors.append(f"{type(exc).__name__}: {exc}")
        result.duration_seconds = round(time.monotonic() - started, 4)
        return result

    @staticmethod
    def _same_origin(target: Target, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or parsed.hostname != target.host:
            return False
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return port == target.port

    @staticmethod
    def _looks_like_schema(body: bytes) -> bool:
        sample = body[:2000].lower()
        return b'"openapi"' in sample or b'"swagger"' in sample

    def _map_javascript(
        self, target: Target, context: ModuleContext, scripts: set[str], result: ModuleResult
    ) -> None:
        for script_url in sorted(scripts)[: context.max_scripts]:
            try:
                response = request(
                    script_url,
                    context.timeout,
                    max_body=1_000_000,
                    allowed_origin=(target.host, target.port),
                )
            except Exception as exc:
                result.errors.append(f"{script_url}: {type(exc).__name__}: {exc}")
                continue
            text = response.body.decode("utf-8", errors="replace")
            routes: dict[str, str] = {}
            for value in FETCH_CALL.findall(text):
                routes[value] = "GET"
            for method, value in AXIOS_CALL.findall(text):
                routes[value] = method.upper()
            for value in ROUTE_LITERAL.findall(text):
                routes.setdefault(value, "GET")
            for value, method in routes.items():
                url = urljoin(script_url, value)
                if not self._same_origin(target, url):
                    continue
                context.surface_graph.add_endpoint(
                    target.url, url, method=method, source="javascript-route"
                )
                context.surface_graph.add_edge(target.url, script_url, url, "javascript-route")

    def _map_openapi(
        self, target: Target, context: ModuleContext, candidates: set[str], result: ModuleResult
    ) -> None:
        for schema_url in sorted(candidates)[: context.max_schema_documents]:
            if not self._same_origin(target, schema_url):
                continue
            try:
                response = request(
                    schema_url,
                    context.timeout,
                    max_body=2_000_000,
                    allowed_origin=(target.host, target.port),
                )
                document = json.loads(response.body.decode("utf-8"))
            except Exception:
                continue
            if not isinstance(document, dict) or not (document.get("openapi") or document.get("swagger")):
                continue
            version = str(document.get("openapi") or document.get("swagger"))
            context.surface_graph.add_document(
                target.url,
                {"kind": "openapi", "url": schema_url, "version": version, "title": document.get("info", {}).get("title")},
            )
            base_url = self._openapi_base(schema_url, document)
            global_security = document.get("security")
            for path, path_item in document.get("paths", {}).items():
                if not isinstance(path_item, dict):
                    continue
                shared_parameters = path_item.get("parameters", [])
                for method, operation in path_item.items():
                    if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                        continue
                    url = urljoin(base_url.rstrip("/") + "/", str(path).lstrip("/"))
                    if not self._same_origin(target, url):
                        continue
                    parameters = self._openapi_parameters(
                        shared_parameters + operation.get("parameters", []), document
                    )
                    content_types = set(operation.get("consumes", document.get("consumes", [])))
                    request_body = operation.get("requestBody", {})
                    content_types.update(request_body.get("content", {}).keys())
                    for media in request_body.get("content", {}).values():
                        if isinstance(media, dict):
                            parameters.extend(
                                self._schema_parameters(media.get("schema", {}), document, "body")
                            )
                    security = operation.get("security", global_security)
                    auth_schemes = sorted(
                        {name for requirement in security or [] for name in requirement}
                    )
                    auth = "none" if security == [] else ",".join(auth_schemes) if auth_schemes else "unknown"
                    for index, content_type in enumerate(sorted(content_types) or [None]):
                        context.surface_graph.add_endpoint(
                            target.url,
                            url,
                            method=method,
                            source="openapi",
                            content_type=content_type,
                            authentication=auth,
                            parameters=parameters if index == 0 else None,
                            metadata={"operation_id": operation.get("operationId"), "schema": schema_url},
                        )

    @staticmethod
    def _openapi_base(schema_url: str, document: dict[str, Any]) -> str:
        servers = document.get("servers") or []
        if servers and isinstance(servers[0], dict) and servers[0].get("url"):
            return urljoin(schema_url, servers[0]["url"])
        if document.get("host"):
            scheme = (document.get("schemes") or [urlparse(schema_url).scheme])[0]
            return f"{scheme}://{document['host']}{document.get('basePath', '/')}"
        parsed = urlparse(schema_url)
        return f"{parsed.scheme}://{parsed.netloc}/"

    @classmethod
    def _openapi_parameters(
        cls, parameters: list[Any], document: dict[str, Any]
    ) -> list[dict[str, Any]]:
        values = []
        for parameter in parameters:
            if not isinstance(parameter, dict) or not parameter.get("name"):
                continue
            schema = parameter.get("schema") or {}
            values.append(
                {
                    "name": parameter["name"],
                    "location": parameter.get("in", "unknown"),
                    "required": bool(parameter.get("required")),
                    "data_type": schema.get("type") or parameter.get("type") or "unknown",
                }
            )
            if parameter.get("in") == "body":
                values.extend(cls._schema_parameters(schema, document, "body"))
        return values

    @classmethod
    def _schema_parameters(
        cls, schema: dict[str, Any], document: dict[str, Any], location: str
    ) -> list[dict[str, Any]]:
        schema = cls._resolve_schema(schema, document)
        required = set(schema.get("required", []))
        values = []
        for name, details in schema.get("properties", {}).items():
            if not isinstance(details, dict):
                continue
            details = cls._resolve_schema(details, document)
            values.append(
                {
                    "name": name,
                    "location": location,
                    "required": name in required,
                    "data_type": details.get("type") or ("object" if details.get("properties") else "unknown"),
                }
            )
        return values

    @staticmethod
    def _resolve_schema(schema: dict[str, Any], document: dict[str, Any]) -> dict[str, Any]:
        reference = schema.get("$ref") if isinstance(schema, dict) else None
        if not isinstance(reference, str) or not reference.startswith("#/"):
            return schema if isinstance(schema, dict) else {}
        current: Any = document
        for part in reference[2:].split("/"):
            if not isinstance(current, dict):
                return {}
            current = current.get(part.replace("~1", "/").replace("~0", "~"))
        return current if isinstance(current, dict) else {}

    def _map_graphql(self, target: Target, context: ModuleContext, result: ModuleResult) -> None:
        candidates = {
            urljoin(target.url.rstrip("/") + "/", "graphql"),
            *(
                url for url in context.surface_graph.endpoint_urls(target.url)
                if "graphql" in urlparse(url).path.lower()
            ),
        }
        query = "{__schema{queryType{name} mutationType{name} types{name kind fields{name args{name}}}}}"
        payload = json.dumps({"query": query}).encode("utf-8")
        for url in sorted(candidates):
            if not self._same_origin(target, url):
                continue
            try:
                response = request(
                    url,
                    context.timeout,
                    method="POST",
                    max_body=2_000_000,
                    data=payload,
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                    allowed_origin=(target.host, target.port),
                )
                document = json.loads(response.body.decode("utf-8"))
                schema = document.get("data", {}).get("__schema")
            except Exception:
                continue
            if not schema:
                continue
            operations: list[str] = []
            for type_item in schema.get("types", []):
                if type_item.get("name") in {
                    (schema.get("queryType") or {}).get("name"),
                    (schema.get("mutationType") or {}).get("name"),
                }:
                    operations.extend(field.get("name") for field in type_item.get("fields", []) if field.get("name"))
            context.surface_graph.add_endpoint(
                target.url,
                url,
                method="POST",
                source="graphql-introspection",
                content_type="application/json",
                status=response.status,
                metadata={"graphql_operations": sorted(set(operations))},
            )
            context.surface_graph.add_document(
                target.url,
                {"kind": "graphql", "url": url, "operations": len(set(operations))},
            )
            result.observations["graphql"] = {"url": url, "operations": sorted(set(operations))}
