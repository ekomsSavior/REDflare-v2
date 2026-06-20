from __future__ import annotations

import base64
import re
import time
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from redflare.core.models import Finding, ModuleResult, Target
from .base import Module, ModuleContext
from .http import request


class SurfaceParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.forms = []
        self.scripts = []
        self.iframes = []
        self.meta_refresh = []
        self._form = None

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "form":
            self._form = {
                "method": values.get("method", "GET").upper(),
                "action": urljoin(self.base_url, values.get("action", "")),
                "inputs": [],
            }
            self.forms.append(self._form)
        elif tag == "input" and self._form is not None:
            self._form["inputs"].append(
                {
                    "name": values.get("name"),
                    "type": values.get("type", "text").lower(),
                }
            )
        elif tag == "script" and values.get("src"):
            self.scripts.append(urljoin(self.base_url, values["src"]))
        elif tag == "iframe" and (values.get("src") or values.get("data-src")):
            self.iframes.append(urljoin(self.base_url, values.get("src") or values["data-src"]))
        elif tag == "meta" and values.get("http-equiv", "").lower() == "refresh":
            match = re.search(r"url\s*=\s*(.+)", values.get("content", ""), re.I)
            if match:
                self.meta_refresh.append(urljoin(self.base_url, match.group(1).strip(" '\"")))

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None


class SurfaceAnalysisModule(Module):
    name = "surface_analysis"
    description = "Analyze forms, scripts, iframes, redirects, emails, and encoded targets"

    def run(self, target: Target, context: ModuleContext) -> ModuleResult:
        started = time.monotonic()
        result = ModuleResult(self.name, target.url)
        try:
            context.emit(target.url, self.name, "progress", "Fetching and parsing application surface")
            response = request(target.url, context.timeout, max_body=1_000_000)
            text = response.body.decode("utf-8", errors="replace")
            parser = SurfaceParser(response.url)
            parser.feed(text)
            emails = sorted(set(re.findall(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", text)))
            encoded_targets = decode_targets(text)
            external_scripts = [
                url for url in parser.scripts if urlparse(url).hostname != target.host
            ]
            result.observations.update(
                {
                    "forms": parser.forms,
                    "scripts": parser.scripts,
                    "external_scripts": external_scripts,
                    "iframes": parser.iframes,
                    "meta_refresh": parser.meta_refresh,
                    "emails": emails,
                    "decoded_targets": encoded_targets,
                }
            )
            context.emit(
                target.url,
                self.name,
                "info",
                f"forms={len(parser.forms)} scripts={len(parser.scripts)} iframes={len(parser.iframes)} emails={len(emails)}",
            )
            credential_forms = [
                form
                for form in parser.forms
                if any(item.get("type") == "password" for item in form["inputs"])
            ]
            if credential_forms:
                result.findings.append(
                    Finding(
                        context.run_id,
                        target.url,
                        self.name,
                        "credential-surface",
                        "Credential-entry form discovered",
                        "info",
                        0.95,
                        "The rendered HTML contains one or more password-entry forms for assessment context.",
                        {"forms": credential_forms},
                        ["forms", "authentication"],
                    )
                )
            if parser.meta_refresh:
                result.findings.append(
                    Finding(
                        context.run_id,
                        target.url,
                        self.name,
                        "client-redirect",
                        "Meta-refresh redirect discovered",
                        "info",
                        0.9,
                        "The page contains a client-side meta-refresh redirect.",
                        {"destinations": parser.meta_refresh},
                        ["redirect", "surface"],
                    )
                )
        except Exception as exc:
            result.status = "error"
            result.errors.append(f"{type(exc).__name__}: {exc}")
        result.duration_seconds = round(time.monotonic() - started, 4)
        return result


def decode_targets(text: str) -> list[str]:
    decoded = []
    for encoded in re.findall(r"(?:target|url)=([A-Za-z0-9+/]{8,}={0,2})", text):
        try:
            value = base64.b64decode(encoded).decode("utf-8")
        except Exception:
            continue
        if value.startswith(("http://", "https://")):
            decoded.append(value)
    return sorted(set(decoded))
