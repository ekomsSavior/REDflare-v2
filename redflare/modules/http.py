from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class HTTPResponse:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes
    tls_verified: bool = True


class ScopedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_origin: tuple[str, int]):
        super().__init__()
        self.allowed_origin = allowed_origin

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urlparse(newurl)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if (parsed.hostname, port) != self.allowed_origin:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def request(
    url: str,
    timeout: float,
    method: str = "GET",
    max_body: int = 1_000_000,
    *,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    allowed_origin: tuple[str, int] | None = None,
    verify_tls: bool = True,
) -> HTTPResponse:
    request_headers = {"User-Agent": "REDflare-v2/2.1 authorized-assessment"}
    request_headers.update(headers or {})
    req = urllib.request.Request(url, data=data, method=method, headers=request_headers)
    context = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    try:
        if allowed_origin:
            opener = urllib.request.build_opener(
                ScopedRedirectHandler(allowed_origin), urllib.request.HTTPSHandler(context=context)
            )
            response = opener.open(req, timeout=timeout)
        else:
            response = urllib.request.urlopen(req, timeout=timeout, context=context)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        body = b"" if method == "HEAD" else response.read(max_body)
        return HTTPResponse(
            url=response.geturl(),
            status=int(response.status),
            headers={key.lower(): value for key, value in response.headers.items()},
            body=body,
            tls_verified=verify_tls,
        )
