from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass
class HTTPResponse:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes


def request(url: str, timeout: float, method: str = "GET", max_body: int = 1_000_000) -> HTTPResponse:
    req = urllib.request.Request(url, method=method, headers={"User-Agent": "REDflare/0.1 authorized-assessment"})
    context = ssl.create_default_context()
    try:
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
        )
