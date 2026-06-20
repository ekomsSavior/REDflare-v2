from __future__ import annotations

import ipaddress
import json
import socket
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from .models import Target


class ScopeError(ValueError):
    pass


@dataclass
class ScopePolicy:
    allowed_hosts: set[str] = field(default_factory=set)
    allow_public: bool = False

    @classmethod
    def from_file(cls, path: str | None, allow_public: bool = False) -> "ScopePolicy":
        if not path:
            return cls(allow_public=allow_public)
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            allowed_hosts={str(host).lower() for host in data.get("allowed_hosts", [])},
            allow_public=allow_public or bool(data.get("allow_public", False)),
        )

    def validate(self, target: Target) -> None:
        host = target.host.lower()
        if self.allowed_hosts and host not in self.allowed_hosts:
            raise ScopeError(f"{host} is not listed in allowed_hosts")
        if not self.allow_public and is_public_host(host):
            raise ScopeError(
                f"{host} resolves to public address space; use --allow-public only for authorized scope"
            )


def normalize_target(value: str) -> Target:
    value = value.strip()
    if not value:
        raise ScopeError("target cannot be empty")
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ScopeError(f"unsupported target: {value}")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    normalized = f"{parsed.scheme}://{parsed.hostname}"
    if port not in {80, 443}:
        normalized += f":{port}"
    normalized += parsed.path.rstrip("/") or ""
    return Target(normalized, parsed.hostname, parsed.scheme, port)


def is_public_host(host: str) -> bool:
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, None)}
    except socket.gaierror as exc:
        raise ScopeError(f"cannot resolve {host}: {exc}") from exc
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not (ip.is_private or ip.is_loopback or ip.is_link_local):
            return True
    return False
