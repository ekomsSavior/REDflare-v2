from __future__ import annotations

import asyncio
import json
import re
import socket
import ssl
import struct
import time
from pathlib import Path

from redflare.core.models import Finding, ModuleResult, Target
from .base import Module, ModuleContext

BASIC_PORTS = (22, 80, 443, 445, 3389, 8080, 8443)
STANDARD_PORTS = (21, 22, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 636, 873, 993, 995,
                  1433, 1521, 2049, 2375, 2376, 3000, 3268, 3269, 3306, 3389, 5432, 5601, 5900, 5985, 5986,
                  6379, 8080, 8443, 8888, 9000, 9200, 27017)
EXTENDED_PORTS = tuple(sorted(set(STANDARD_PORTS + (23, 69, 88, 109, 161, 179, 427, 500, 514, 515, 548, 554, 623,
                  902, 1080, 1194, 1883, 2181, 3128, 4369, 4848, 5000, 5672, 6443, 7001, 8000, 8008, 8081,
                  8880, 9001, 9090, 9092, 9100, 9300, 9418, 11211, 15672, 18080))))
PORT_SERVICE = {21:"ftp",22:"ssh",25:"smtp",53:"dns",80:"http",110:"pop3",135:"msrpc",139:"netbios",143:"imap",
  389:"ldap",443:"https",445:"smb",465:"smtps",587:"smtp",636:"ldaps",993:"imaps",995:"pop3s",1433:"mssql",
  1521:"oracle",2049:"nfs",2375:"docker",2376:"docker-tls",3000:"http",3268:"ldap-gc",3269:"ldaps-gc",3306:"mysql",
  3389:"rdp",5432:"postgresql",5601:"kibana",5900:"vnc",5985:"winrm",5986:"winrm-tls",6379:"redis",8080:"http",
  8443:"https",8888:"http",9000:"http",9200:"elasticsearch",27017:"mongodb"}
TLS_PORTS = {443, 465, 636, 993, 995, 2376, 3269, 5986, 8443}

def ports_for_depth(depth: str) -> tuple[int, ...]:
    return BASIC_PORTS if depth == "basic" else STANDARD_PORTS if depth == "standard" else EXTENDED_PORTS if depth == "extended" else tuple(range(1, 65536))

def parse_ports(value: str) -> tuple[int, ...]:
    ports = set()
    for part in value.split(","):
        part = part.strip()
        if not part: continue
        if "-" in part:
            start, end = map(int, part.split("-", 1)); ports.update(range(start, end + 1))
        else: ports.add(int(part))
    if not ports or min(ports) < 1 or max(ports) > 65535: raise ValueError("ports must be between 1 and 65535")
    return tuple(sorted(ports))

class NetworkDiscoveryModule(Module):
    name = "network_discovery"
    description = "Discover authorized TCP services, identify protocols and versions, and infer infrastructure roles"

    def run(self, target: Target, context: ModuleContext) -> ModuleResult:
        started = time.monotonic(); result = ModuleResult(self.name, target.url)
        resolved = tuple(sorted({item[4][0] for item in socket.getaddrinfo(target.host, None, type=socket.SOCK_STREAM)}))
        if context.network_allowed_networks:
            import ipaddress
            addresses = tuple(value for value in resolved if any(ipaddress.ip_address(value) in network for network in context.network_allowed_networks))
            if not addresses:
                result.status="error"; result.errors.append("No resolved target address is inside allowed_networks"); return result
        else: addresses = context.network_addresses or resolved[:1]
        ports = context.network_ports or ports_for_depth(context.network_depth)
        if context.network_port_include: ports = tuple(port for port in ports if port in context.network_port_include)
        ports = tuple(port for port in ports if port not in context.network_port_exclude)
        context.emit(target.url, self.name, "progress", f"Scanning {len(addresses)} authorized address(es) across {len(ports)} TCP ports ({context.network_depth})")
        records, probe_errors = asyncio.run(self._scan(addresses, ports, target.host, target.port, target.scheme, context))
        result.errors.extend(probe_errors[:50])
        hosts = []
        for address in addresses:
            services = [item for item in records if item["address"] == address]
            roles = infer_roles(services)
            try: ptr = socket.gethostbyaddr(address)[0]
            except Exception: ptr = None
            if ptr and any(marker in ptr.lower() for marker in ("amazonaws.com","azure.com","cloudapp.net","googleusercontent.com","digitalocean.com","linodeusercontent.com","vultrusercontent.com","cloudflare.com")):
                roles.append({"role":"cloud-hosted-or-vps-like","confidence":.65,"evidence":f"provider-associated PTR: {ptr}"})
            context.surface_graph.add_network_host(target.url, address, hostname=target.host, ptr=ptr)
            for service in services: context.surface_graph.add_service(target.url, address, service)
            for role in roles: context.surface_graph.add_host_role(target.url, address, role)
            hosts.append({"address": address, "hostname": target.host, "ptr": ptr, "services": services, "roles": roles})
            for service in services: context.emit(target.url, self.name, "info", f"OPEN {address}:{service['port']}/tcp {service['service']} {service.get('product','')} {service.get('version','')}".strip())
        if context.network_enumeration:
            for service in records:
                if service.get("risk") == "unauthenticated-redis":
                    result.findings.append(Finding(context.run_id, target.url, self.name, "exposed-network-service",
                        "Redis responded without authentication", "high", .95, "An explicitly authorized Redis PING received PONG without authentication.", service,
                        ["network", "redis", "authorization"], remediation="Require Redis authentication, bind to trusted interfaces, and restrict access with network policy."))
        result.observations = {"engine":"native-redflare", "depth":context.network_depth, "addresses":len(addresses), "ports_scanned":len(ports),
                               "open_services":len(records), "hosts":hosts, "enumeration_authorized":context.network_enumeration}
        if probe_errors: result.observations["non_fatal_probe_errors"] = len(probe_errors)
        directory = context.artifact_dir / self.name / target.host; directory.mkdir(parents=True, exist_ok=True)
        for filename, payload in (("port_scan.json", [{"address":r["address"],"port":r["port"],"protocol":"tcp","state":"open"} for r in records]),
                                  ("service_enumeration.json", hosts),
                                  ("fingerprints.json", [r for r in records if r.get("product") or r.get("version")])):
            path = directory / filename; path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"); result.artifacts.append(str(path))
        result.duration_seconds = round(time.monotonic()-started, 4); return result

    async def _scan(self, addresses, ports, hostname, target_port, target_scheme, context):
        queue=asyncio.Queue(); found=[]; errors=[]
        for address in addresses:
            for port in ports: queue.put_nowait((address,port))
        async def probe(address, port):
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=context.network_timeout)
            except (OSError, asyncio.TimeoutError): return
            if port in TLS_PORTS or (port == target_port and target_scheme == "https"):
                await close_writer(writer)
                try:
                    tls=ssl.create_default_context(); tls.check_hostname=False; tls.verify_mode=ssl.CERT_NONE; tls.set_alpn_protocols(["http/1.1"])
                    reader,writer=await asyncio.wait_for(asyncio.open_connection(address,port,ssl=tls,server_hostname=hostname),timeout=max(1.5,context.network_timeout*2))
                except (OSError,asyncio.TimeoutError,ssl.SSLError):
                    found.append({"address":address,"port":port,"protocol":"tcp","service":target_scheme if port==target_port else PORT_SERVICE.get(port,"unknown"),"confidence":.65,"evidence":"open TCP port; TLS negotiation failed","banner":"","headers":{}}); return
            hint = target_scheme if port == target_port else None
            try: record = await identify(reader, writer, address, port, hostname, context.network_timeout, context.network_enumeration, hint)
            finally: await close_writer(writer)
            found.append(record)
        async def worker():
            while True:
                try: address,port=queue.get_nowait()
                except asyncio.QueueEmpty: return
                try: await probe(address,port)
                except Exception as exc: errors.append(f"{address}:{port}: {type(exc).__name__}: {exc}")
                finally: queue.task_done()
        await asyncio.gather(*(worker() for _ in range(min(max(1,context.network_concurrency),queue.qsize()))))
        return sorted(found, key=lambda x:(x["address"],x["port"])), errors

async def close_writer(writer):
    """Close a service socket without allowing peer TLS shutdown quirks to fail the host scan."""
    try:
        writer.close()
        await writer.wait_closed()
    except (OSError, ssl.SSLError, asyncio.TimeoutError, RuntimeError):
        pass

async def identify(reader, writer, address, port, hostname, timeout, enumerate_services, service_hint=None):
    service = service_hint or PORT_SERVICE.get(port, "unknown"); banner=b""; headers={}; product=""; version=""; evidence="target URL scheme" if service_hint else "port convention"
    try:
        if service in {"http","https","kibana","elasticsearch","docker","winrm","winrm-tls"}:
            if port in TLS_PORTS or service == "https": service = "https"
            writer.write(f"HEAD / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n".encode()); await writer.drain()
            banner = await asyncio.wait_for(reader.read(8192), timeout=timeout)
            text=banner.decode(errors="replace"); headers={k.strip().lower():v.strip() for k,v in (line.split(":",1) for line in text.split("\r\n")[1:] if ":" in line)}
            server=headers.get("server",""); product,version=parse_product(server); evidence="HTTP Server header" if server else evidence
        elif service in {"ssh","ftp","smtp","pop3","imap","mysql","vnc"}:
            banner=await asyncio.wait_for(reader.read(2048), timeout=timeout); product,version=parse_product(banner.decode(errors="replace")); evidence="server banner"
            if service=="smtp":
                writer.write(b"EHLO redflare.local\r\n"); await writer.drain(); banner += await asyncio.wait_for(reader.read(2048), timeout=timeout)
        elif service=="rdp":
            writer.write(bytes.fromhex("030000130ee000000000000100080003000000")); await writer.drain(); banner=await asyncio.wait_for(reader.read(1024),timeout=timeout); evidence="RDP X.224 negotiation"
        elif service=="smb":
            packet=bytes.fromhex("000000a4fe534d4240000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000024000800010000007f000000000000000000000000000000000000000000000000000000000000000311030002100202000302031103000100260000000000010020000100000000000000000000000000000000000000000000000000000000000000")
            writer.write(packet); await writer.drain(); banner=await asyncio.wait_for(reader.read(2048),timeout=timeout); evidence="SMB2 negotiation" if b"\xfeSMB" in banner else evidence
        elif service=="redis" and enumerate_services:
            writer.write(b"*1\r\n$4\r\nPING\r\n"); await writer.drain(); banner=await asyncio.wait_for(reader.read(512), timeout=timeout)
        elif service=="postgresql":
            writer.write(struct.pack("!II",8,80877103)); await writer.drain(); banner=await asyncio.wait_for(reader.read(1), timeout=timeout); evidence="PostgreSQL SSL negotiation"
        elif service=="unknown":
            banner=await asyncio.wait_for(reader.read(1024),timeout=timeout); product,version=parse_product(banner.decode(errors="replace")); evidence="server banner" if banner else evidence
    except (OSError, asyncio.TimeoutError): pass
    record={"address":address,"port":port,"protocol":"tcp","service":service,"confidence":.95 if banner else .65,"evidence":evidence,
            "banner":redact_banner(banner.decode(errors="replace")),"headers":headers}
    ssl_object=writer.get_extra_info("ssl_object")
    if ssl_object: record["tls"]={"version":ssl_object.version(),"cipher":(ssl_object.cipher() or [None])[0],"alpn":ssl_object.selected_alpn_protocol()}
    if product: record["product"]=product
    if version: record["version"]=version
    if service=="redis" and banner.startswith(b"+PONG"): record["risk"]="unauthenticated-redis"
    if service=="unknown" and banner.startswith(b"SSH-"): record["service"]="ssh"
    return record

def parse_product(text):
    patterns=((r"OpenSSH[_/ -]([\w.]+)","OpenSSH"),(r"Apache[/ ]([\w.]+)","Apache HTTP Server"),(r"nginx[/ ]([\w.]+)","nginx"),
              (r"Microsoft-IIS[/ ]([\w.]+)","Microsoft IIS"),(r"^SSH-[\d.]+-([^\s_]+)[_-]([\w.]+)",None),(r"^([\w.-]+)[/ ]([\d][\w.-]+)",None))
    for pattern,name in patterns:
        match=re.search(pattern,text,re.I)
        if match:
            if name:return name,match.group(1)
            return match.group(1),match.group(2)
    return "",""

def redact_banner(value):
    value=re.sub(r"(?i)(password|token|secret|authorization)\s*[:=]\s*\S+",r"\1=<redacted>",value)
    return value.replace("\x00","")[:512].strip()

def infer_roles(services):
    ports={item["port"] for item in services}; products={str(item.get("product") or "").lower() for item in services}; roles=[]
    def add(name, confidence, evidence): roles.append({"role":name,"confidence":confidence,"evidence":evidence})
    if {53,88,389,445}.issubset(ports): add("probable-domain-controller",.9,"DNS, Kerberos, LDAP and SMB exposed")
    elif 389 in ports or 636 in ports: add("directory-server",.7,"LDAP service exposed")
    if ports & {3306,5432,1433,1521,27017}: add("database-server",.8,"database protocol exposed")
    if ports & {25,465,587} and ports & {110,143,993,995}: add("mail-server",.85,"SMTP and mailbox protocols exposed")
    if ports & {80,443,8080,8443}: add("web-server",.9,"HTTP service exposed")
    if ports & {2375,2376,6443}: add("container-platform",.75,"container orchestration API port exposed")
    if ports & {445,3389} or "microsoft iis" in products: add("probable-windows-server",.75,"Windows-associated service combination observed")
    return roles
