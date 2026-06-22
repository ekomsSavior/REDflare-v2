from __future__ import annotations

import hashlib
import ipaddress
import json
import socket
import ssl
import tempfile
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from redflare.core.models import Finding, ModuleResult, Target
from .base import Module, ModuleContext

TLS_PORTS = {443, 465, 636, 853, 993, 995, 2376, 3269, 5986, 8443}
WEAK_CIPHER_MARKERS = ("NULL", "ANON", "EXPORT", "RC4", "3DES", "DES-CBC", "IDEA", "MD5")
PROTOCOLS = (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
             ("TLSv1.2", ssl.TLSVersion.TLSv1_2), ("TLSv1.3", ssl.TLSVersion.TLSv1_3))


class TLSAssessmentModule(Module):
    name = "tls_assessment"
    description = "Assess certificate trust, protocol support, cryptographic negotiation, and certificate reuse across discovered TLS services"

    def run(self, target: Target, context: ModuleContext) -> ModuleResult:
        started = time.monotonic(); result = ModuleResult(self.name, target.url)
        services = self._services(target, context); assessments = []
        for address, port in services:
            context.emit(target.url, self.name, "progress", f"Assessing TLS on {address}:{port}")
            try: assessment = assess_service(target.host, address, port, context)
            except Exception as exc:
                result.errors.append(f"{address}:{port}: {type(exc).__name__}: {exc}"); continue
            assessments.append(assessment)
            context.surface_graph.add_service(target.url, address, {"address": address, "port": port, "protocol": "tcp",
                "service": "https" if port in {443, 8443} else "tls", "tls_assessment": assessment})
            if not assessment["trust"]["verified"]:
                if context.continue_after_tls_failure: context.allow_unverified_tls(target.host, port)
                result.findings.append(self._finding(context, target, "tls-certificate-trust", "TLS certificate trust validation failed",
                    "medium", assessment["trust"].get("message") or "The certificate chain could not be validated.", assessment))
            if assessment["certificate"].get("hostname_match") is False:
                result.findings.append(self._finding(context, target, "tls-hostname-mismatch", "TLS certificate does not match the target hostname",
                    "medium", "The certificate SAN/CN does not cover the assessed hostname.", assessment))
            days = assessment["certificate"].get("days_remaining")
            if days is not None and days < 30:
                title = "TLS certificate has expired" if days < 0 else "TLS certificate expires soon"
                result.findings.append(self._finding(context, target, "tls-certificate-expiry", title, "high" if days < 0 else "medium",
                    f"The certificate has {days} day(s) remaining.", assessment))
            weak_protocols = [name for name in assessment["protocols"]["supported"] if name in {"TLSv1.0", "TLSv1.1"}]
            if weak_protocols:
                result.findings.append(self._finding(context, target, "tls-weak-protocol", "Deprecated TLS protocol is supported", "medium",
                    f"The service accepted: {', '.join(weak_protocols)}.", {**assessment, "weak_protocols": weak_protocols}))
            if assessment["ciphers"]["weak"]:
                result.findings.append(self._finding(context, target, "tls-weak-cipher", "Weak TLS cipher suite is supported", "medium",
                    "The service accepted one or more deprecated or cryptographically weak cipher suites.", assessment))
            key_size = assessment["certificate"].get("key_size") or 0
            key_algorithm = str(assessment["certificate"].get("key_algorithm") or "")
            signature = str(assessment["certificate"].get("signature_algorithm") or "").lower()
            if (key_algorithm.upper().startswith(("RSA", "DSA")) and key_size < 2048) or "sha1" in signature or "md5" in signature:
                result.findings.append(self._finding(context, target, "tls-weak-certificate-crypto",
                    "TLS certificate uses weak cryptography", "medium",
                    "The certificate uses a weak public-key size or deprecated signature digest.", assessment))
        reused = {}
        for item in assessments:
            fingerprint = item["certificate"].get("sha256")
            if fingerprint: reused.setdefault(fingerprint, []).append(f"{item['address']}:{item['port']}")
        reused = {key: value for key, value in reused.items() if len(value) > 1}
        for item in assessments: item["certificate_reuse"] = reused.get(item["certificate"].get("sha256"), [])
        directory = context.artifact_dir / self.name / target.host; directory.mkdir(parents=True, exist_ok=True)
        artifact = directory / "tls_assessment.json"
        artifact.write_text(json.dumps({"services": assessments, "certificate_reuse": reused}, indent=2, sort_keys=True), encoding="utf-8")
        result.artifacts.append(str(artifact)); result.observations = {"engine": "native-redflare", "services_assessed": len(assessments),
            "trust_failures": sum(not item["trust"]["verified"] for item in assessments), "controlled_continuation": context.continue_after_tls_failure,
            "certificate_reuse": reused, "services": assessments}
        result.duration_seconds = round(time.monotonic() - started, 4)
        if services and not assessments: result.status = "error"
        return result

    @staticmethod
    def _services(target, context):
        snapshot = context.surface_graph.snapshot().get("targets", {}).get(target.url, {}); values = set()
        for host in snapshot.get("network_hosts", []):
            for service in host.get("services", []):
                port = int(service.get("port", 0)); name = str(service.get("service", ""))
                if service.get("tls") or port in TLS_PORTS or name in {"https", "smtps", "ldaps", "imaps", "pop3s", "docker-tls", "winrm-tls"}:
                    values.add((host["address"], port))
        if target.scheme == "https" and not any(port == target.port for _, port in values):
            try: values.add((socket.gethostbyname(target.host), target.port))
            except OSError: pass
        return sorted(values)

    @staticmethod
    def _finding(context, target, category, title, severity, description, evidence):
        return Finding(context.run_id, target.url, "tls_assessment", category, title, severity, .99, description, evidence,
            ["tls", "certificate", "transport-security"], remediation="Deploy a publicly trusted, hostname-valid certificate and disable deprecated protocols and weak cipher suites.")


def assess_service(hostname, address, port, context):
    trust = {"verified": True, "verify_code": None, "message": "Certificate chain validated"}
    try: negotiated = handshake(hostname, address, port, verify=True, timeout=context.timeout)
    except ssl.SSLCertVerificationError as exc:
        code = getattr(exc, "verify_code", None)
        kind = "self-signed" if code in {18, 19} else "unknown-authority" if code in {20, 21} else "expired" if code == 10 else "hostname-mismatch" if code == 62 else "validation-failed"
        trust = {"verified": False, "verify_code": code, "failure_kind": kind, "message": str(exc)}
        negotiated = handshake(hostname, address, port, verify=False, timeout=context.timeout)
    certificate = decode_certificate(negotiated.pop("der_certificate"), hostname)
    try:
        without_sni = handshake(hostname, address, port, verify=False, timeout=context.timeout, use_sni=False)
        sni_behavior = {"accepted_without_sni": True,
                        "same_certificate": hashlib.sha256(without_sni.pop("der_certificate")).hexdigest() == certificate["sha256"],
                        "negotiated": without_sni}
    except (OSError, ssl.SSLError) as exc:
        sni_behavior = {"accepted_without_sni": False, "error": f"{type(exc).__name__}: {exc}"}
    protocols = probe_protocols(hostname, address, port, context.timeout)
    ciphers = enumerate_ciphers(hostname, address, port, context.timeout) if context.tls_cipher_enumeration else {"supported": [], "weak": [], "tested": 0}
    return {"address": address, "port": port, "hostname": hostname, "trust": trust, "certificate": certificate,
            "negotiated": negotiated, "sni_behavior": sni_behavior, "protocols": protocols, "ciphers": ciphers}


def handshake(hostname, address, port, *, verify, timeout, version=None, max_version=None, cipher=None, use_sni=True):
    context = ssl.create_default_context() if verify else ssl._create_unverified_context()
    context.set_alpn_protocols(["h2", "http/1.1"])
    if version: context.minimum_version = context.maximum_version = version
    if max_version: context.maximum_version = max_version
    if version in {ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1}: context.set_ciphers("ALL:@SECLEVEL=0")
    if cipher: context.set_ciphers(cipher + ":@SECLEVEL=0")
    with socket.create_connection((address, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=hostname if use_sni else None) as tls:
            details = tls.cipher() or (None, None, None)
            return {"version": tls.version(), "cipher": details[0], "cipher_bits": details[2], "alpn": tls.selected_alpn_protocol(),
                    "compression": tls.compression(), "sni_used": use_sni, "der_certificate": tls.getpeercert(binary_form=True)}


def decode_certificate(der, hostname):
    path = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as handle:
            handle.write(ssl.DER_cert_to_PEM_cert(der)); path = handle.name
        decoded = ssl._ssl._test_decode_cert(path)
    finally:
        if path: Path(path).unlink(missing_ok=True)
    subject = flatten_name(decoded.get("subject", ())); issuer = flatten_name(decoded.get("issuer", ()))
    hostname_match = certificate_matches_hostname(decoded, hostname)
    not_before = parse_cert_time(decoded.get("notBefore")); not_after = parse_cert_time(decoded.get("notAfter"))
    return {"subject": subject, "issuer": issuer, "serial": decoded.get("serialNumber"),
        "sans": [value for kind, value in decoded.get("subjectAltName", ()) if kind == "DNS"], "sha256": hashlib.sha256(der).hexdigest(),
        "self_signed": subject == issuer, "hostname_match": hostname_match, "not_before": iso(not_before), "not_after": iso(not_after),
        "days_remaining": (not_after - datetime.now(timezone.utc)).days if not_after else None, **public_key_metadata(der)}


def flatten_name(value): return ", ".join(f"{key}={item}" for group in value for key, item in group)


def certificate_matches_hostname(decoded, hostname):
    names = decoded.get("subjectAltName", ())
    try: ip = ipaddress.ip_address(hostname)
    except ValueError: ip = None
    if ip:
        return any(kind == "IP Address" and value == str(ip) for kind, value in names)
    dns_names = [value for kind, value in names if kind == "DNS"]
    if not dns_names:
        dns_names = [item for group in decoded.get("subject", ()) for key, item in group if key == "commonName"]
    return any(ssl._dnsname_match(pattern, hostname) for pattern in dns_names)
def parse_cert_time(value): return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), timezone.utc) if value else None
def iso(value): return value.isoformat() if value else None


def probe_protocols(hostname, address, port, timeout):
    supported, errors = [], {}
    for name, version in PROTOCOLS:
        try:
            with warnings.catch_warnings(): warnings.simplefilter("ignore", DeprecationWarning); handshake(hostname, address, port, verify=False, timeout=timeout, version=version)
            supported.append(name)
        except (OSError, ssl.SSLError) as exc: errors[name] = type(exc).__name__
    return {"supported": supported, "rejected": [name for name, _ in PROTOCOLS if name not in supported], "errors": errors}


def enumerate_ciphers(hostname, address, port, timeout):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); context.check_hostname = False; context.verify_mode = ssl.CERT_NONE
    context.maximum_version = ssl.TLSVersion.TLSv1_2; context.set_ciphers("ALL:@SECLEVEL=0")
    names = sorted({item["name"] for item in context.get_ciphers() if not item["name"].startswith("TLS_")}); supported = []
    def probe(name):
        try: return handshake(hostname, address, port, verify=False, timeout=min(timeout, 3.0), max_version=ssl.TLSVersion.TLSv1_2, cipher=name).get("cipher")
        except (OSError, ssl.SSLError): return None
    with ThreadPoolExecutor(max_workers=min(16, max(1, len(names)))) as pool:
        futures = {pool.submit(probe, name): name for name in names}
        for future in as_completed(futures):
            if future.result(): supported.append(futures[future])
    supported.sort(); weak = [name for name in supported if any(marker in name.upper() for marker in WEAK_CIPHER_MARKERS)]
    return {"supported": supported, "weak": weak, "tested": len(names)}


def public_key_metadata(der):
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
        cert = x509.load_der_x509_certificate(der); key = cert.public_key()
        if isinstance(key, rsa.RSAPublicKey): algorithm = "RSA"
        elif isinstance(key, ec.EllipticCurvePublicKey): algorithm = "EC"
        elif isinstance(key, dsa.DSAPublicKey): algorithm = "DSA"
        elif isinstance(key, ed25519.Ed25519PublicKey): algorithm = "Ed25519"
        elif isinstance(key, ed448.Ed448PublicKey): algorithm = "Ed448"
        else: algorithm = type(key).__name__.lstrip("_").removesuffix("PublicKey")
        return {"key_algorithm": algorithm, "key_size": getattr(key, "key_size", 256 if algorithm == "Ed25519" else 448 if algorithm == "Ed448" else None),
                "signature_algorithm": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else cert.signature_algorithm_oid.dotted_string}
    except (ImportError, ValueError, TypeError):
        try: return asn1_key_metadata(der)
        except (ValueError, IndexError):
            return {"key_algorithm": "unavailable", "key_size": None, "signature_algorithm": "unavailable"}


def asn1_tlv(data, offset=0):
    tag = data[offset]; length = data[offset + 1]; cursor = offset + 2
    if length & 0x80:
        count = length & 0x7f
        if not count or count > 4: raise ValueError("unsupported DER length")
        length = int.from_bytes(data[cursor:cursor + count], "big"); cursor += count
    return tag, cursor, cursor + length


def asn1_children(data, start, end):
    values = []; cursor = start
    while cursor < end:
        tag, value_start, value_end = asn1_tlv(data, cursor); values.append((tag, value_start, value_end)); cursor = value_end
    return values


def decode_oid(data):
    first = data[0]; values = [first // 40, first % 40]; value = 0
    for byte in data[1:]:
        value = (value << 7) | (byte & 0x7f)
        if not byte & 0x80: values.append(value); value = 0
    return ".".join(map(str, values))


def asn1_key_metadata(der):
    _, cert_start, cert_end = asn1_tlv(der); cert = asn1_children(der, cert_start, cert_end)
    _, tbs_start, tbs_end = cert[0]; tbs = asn1_children(der, tbs_start, tbs_end)
    index = 1 if tbs[0][0] == 0xA0 else 0
    spki = tbs[index + 6]
    _, spki_start, spki_end = spki; spki_items = asn1_children(der, spki_start, spki_end)
    _, alg_start, alg_end = spki_items[0]; alg_items = asn1_children(der, alg_start, alg_end)
    oid = decode_oid(der[alg_items[0][1]:alg_items[0][2]])
    algorithms = {"1.2.840.113549.1.1.1": "RSA", "1.2.840.10045.2.1": "EC", "1.2.840.10040.4.1": "DSA",
                  "1.3.101.112": "Ed25519", "1.3.101.113": "Ed448"}
    algorithm = algorithms.get(oid, oid); size = None
    bit_string = der[spki_items[1][1] + 1:spki_items[1][2]]
    if algorithm == "RSA":
        _, rsa_start, rsa_end = asn1_tlv(bit_string); modulus = asn1_children(bit_string, rsa_start, rsa_end)[0]
        size = int.from_bytes(bit_string[modulus[1]:modulus[2]], "big").bit_length()
    elif algorithm == "EC" and len(alg_items) > 1:
        curve = decode_oid(der[alg_items[1][1]:alg_items[1][2]])
        size = {"1.2.840.10045.3.1.7": 256, "1.3.132.0.34": 384, "1.3.132.0.35": 521}.get(curve)
    elif algorithm == "Ed25519": size = 256
    elif algorithm == "Ed448": size = 448
    _, sig_start, sig_end = cert[1]; sig_items = asn1_children(der, sig_start, sig_end)
    sig_oid = decode_oid(der[sig_items[0][1]:sig_items[0][2]])
    signatures = {"1.2.840.113549.1.1.5": "sha1WithRSAEncryption", "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
                  "1.2.840.113549.1.1.12": "sha384WithRSAEncryption", "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
                  "1.2.840.10045.4.3.2": "ecdsa-with-SHA256", "1.2.840.10045.4.3.3": "ecdsa-with-SHA384"}
    return {"key_algorithm": algorithm, "key_size": size, "signature_algorithm": signatures.get(sig_oid, sig_oid)}
