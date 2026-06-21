from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import Finding


@dataclass(frozen=True)
class TestDefinition:
    id: str
    name: str
    module: str
    category: str
    wstg: tuple[str, ...] = ()
    asvs: tuple[str, ...] = ()
    cwe: tuple[str, ...] = ()
    api_security: tuple[str, ...] = ()

    def references(self) -> dict[str, list[dict[str, str]]]:
        return {
            "OWASP_WSTG": [reference("OWASP_WSTG", value) for value in self.wstg],
            "OWASP_ASVS": [reference("OWASP_ASVS", value) for value in self.asvs],
            "CWE": [reference("CWE", value) for value in self.cwe],
            "OWASP_API_SECURITY": [reference("OWASP_API_SECURITY", value) for value in self.api_security],
        }


WSTG_URLS = {
    "WSTG-INFO-06": "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/06-Identify_Application_Entry_Points",
    "WSTG-INFO-07": "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/07-Map_Execution_Paths_Through_Application",
    "WSTG-INFO-05": "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage",
    "WSTG-CONF-04": "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
    "WSTG-CONF-05": "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces",
    "WSTG-CONF-07": "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security",
    "WSTG-ATHZ-02": "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema",
    "WSTG-CLNT-04": "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect",
}

API_SECURITY_URLS = {
    "API1:2023": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
    "API3:2023": "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
    "API8:2023": "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
    "API9:2023": "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
    "API10:2023": "https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/",
}


def reference(family: str, identifier: str) -> dict[str, str]:
    if family == "OWASP_WSTG":
        return {"id": identifier, "version": "4.2", "url": WSTG_URLS[identifier]}
    if family == "OWASP_ASVS":
        return {
            "id": identifier,
            "version": "5.0.0",
            "url": "https://owasp.org/www-project-application-security-verification-standard/",
        }
    if family == "CWE":
        number = identifier.removeprefix("CWE-")
        return {"id": identifier, "url": f"https://cwe.mitre.org/data/definitions/{number}.html"}
    return {
        "id": identifier,
        "version": "2023",
        "url": API_SECURITY_URLS[identifier],
    }


TEST_REGISTRY: tuple[TestDefinition, ...] = (
    TestDefinition(
        "RFV2-COMP-001", "Correlate disclosed component versions with known vulnerabilities",
        "cve_intelligence", "known-vulnerable-component",
        ("WSTG-INFO-05",), ("v5.0.0-14.2.1",), ("CWE-1104",), ("API9:2023",),
    ),
    TestDefinition(
        "RFV2-MAP-001", "Build application entry-point inventory", "application_mapping", "attack-surface-inventory",
        ("WSTG-INFO-06", "WSTG-INFO-07"), ("v5.0.0-8.1.1", "v5.0.0-13.4.5"), ("CWE-1059",), ("API9:2023",),
    ),
    TestDefinition(
        "RFV2-CONF-001", "Review browser security headers", "http_headers", "security-headers",
        ("WSTG-CONF-07",),
        ("v5.0.0-3.4.1", "v5.0.0-3.4.3", "v5.0.0-3.4.4", "v5.0.0-3.4.5"),
        ("CWE-693",), ("API8:2023",),
    ),
    TestDefinition(
        "RFV2-INFO-002", "Identify credential-entry surfaces", "surface_analysis", "credential-surface",
        ("WSTG-INFO-06",), ("v5.0.0-6.1.3",), ("CWE-200",), ("API9:2023",),
    ),
    TestDefinition(
        "RFV2-CLNT-001", "Identify client-side redirects", "surface_analysis", "client-redirect",
        ("WSTG-CLNT-04",), ("v5.0.0-1.2.2",), ("CWE-601",), ("API10:2023",),
    ),
    TestDefinition(
        "RFV2-CONF-002", "Discover exposed application paths", "path_discovery", "discovered-path",
        ("WSTG-CONF-04", "WSTG-CONF-05"), ("v5.0.0-13.4.5",), ("CWE-200",), ("API9:2023",),
    ),
    TestDefinition(
        "RFV2-DATA-001", "Detect sensitive data in client-accessible responses", "sensitive_exposure", "sensitive-data-exposure",
        ("WSTG-INFO-05",), ("v5.0.0-13.4.7", "v5.0.0-14.2.3"), ("CWE-200", "CWE-798"), ("API3:2023", "API8:2023"),
    ),
    TestDefinition(
        "RFV2-BROW-001", "Corroborate headers in a browser runtime", "gatekeeper", "browser-security-headers",
        ("WSTG-CONF-07",), ("v5.0.0-3.4.1", "v5.0.0-3.4.3"), ("CWE-693",), ("API8:2023",),
    ),
    TestDefinition(
        "RFV2-BROW-002", "Inventory browser-observed endpoints", "gatekeeper", "browser-endpoints",
        ("WSTG-INFO-06", "WSTG-INFO-07"), ("v5.0.0-8.1.1",), ("CWE-1059",), ("API9:2023",),
    ),
    TestDefinition(
        "RFV2-ATHZ-001", "Identify unauthenticated service surfaces", "noauth_finder", "unauthenticated-service",
        ("WSTG-ATHZ-02",), ("v5.0.0-8.2.1",), ("CWE-862",), ("API1:2023",),
    ),
    TestDefinition(
        "RFV2-CORR-001", "Correlate exposed surfaces and weak hardening", "correlation", "exposed-surface",
        ("WSTG-INFO-06",), ("v5.0.0-13.4.5",), ("CWE-693",), ("API8:2023",),
    ),
)

_BY_KEY = {(item.module, item.category): item for item in TEST_REGISTRY}


def enrich_finding(finding: "Finding") -> "Finding":
    definition = _BY_KEY.get((finding.module, finding.category))
    if definition:
        finding.test_id = definition.id
        dynamic = finding.standards
        finding.standards = definition.references()
        for family, references in dynamic.items():
            existing = {item.get("id") for item in finding.standards.setdefault(family, [])}
            finding.standards[family].extend(item for item in references if item.get("id") not in existing)
    return finding


def registry_document() -> dict:
    return {
        "schema_version": "1.0",
        "tests": [
            {
                "id": item.id,
                "name": item.name,
                "module": item.module,
                "category": item.category,
                "references": item.references(),
            }
            for item in TEST_REGISTRY
        ],
    }
