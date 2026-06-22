from __future__ import annotations

from pathlib import Path
import json
import os
from datetime import datetime


BANNER = r"""
 ██████╗ ███████╗██████╗ ███████╗██╗      █████╗ ██████╗ ███████╗
 ██╔══██╗██╔════╝██╔══██╗██╔════╝██║     ██╔══██╗██╔══██╗██╔════╝
 ██████╔╝█████╗  ██║  ██║█████╗  ██║     ███████║██████╔╝█████╗
 ██╔══██╗██╔══╝  ██║  ██║██╔══╝  ██║     ██╔══██║██╔══██╗██╔══╝
 ██║  ██║███████╗██████╔╝██║     ███████╗██║  ██║██║  ██║███████╗
 ╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
 Authorized Web Assessment Framework
"""


def prompt(text: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{text}{suffix}: ").strip()
    return value or default


def yes_no(text: str, default: bool = False) -> bool:
    marker = "Y/n" if default else "y/N"
    value = input(f"{text} [{marker}]: ").strip().lower()
    if not value:
        return default
    return value in {"y", "yes"}


def recent_runs(limit: int = 10) -> list[Path]:
    roots = [Path(os.environ.get("REDFLARE_HOME", Path.cwd())) / "runs"]
    found: dict[Path, float] = {}
    for root in roots:
        if not root.is_dir():
            continue
        for candidate in root.iterdir():
            if candidate.is_dir() and ((candidate / "attack_surface.json").exists() or (candidate / "findings.jsonl").exists()):
                resolved = candidate.resolve()
                found[resolved] = max(found.get(resolved, 0), candidate.stat().st_mtime)
    return [path for path, _ in sorted(found.items(), key=lambda item: item[1], reverse=True)[:limit]]


def run_label(run: Path) -> str:
    try:
        manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        manifest = {}
    targets = manifest.get("targets") or []
    names = [str(item.get("host") or item.get("url") or "") for item in targets if isinstance(item, dict)]
    target = names[0] if names else run.name
    if len(names) > 1:
        target += f" +{len(names) - 1}"
    created = str(manifest.get("created_at") or "")
    try:
        when = datetime.fromisoformat(created).astimezone().strftime("%b %d %H:%M")
    except ValueError:
        when = datetime.fromtimestamp(run.stat().st_mtime).strftime("%b %d %H:%M")
    try:
        summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
        findings = f" · {int(summary.get('findings', 0))} findings"
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        findings = ""
    return f"{target} · {when}{findings}"


def visualize_arguments() -> list[str] | None:
    runs = recent_runs()
    print("\nVisual investigation console")
    if runs:
        print("Recent REDflare runs:")
        for index, run in enumerate(runs, start=1):
            print(f"{index}) {run_label(run)}")
            print(f"   {run}")
        selection = prompt("Choose a run number or paste a run path / file URL", "1")
        run = str(runs[int(selection) - 1]) if selection.isdigit() and 0 < int(selection) <= len(runs) else selection
    else:
        run = prompt("Run directory or file:/// URL")
    if not run:
        print("No run selected.")
        return None
    arguments = ["visualize", run, "--port", prompt("Local visualizer port", "8765")]
    if not yes_no("Open the visualizer in your browser", True):
        arguments.append("--no-browser")
    print("\nOpening the REDflare visual investigation console...\n")
    return arguments


def interactive_arguments() -> list[str] | None:
    print(BANNER)
    print("1) Full assessment pipeline (recommended)")
    print("2) Web assessment (native modules)")
    print("3) Quick reconnaissance")
    print("4) Visualize a completed run")
    print("5) Native capability health check")
    print("6) Exit")
    choice = prompt("Select an option", "1")
    if choice == "4":
        return visualize_arguments()
    if choice == "5":
        return ["doctor"]
    if choice == "6":
        return None
    profile = {"1": "full", "2": "web", "3": "quick"}.get(choice)
    if not profile:
        print("Unknown menu choice.")
        return None

    print("\nTarget input")
    print("1) Enter one or more targets")
    print("2) Load targets from a file")
    target_mode = prompt("Select target input", "1")
    arguments = ["scan"]
    if target_mode == "2":
        arguments.extend(["--targets-file", prompt("Path to target file")])
    else:
        values = prompt("Target URL(s), comma-separated")
        arguments.extend(value.strip() for value in values.split(",") if value.strip())

    scope = prompt("Optional JSON scope file (blank to use entered targets)")
    if scope:
        arguments.extend(["--scope", scope])

    print("\nAuthorization gate")
    print("Only continue for systems covered by explicit written authorization.")
    if not yes_no("I confirm every entered target is authorized", False):
        print("Authorization was not confirmed. Scan cancelled.")
        return None
    arguments.append("--authorized")
    if yes_no("Does this scope include public internet hosts", True):
        arguments.append("--allow-public")

    if profile == "full" and not yes_no(
        "Full mode includes TCP discovery, protocol identification, browser interaction, and focused authorization checks. Is that permitted",
        False,
    ):
        print("Falling back to native web assessment mode.")
        profile = "web"
    arguments.extend(["--profile", profile])

    output = prompt("Base output directory", str(Path(os.environ.get("REDFLARE_HOME", Path.cwd())) / "runs"))
    arguments.extend(["--output", output])
    arguments.extend(["--workers", prompt("Targets to process concurrently", "1")])
    arguments.extend(["--timeout", prompt("Request timeout in seconds", "10")])

    if profile == "full":
        print("\nNative network discovery")
        print("1) Standard — curated infrastructure/application ports (recommended)")
        print("2) Basic — essential web and administration ports")
        print("3) Extended — broader service discovery")
        print("4) Complete — TCP ports 1-65535")
        depth = {"1":"standard", "2":"basic", "3":"extended", "4":"complete"}.get(prompt("Select network depth", "1"), "standard")
        if depth == "complete" and not yes_no("I explicitly confirm complete TCP scanning is authorized", False):
            print("Complete scanning was not confirmed; using standard depth."); depth = "standard"
        arguments.extend(["--network-depth", depth])
        ports = prompt("Optional explicit TCP ports/ranges (blank uses selected depth)")
        if ports: arguments.extend(["--ports", ports])
        if yes_no("Authorize bounded protocol-specific enumeration checks", False): arguments.append("--service-enumeration")
        if not yes_no("Continue assessment after recording TLS validation failures", True): arguments.append("--no-tls-continuation")
        if not yes_no("Enumerate TLS 1.2-and-earlier cipher support on discovered TLS services", True): arguments.append("--no-tls-cipher-enumeration")

    if profile in {"web", "full"}:
        wordlist = prompt("Optional path wordlist")
        if wordlist:
            arguments.extend(["--wordlist", wordlist])
        arguments.extend(["--rate", prompt("Path requests per second", "1")])
        arguments.extend(["--max-paths", prompt("Maximum paths per target", "100")])
        arguments.extend(["--max-crawl-pages", prompt("Maximum pages to map per target", "30")])
        arguments.extend(["--max-crawl-depth", prompt("Maximum crawler depth", "2")])
        if yes_no("Permit bounded GraphQL schema introspection on in-scope endpoints", False):
            arguments.append("--graphql-introspection")
        arguments.extend(["--max-exposure-endpoints", prompt("Maximum responses to inspect for sensitive exposure", "75")])

    if profile == "full":
        key_file = prompt("Optional NVD API key file (must be readable only by you)")
        if key_file: arguments.extend(["--nvd-api-key-file", key_file])
        repositories = prompt(
            "Optional associated GitHub repositories as owner/repository or URLs (blank if none)"
        )
        for repository in repositories.split(","):
            value = repository.strip()
            if not value:
                continue
            bare = value.removesuffix(".git").removeprefix("https://github.com/").removeprefix("http://github.com/")
            if len([part for part in bare.split("/") if part]) != 2:
                print(f"Skipping invalid repository {value!r}; expected owner/repository or a GitHub URL.")
                continue
            arguments.extend(["--github-repo", value])

    print("\nConfiguration complete. Starting REDflare pipeline...\n")
    return arguments
