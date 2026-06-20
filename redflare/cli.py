from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .core.scope import ScopeError, ScopePolicy, normalize_target
from .core.standards import registry_document
from .core.runner import Runner
from .core.storage import RunStore
from .modules.adapters import adapter_health, run_reaper
from .modules.base import ModuleContext
from .profiles import PROFILES, build_modules
from .interactive import interactive_arguments
from .ui import LiveConsole


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="redflare", description="Authorized web assessment orchestrator")
    parser.add_argument("--version", action="version", version=f"REDflare {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("modules", help="List profiles and modules")
    sub.add_parser("doctor", help="Check source-tool adapters")
    sub.add_parser("tests", help="List stable test IDs and standards mappings")

    intel = sub.add_parser("intel", help="Run repository secret intelligence through REAPER")
    intel.add_argument("--repo", action="append", required=True, help="Authorized GitHub repository URL; repeatable")
    intel.add_argument("--authorized", action="store_true", help="Acknowledge authorization for every repository")
    intel.add_argument("--output", default="runs", help="Base run output directory")

    scan = sub.add_parser("scan", help="Run an authorized assessment")
    scan.add_argument("targets", nargs="*", help="HTTP(S) URLs or hostnames")
    scan.add_argument("--targets-file", help="Targets file, one per line")
    scan.add_argument("--scope", help="JSON scope policy with allowed_hosts")
    scan.add_argument("--authorized", action="store_true", help="Acknowledge explicit authorization for every target")
    scan.add_argument("--allow-public", action="store_true", help="Permit authorized public targets")
    scan.add_argument("--profile", choices=sorted(PROFILES), default="quick")
    scan.add_argument("--output", default="runs", help="Base run output directory")
    scan.add_argument("--wordlist", help="Path wordlist for the web profile")
    scan.add_argument("--max-paths", type=int, default=100)
    scan.add_argument("--max-crawl-pages", type=int, default=30)
    scan.add_argument("--max-crawl-depth", type=int, default=2)
    scan.add_argument("--max-scripts", type=int, default=20)
    scan.add_argument("--max-schema-documents", type=int, default=8)
    scan.add_argument("--max-exposure-endpoints", type=int, default=75)
    scan.add_argument("--max-exposure-findings", type=int, default=100)
    scan.add_argument("--max-exposure-body-bytes", type=int, default=2_000_000)
    scan.add_argument(
        "--graphql-introspection",
        action="store_true",
        help="Explicitly permit bounded GraphQL schema introspection on in-scope endpoints",
    )
    scan.add_argument("--rate", type=float, default=2.0, help="Path requests per second")
    scan.add_argument("--timeout", type=float, default=8.0)
    scan.add_argument("--workers", type=int, default=2)
    scan.add_argument("--github-repo", action="append", default=[], help="Associated authorized GitHub repository URL; repeatable")
    return parser


def main(argv: list[str] | None = None) -> int:
    if argv is None and len(sys.argv) == 1:
        argv = interactive_arguments()
        if argv is None:
            return 0
    args = build_parser().parse_args(argv)
    if args.command == "modules":
        for name, classes in PROFILES.items():
            print(f"{name:5}  " + ", ".join(module.name for module in classes))
        return 0
    if args.command == "doctor":
        print(json.dumps({"adapters": adapter_health()}, indent=2))
        return 0
    if args.command == "tests":
        print(json.dumps(registry_document(), indent=2))
        return 0
    if args.command == "intel":
        if not args.authorized:
            print("Refusing to run intelligence collection without --authorized.", file=sys.stderr)
            return 2
        store = RunStore(args.output)
        result = run_reaper(args.repo, store.artifacts / "reaper")
        store.write_manifest(
            {"run_id": store.run_id, "kind": "repository-intelligence", "repositories": args.repo}
        )
        (store.root / "summary.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps(result, indent=2))
        return 0 if result["status"] == "completed" else 1
    if not args.authorized:
        print("Refusing to scan without --authorized acknowledgement.", file=sys.stderr)
        return 2

    values = list(args.targets)
    if args.targets_file:
        values.extend(
            line.strip()
            for line in Path(args.targets_file).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
    if not values:
        print("Provide at least one target or --targets-file.", file=sys.stderr)
        return 2

    try:
        policy = ScopePolicy.from_file(args.scope, allow_public=args.allow_public)
        targets = []
        seen = set()
        for value in values:
            target = normalize_target(value)
            policy.validate(target)
            if target.url not in seen:
                targets.append(target)
                seen.add(target.url)
    except (ScopeError, OSError, json.JSONDecodeError) as exc:
        print(f"Scope error: {exc}", file=sys.stderr)
        return 2

    store = RunStore(args.output)
    console = LiveConsole()
    context = ModuleContext(
        run_id=store.run_id,
        artifact_dir=store.artifacts,
        timeout=args.timeout,
        rate=args.rate,
        wordlist=args.wordlist,
        max_paths=max(1, args.max_paths),
        max_crawl_pages=max(1, args.max_crawl_pages),
        max_crawl_depth=max(0, args.max_crawl_depth),
        max_scripts=max(0, args.max_scripts),
        max_schema_documents=max(0, args.max_schema_documents),
        max_exposure_endpoints=max(1, args.max_exposure_endpoints),
        max_exposure_findings=max(1, args.max_exposure_findings),
        max_exposure_body_bytes=max(1_024, args.max_exposure_body_bytes),
        graphql_introspection=args.graphql_introspection,
        allow_public=args.allow_public,
        reporter=console.emit,
    )
    print(f"REDflare {__version__} | run={store.run_id} | profile={args.profile}")
    print(f"Evidence: {store.root}")
    results, summary = Runner(store, build_modules(args.profile), context, args.workers).run(targets)
    if args.github_repo:
        intel = run_reaper(args.github_repo, store.artifacts / "reaper")
        summary["repository_intelligence"] = intel
        (store.root / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    console.final_report(summary, results, store.root)
    intel_ok = not args.github_repo or summary["repository_intelligence"]["status"] == "completed"
    return 0 if summary["errors"] == 0 and intel_ok else 1
