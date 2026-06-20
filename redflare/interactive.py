from __future__ import annotations


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


def interactive_arguments() -> list[str] | None:
    print(BANNER)
    print("1) Full assessment pipeline (recommended)")
    print("2) Web assessment (native modules)")
    print("3) Quick reconnaissance")
    print("4) Tool and adapter health check")
    print("5) Exit")
    choice = prompt("Select an option", "1")
    if choice == "4":
        return ["doctor"]
    if choice == "5":
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
        "Full mode includes browser interaction and focused unauthenticated service probing. Is that permitted",
        False,
    ):
        print("Falling back to native web assessment mode.")
        profile = "web"
    arguments.extend(["--profile", profile])

    output = prompt("Base output directory", "runs")
    arguments.extend(["--output", output])
    arguments.extend(["--workers", prompt("Targets to process concurrently", "1")])
    arguments.extend(["--timeout", prompt("Request timeout in seconds", "10")])

    if profile in {"web", "full"}:
        wordlist = prompt("Optional path wordlist")
        if wordlist:
            arguments.extend(["--wordlist", wordlist])
        arguments.extend(["--rate", prompt("Path requests per second", "1")])
        arguments.extend(["--max-paths", prompt("Maximum paths per target", "100")])

    if profile == "full":
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
