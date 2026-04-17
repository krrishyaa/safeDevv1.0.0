"""
cli.py

SafeDev CLI - all commands, flat structure, no pip/npm prefix needed.
Use --ecosystem npm to switch to npm. Default is pip.
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

if sys.platform == "win32":
    import codecs

    sys.stdout = codecs.getwriter("utf-8")(sys.stdout.buffer, "strict")
    sys.stderr = codecs.getwriter("utf-8")(sys.stderr.buffer, "strict")

import click
from colorama import init, Fore, Style

from safedev.utils.blocklist import check_blocklist
from safedev.utils.typosquat import check_typosquat
from safedev.utils.reporter import build_report, print_report
from safedev.scanners.package_scanner import scan_pip_package, scan_npm_package
from safedev.scanners.repo_scanner import scan_repo, scan_local_directory

init(autoreset=True)

SAFEDEV_VERSION = "1.0.0"

# Banner
BANNER = f"""{Fore.CYAN}{Style.BRIGHT}
  ███████╗ █████╗ ███████╗███████╗███████╗██████╗ ███████╗██╗   ██╗
  ██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗██╔════╝██║   ██║
  ███████╗███████║█████╗  █████╗  ██║  ██║█████╗  ██║   ██║
  ╚════██║██╔══██║██╔══╝  ██╔══╝  ██║  ██║██╔══╝  ╚██╗ ██╔╝
  ███████║██║  ██║██║     ███████╗██████╔╝███████╗  ╚████╔╝
  ╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═════╝ ╚══════╝   ╚═══╝
{Style.RESET_ALL}{Fore.WHITE}  Universal Developer Security Tool — Supply Chain Protection
{Fore.YELLOW}  v{SAFEDEV_VERSION}  |  github.com/yourname/safedev
"""


def show_banner():
    click.echo(BANNER)


# Helpers


def _get_pip_base_command():
    """
    Return the safest pip invocation for the current runtime.

    In normal Python execution, use: python -m pip.
    In PyInstaller/frozen EXE mode, sys.executable points to safedev.exe,
    so `safedev.exe -m pip ...` is invalid. Also avoid resolving `pip` to the
    current executable by mistake on Windows.
    """
    if not getattr(sys, "frozen", False):
        return [sys.executable, "-m", "pip"]

    current_exe = Path(sys.executable).resolve()

    candidates = [
        shutil.which("pip.exe"),
        shutil.which("pip3.exe"),
        shutil.which("pip"),
        shutil.which("pip3"),
    ]

    for candidate in candidates:
        if not candidate:
            continue
        try:
            candidate_path = Path(candidate).resolve()
        except Exception:
            candidate_path = Path(candidate)

        if candidate_path == current_exe:
            continue

        name = candidate_path.name.lower()
        if "safedev" in name:
            continue

        return [str(candidate_path)]

    py_cmd = shutil.which("py")
    if py_cmd:
        return [py_cmd, "-m", "pip"]

    python_cmd = shutil.which("python")
    if python_cmd:
        try:
            python_path = Path(python_cmd).resolve()
        except Exception:
            python_path = Path(python_cmd)

        if python_path != current_exe:
            return [str(python_path), "-m", "pip"]

    raise RuntimeError(
        "Could not find a usable pip command. Install Python/pip and ensure it is on PATH."
    )


def _run_pip(*args):
    subprocess.run(_get_pip_base_command() + list(args))


def _run_npm(*args):
    subprocess.run(["npm"] + list(args))


def _safe_capture_command(command):
    try:
        return subprocess.run(command, capture_output=True, text=True)
    except FileNotFoundError:
        return None
    except Exception:
        return None


def _find_dashboard_path():
    candidates = []

    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        executable_dir = Path(sys.executable).resolve().parent
        if meipass:
            candidates.extend(
                [
                    Path(meipass) / "safedev" / "ui" / "dashboard.py",
                    Path(meipass) / "ui" / "dashboard.py",
                ]
            )
        candidates.extend(
            [
                executable_dir / "safedev" / "ui" / "dashboard.py",
                executable_dir / "ui" / "dashboard.py",
                executable_dir / "_internal" / "safedev" / "ui" / "dashboard.py",
            ]
        )

    package_dir = Path(__file__).resolve().parent
    candidates.extend(
        [
            package_dir / "ui" / "dashboard.py",
            Path.cwd() / "safedev" / "ui" / "dashboard.py",
        ]
    )

    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)

    return None


def _streamlit_available():
    try:
        import streamlit  # noqa: F401

        return True
    except Exception:
        return False


def _launch_streamlit_dashboard(dashboard_path):
    commands = [
        [
            sys.executable,
            "-m",
            "streamlit",
            "run",
            dashboard_path,
            "--server.headless=true",
        ],
        ["streamlit", "run", dashboard_path, "--server.headless=true"],
    ]

    last_error = None
    for command in commands:
        try:
            return subprocess.run(command).returncode
        except FileNotFoundError as exc:
            last_error = exc
        except Exception as exc:
            last_error = exc

    raise RuntimeError(f"Unable to launch Streamlit: {last_error}")


def _scan_and_confirm(package: str, ecosystem: str, action: str) -> bool:
    """Scan a package. Return True if safe to proceed."""
    show_banner()
    print(f"{Fore.CYAN}[*] Package   : {Style.BRIGHT}{package}")
    print(f"{Fore.CYAN}[*] Ecosystem  : {Style.BRIGHT}{ecosystem.upper()}")
    print(f"{Fore.CYAN}[*] Action     : {Style.BRIGHT}{action}")
    print()

    if ecosystem.lower() == "pip":
        report = scan_pip_package(package, do_install=False)
    else:
        report = scan_npm_package(package, do_install=False)

    if report.get("blocked"):
        print(f"{Fore.RED}{Style.BRIGHT}{'=' * 60}")
        print(f"{Fore.RED}{Style.BRIGHT}  INSTALLATION BLOCKED")
        print(f"{Fore.RED}  Package : {package}")
        print(f"{Fore.RED}  Reason  : {report['block_reason']}")
        print()
        print(f"{Fore.YELLOW}  Nothing was downloaded. Nothing was installed.")
        print(f"{Fore.RED}{Style.BRIGHT}{'=' * 60}")
        return False

    if report.get("error"):
        print(f"{Fore.YELLOW}[!] Could not pre-scan {package}: {report['error']}")
        print(f"{Fore.YELLOW}    Proceeding anyway...")
        return True

    print_report(report)

    score = report.get("score", 0)
    if score >= 7:
        print(
            f"{Fore.RED}{Style.BRIGHT}  ✘  BLOCKED — risk score {score}/10 is too high."
        )
        print(f"{Fore.YELLOW}  Use pip install {package} directly to bypass SafeDev.")
        return False
    elif score >= 4:
        print(f"{Fore.YELLOW}  ⚠  Medium risk ({score}/10). Proceed with caution.")
        return click.confirm(f"{Fore.WHITE}  Continue with {action}?", default=True)
    else:
        print(f"{Fore.GREEN}{Style.BRIGHT}  ✔  Safe ({score}/10). Proceeding...")
        return True


# Root CLI group
@click.group()
@click.version_option(version=SAFEDEV_VERSION, prog_name="SafeDev")
def cli():
    """
    SafeDev — Universal Developer Security Tool.

    \b
    Protects against supply chain attacks by scanning packages
    BEFORE you install them.

    \b
    Quick start:
      safedev install requests
      safedev install axios --ecosystem npm
      safedev list
      safedev upgrade requests
      safedev scan ./my-project
      safedev ui
    """
    pass


#
# safedev version
#
@cli.command("version")
def version_command():
    """Show SafeDev and ecosystem versions.

    \b
    Example:
      safedev version
    """
    show_banner()
    print(f"{Fore.CYAN}  SafeDev version : {Style.BRIGHT}{SAFEDEV_VERSION}")
    print()

    print(f"{Fore.CYAN}  Python  : {Style.BRIGHT}{sys.version.split()[0]}")

    result = _safe_capture_command(_get_pip_base_command() + ["--version"])
    if result and result.returncode == 0:
        pip_ver = result.stdout.strip().split()[1]
        print(f"{Fore.CYAN}  pip     : {Style.BRIGHT}{pip_ver}")
    else:
        print(f"{Fore.YELLOW}  pip     : not found")

    result = _safe_capture_command(["npm", "--version"])
    if result and result.returncode == 0:
        print(f"{Fore.CYAN}  npm     : {Style.BRIGHT}{result.stdout.strip()}")
    else:
        print(f"{Fore.YELLOW}  npm     : not installed (needed for npm scanning)")

    result = _safe_capture_command(["node", "--version"])
    if result and result.returncode == 0:
        print(f"{Fore.CYAN}  node    : {Style.BRIGHT}{result.stdout.strip()}")
    else:
        print(f"{Fore.YELLOW}  node    : not installed")

    result = _safe_capture_command(["git", "--version"])
    if result and result.returncode == 0:
        git_ver = result.stdout.strip().replace("git version ", "")
        print(f"{Fore.CYAN}  git     : {Style.BRIGHT}{git_ver}")
    else:
        print(f"{Fore.YELLOW}  git     : not installed (needed for repo scanning)")

    print()


@cli.command("install")
@click.argument("packages", nargs=-1, required=True)
@click.option(
    "--ecosystem",
    "-e",
    default="pip",
    type=click.Choice(["pip", "npm"], case_sensitive=False),
    help="Package ecosystem: pip or npm (default: pip)",
)
@click.option(
    "--save-dev", is_flag=True, default=False, help="[npm] Install as dev dependency"
)
@click.option(
    "--global",
    "-g",
    "global_install",
    is_flag=True,
    default=False,
    help="[npm] Install globally",
)
def install_command(packages, ecosystem, save_dev, global_install):
    """Scan then install packages. Blocks if malicious.

    \b
    Examples:
      safedev install requests
      safedev install requests flask click
      safedev install axios --ecosystem npm
      safedev install jest --ecosystem npm --save-dev
    """
    for package in packages:
        safe = _scan_and_confirm(package, ecosystem, "install")
        if safe:
            print()
            print(f"{Fore.GREEN}[*] Installing {package}...")
            if ecosystem.lower() == "pip":
                _run_pip("install", package)
            else:
                args = ["install", package]
                if save_dev:
                    args.append("--save-dev")
                if global_install:
                    args.append("-g")
                _run_npm(*args)
            print(f"{Fore.GREEN}  Done. Stay safe with SafeDev. 🔒")
        print()


@cli.command("upgrade")
@click.argument("packages", nargs=-1, required=True)
@click.option(
    "--ecosystem",
    "-e",
    default="pip",
    type=click.Choice(["pip", "npm"], case_sensitive=False),
    help="Package ecosystem (default: pip)",
)
def upgrade_command(packages, ecosystem):
    """Scan then upgrade packages to latest version.

    \b
    Examples:
      safedev upgrade requests
      safedev upgrade requests flask
      safedev upgrade axios --ecosystem npm
    """
    for package in packages:
        safe = _scan_and_confirm(package, ecosystem, "upgrade")
        if safe:
            print()
            print(f"{Fore.GREEN}[*] Upgrading {package}...")
            if ecosystem.lower() == "pip":
                _run_pip("install", "--upgrade", package)
            else:
                _run_npm("update", package)
            print(f"{Fore.GREEN}  Done.")
        print()


@cli.command("uninstall")
@click.argument("packages", nargs=-1, required=True)
@click.option(
    "--ecosystem",
    "-e",
    default="pip",
    type=click.Choice(["pip", "npm"], case_sensitive=False),
    help="Package ecosystem (default: pip)",
)
@click.option(
    "--yes", "-y", is_flag=True, default=False, help="Skip confirmation prompt"
)
def uninstall_command(packages, ecosystem, yes):
    """Uninstall packages (no scan needed - removing is always safe).

    \b
    Examples:
      safedev uninstall requests
      safedev uninstall requests flask --yes
      safedev uninstall axios --ecosystem npm
    """
    show_banner()
    print(f"{Fore.CYAN}[*] Ecosystem : {ecosystem.upper()}")
    print(f"{Fore.CYAN}[*] Removing  : {', '.join(packages)}")
    print()
    if ecosystem.lower() == "pip":
        args = ["uninstall"] + list(packages)
        if yes:
            args.append("-y")
        _run_pip(*args)
    else:
        _run_npm("uninstall", *packages)


@cli.command("list")
@click.option(
    "--ecosystem",
    "-e",
    default="pip",
    type=click.Choice(["pip", "npm"], case_sensitive=False),
    help="Package ecosystem (default: pip)",
)
@click.option(
    "--outdated", is_flag=True, default=False, help="Show only outdated packages"
)
@click.option(
    "--global",
    "-g",
    "global_list",
    is_flag=True,
    default=False,
    help="[npm] List global packages",
)
def list_command(ecosystem, outdated, global_list):
    """List installed packages.

    \b
    Examples:
      safedev list
      safedev list --outdated
      safedev list --ecosystem npm
      safedev list --ecosystem npm --global
    """
    if ecosystem.lower() == "pip":
        args = ["list"]
        if outdated:
            args.append("--outdated")
        _run_pip(*args)
    else:
        args = ["list", "--depth=0"]
        if global_list:
            args.append("-g")
        if outdated:
            _run_npm("outdated")
            return
        _run_npm(*args)


@cli.command("show")
@click.argument("packages", nargs=-1, required=True)
@click.option(
    "--ecosystem",
    "-e",
    default="pip",
    type=click.Choice(["pip", "npm"], case_sensitive=False),
    help="Package ecosystem (default: pip)",
)
def show_command(packages, ecosystem):
    """Show details about an installed package.

    \b
    Examples:
      safedev show requests
      safedev show axios --ecosystem npm
    """
    if ecosystem.lower() == "pip":
        _run_pip("show", *packages)
    else:
        for pkg in packages:
            _run_npm("show", pkg)


@cli.command("freeze")
def freeze_command():
    """Output installed pip packages as requirements.txt format.

    \b
    Example:
      safedev freeze
      safedev freeze > requirements.txt
    """
    _run_pip("freeze")


@cli.command("check")
@click.option(
    "--ecosystem",
    "-e",
    default="pip",
    type=click.Choice(["pip", "npm"], case_sensitive=False),
    help="Package ecosystem (default: pip)",
)
def check_command(ecosystem):
    """Check for dependency issues or vulnerabilities.

    \b
    Examples:
      safedev check
      safedev check --ecosystem npm
    """
    if ecosystem.lower() == "pip":
        _run_pip("check")
    else:
        _run_npm("audit")


@cli.command("audit")
def audit_command():
    """Run npm security audit on current project.

    \b
    Example:
      safedev audit
    """
    _run_npm("audit")


@cli.command("run")
@click.argument("script")
@click.argument("args", nargs=-1)
def run_command(script, args):
    """Run an npm script from package.json.

    \b
    Examples:
      safedev run build
      safedev run test
      safedev run start
    """
    _run_npm("run", script, *args)


@cli.command("clone")
@click.argument("repo_url")
@click.option(
    "--force",
    "-f",
    is_flag=True,
    default=False,
    help="Proceed even if risk score is high",
)
@click.option(
    "--threshold",
    "-t",
    default=5,
    type=int,
    help="Block if risk score > this (default: 5)",
    show_default=True,
)
@click.option(
    "--output",
    "-o",
    default="text",
    type=click.Choice(["text", "json"], case_sensitive=False),
    help="Output format",
    show_default=True,
)
def clone_command(repo_url, force, threshold, output):
    """Scan a Git repository BEFORE cloning it.

    \b
    Examples:
      safedev clone https://github.com/user/repo
      safedev clone https://github.com/user/repo --threshold 3
    """
    if output == "text":
        show_banner()
        click.echo(f"{Fore.CYAN}[*] Repository : {Fore.WHITE}{Style.BRIGHT}{repo_url}")
        click.echo(f"{Fore.CYAN}[*] Cloning to temp dir for analysis...\n")

    report = scan_repo(repo_url)

    if report.get("error"):
        click.echo(f"{Fore.RED}[✗] Could not clone repository: {report['error']}")
        sys.exit(1)

    print_report(report, output_format=output)

    if output == "json":
        tmp = report.pop("_tmp_dir", None)
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
        return

    score = report["score"]
    tmp_dir = report.get("_tmp_dir")

    if score > threshold:
        print(
            f"\n{Fore.RED}{Style.BRIGHT}  ⚠  Risk score {score}/10 exceeds threshold {threshold}/10."
        )
        if not force:
            proceed = click.confirm(f"{Fore.WHITE}  Clone anyway?", default=False)
            if not proceed:
                print(f"{Fore.YELLOW}  Aborted.")
                if tmp_dir:
                    shutil.rmtree(tmp_dir, ignore_errors=True)
                return
    else:
        print(f"\n{Fore.GREEN}  ✔  Score {score}/10 is within threshold. Proceeding...")

    dest = os.path.basename(repo_url.rstrip("/").split("/")[-1]).replace(".git", "")
    if os.path.exists(dest):
        dest = dest + "_safedev"
    if tmp_dir and os.path.exists(tmp_dir):
        shutil.copytree(tmp_dir, dest)
        shutil.rmtree(tmp_dir, ignore_errors=True)
        print(f"{Fore.GREEN}  Cloned to ./{dest}")
    else:
        subprocess.run(["git", "clone", repo_url])

    print(f"\n{Fore.CYAN}  Done. Stay safe with SafeDev. 🔒\n")


@cli.command("scan")
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option(
    "--output",
    "-o",
    default="text",
    type=click.Choice(["text", "json"], case_sensitive=False),
    help="Output format",
    show_default=True,
)
def scan_command(path, output):
    """Scan an existing local directory for malware.

    \b
    Examples:
      safedev scan .
      safedev scan ./my-project
      safedev scan C:\\Users\\me\\code
    """
    if output == "text":
        show_banner()
        click.echo(f"{Fore.CYAN}[*] Scanning: {Fore.WHITE}{Style.BRIGHT}{path}\n")
    report = scan_local_directory(path)
    print_report(report, output_format=output)


@cli.command("scan-deps")
@click.argument("filepath", type=click.Path(exists=True))
@click.option(
    "--threshold",
    "-t",
    default=5,
    type=int,
    help="Warn if any package score > this (default: 5)",
    show_default=True,
)
@click.option(
    "--output",
    "-o",
    default="text",
    type=click.Choice(["text", "json"], case_sensitive=False),
    help="Output format",
    show_default=True,
)
@click.option(
    "--max",
    "max_packages",
    default=20,
    type=int,
    help="Max packages to scan (default: 20)",
    show_default=True,
)
def scan_deps_command(filepath, threshold, output, max_packages):
    """Scan ALL packages listed in requirements.txt or package.json.

    \b
    Examples:
      safedev scan-deps requirements.txt
      safedev scan-deps package.json
      safedev scan-deps requirements.txt --threshold 3
    """
    from safedev.scanners.dep_scanner import scan_dependencies
    import json as _json

    if output == "text":
        show_banner()
        click.echo(
            f"{Fore.CYAN}[*] Dependency file : {Fore.WHITE}{Style.BRIGHT}{filepath}"
        )
        click.echo(f"{Fore.CYAN}[*] Risk threshold  : {Fore.WHITE}{threshold}/10")
        click.echo(f"{Fore.CYAN}[*] Max packages    : {Fore.WHITE}{max_packages}\n")

    summary = None

    for event in scan_dependencies(filepath, max_packages=max_packages):
        if event["type"] == "progress" and output == "text":
            pkg = event["package"]
            score = event["score"]
            label = event["label"]
            cur = event["current"]
            total = event["total"]

            if score <= 2:
                sc = Fore.GREEN
            elif score <= 5:
                sc = Fore.YELLOW
            else:
                sc = Fore.RED + Style.BRIGHT

            bar_done = int((cur / total) * 20)
            bar_empty = 20 - bar_done
            bar = f"[{'█' * bar_done}{'░' * bar_empty}]"

            click.echo(
                f"  {Fore.CYAN}{bar} {cur:02d}/{total:02d}  "
                f"{Fore.WHITE}{pkg:<30} "
                f"{sc}{score}/10  {label}{Style.RESET_ALL}"
            )
        elif event["type"] == "summary":
            summary = event

    if summary is None:
        click.echo(f"{Fore.RED}[✗] No packages found in {filepath}")
        sys.exit(1)

    if output == "json":
        summary.pop("type", None)
        print(_json.dumps(summary, indent=2))
        return

    results = summary["results"]
    avg = summary["summary_score"]
    highest = summary["highest_risk"]

    click.echo()
    click.echo("═" * 65)
    click.echo(f"  {Fore.CYAN}{Style.BRIGHT}DEPENDENCY SCAN COMPLETE{Style.RESET_ALL}")
    click.echo("─" * 65)
    click.echo(f"  File scanned  : {filepath}")
    click.echo(f"  Total found   : {summary['total_packages']} packages")
    click.echo(f"  Scanned       : {summary['scanned']} packages")
    if summary["skipped"] > 0:
        click.echo(
            f"  {Fore.YELLOW}Skipped (limit): {summary['skipped']} packages{Style.RESET_ALL}"
        )
    click.echo(f"  Avg risk score: {avg}/10")
    click.echo("─" * 65)
    click.echo(
        f"  {Fore.GREEN}✓ Safe (0-2)    : {summary['safe_count']:<4}{Style.RESET_ALL}"
        f"  {Fore.YELLOW}! Low (3-5)    : {summary['low_count']:<4}{Style.RESET_ALL}"
    )
    click.echo(
        f"  {Fore.YELLOW}{Style.BRIGHT}⚠ Medium (6-8)  : {summary['medium_count']:<4}{Style.RESET_ALL}"
        f"  {Fore.RED}{Style.BRIGHT}✗ High (9-10)  : {summary['high_count']:<4}{Style.RESET_ALL}"
    )
    click.echo("═" * 65)

    click.echo(
        f"\n  {Style.BRIGHT}Package Results (sorted by risk):{Style.RESET_ALL}\n"
    )
    click.echo(f"  {'Package':<30} {'Score':>6}  {'Risk Level':<14} {'Issues':>6}")
    click.echo(f"  {'-' * 30} {'-' * 6}  {'-' * 14} {'-' * 6}")

    for r in results:
        name = r.get("package_name", r.get("target", "?"))[:29]
        score = r.get("score", 0)
        label = r.get("risk_label", "?")
        issues = r.get("total_findings", 0)
        err_ = r.get("error")

        if err_:
            click.echo(
                f"  {Fore.YELLOW}{name:<30} {'ERR':>6}  {'DOWNLOAD FAIL':<14} {'-':>6}{Style.RESET_ALL}"
            )
            continue

        color = (
            Fore.GREEN
            if score <= 2
            else Fore.YELLOW
            if score <= 5
            else Fore.YELLOW + Style.BRIGHT
            if score <= 8
            else Fore.RED + Style.BRIGHT
        )

        click.echo(
            f"  {color}{name:<30} {score:>5}/10  {label:<14} {issues:>6}{Style.RESET_ALL}"
        )

    if highest and highest.get("score", 0) > threshold:
        click.echo()
        click.echo(
            f"  {Fore.RED}{Style.BRIGHT}⚠ HIGHEST RISK: {highest.get('package_name', '?')}  "
            f"(score: {highest['score']}/10){Style.RESET_ALL}"
        )
        for f in highest.get("findings", [])[:3]:
            click.echo(
                f"  {Fore.YELLOW}  • [{f['rule_id']}] {f['name']}{Style.RESET_ALL}"
            )

    click.echo()
    risky = [r for r in results if r.get("score", 0) > threshold and not r.get("error")]
    if risky:
        click.echo(
            f"{Fore.RED}{Style.BRIGHT}  [!] {len(risky)} package(s) exceed threshold {threshold}/10:{Style.RESET_ALL}"
        )
        for r in risky:
            click.echo(
                f"      • {r.get('package_name', '?')}  (score: {r['score']}/10)"
            )
        click.echo(f"\n  {Fore.YELLOW}Review these packages before using them.\n")
    else:
        click.echo(
            f"  {Fore.GREEN}{Style.BRIGHT}[✓] All packages within threshold {threshold}/10.{Style.RESET_ALL}\n"
        )


@cli.command("ui")
def ui_command():
    """Launch the SafeDev web dashboard in your browser.

    \b
    Example:
      safedev ui
    """
    show_banner()

    dashboard = _find_dashboard_path()
    if not dashboard:
        print(f"{Fore.RED}[!] SafeDev dashboard file was not found.")
        print(
            f"{Fore.YELLOW}    Expected a packaged or installed file at safedev/ui/dashboard.py"
        )
        print(
            f"{Fore.YELLOW}    Reinstall SafeDev or rebuild the executable with UI assets included."
        )
        sys.exit(1)

    if not _streamlit_available():
        print(f"{Fore.RED}[!] Streamlit is not installed or failed to import.")
        print(f"{Fore.YELLOW}    Fix: pip install streamlit")
        print(
            f"{Fore.YELLOW}    If using the packaged EXE, rebuild it with Streamlit hidden imports included."
        )
        sys.exit(1)

    print(f"{Fore.GREEN}[*] Launching dashboard at http://localhost:8501")
    print(f"{Fore.CYAN}    Dashboard: {dashboard}")
    print(f"{Fore.CYAN}    Press Ctrl+C to stop.\n")

    try:
        exit_code = _launch_streamlit_dashboard(dashboard)
    except Exception as exc:
        print(f"{Fore.RED}[!] Failed to launch the Streamlit dashboard.")
        print(f"{Fore.YELLOW}    Reason: {exc}")
        sys.exit(1)

    if exit_code not in (0, None):
        sys.exit(exit_code)


@cli.command("install-deps")
@click.argument("filepath", type=click.Path(exists=True))
@click.option(
    "--max",
    "max_packages",
    default=20,
    type=int,
    help="Max packages to scan (default: 20)",
    show_default=True,
)
@click.option(
    "--threshold",
    "-t",
    default=6,
    type=int,
    help="Block packages above this score (default: 6)",
    show_default=True,
)
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    default=False,
    help="Skip confirmation and install all safe packages automatically",
)
def install_deps_command(filepath, max_packages, threshold, yes):
    """Scan then install all packages from requirements.txt or package.json.

    \b
    Scans every package first. Blocks malicious ones.
    Installs all packages that pass the risk threshold.

    \b
    Examples:
      safedev install-deps requirements.txt
      safedev install-deps requirements.txt --yes
      safedev install-deps package.json
      safedev install-deps requirements.txt --threshold 3
    """
    from safedev.scanners.dep_scanner import scan_dependencies

    show_banner()
    print(f"{Fore.CYAN}[*] File      : {Style.BRIGHT}{filepath}")
    print(
        f"{Fore.CYAN}[*] Threshold : {Style.BRIGHT}{threshold}/10 (packages above this will be blocked)"
    )
    print(f"{Fore.CYAN}[*] Max pkgs  : {Style.BRIGHT}{max_packages}")
    print()
    print("=" * 62)
    print()

    summary = None
    results = []
    ecosystem = "pip"

    for event in scan_dependencies(filepath, max_packages=max_packages):
        if event["type"] == "progress":
            pkg = event["package"]
            score = event["score"]
            label = event["label"]
            cur = event["current"]
            total = event["total"]

            if score <= 2:
                sc = Fore.GREEN
            elif score <= threshold:
                sc = Fore.YELLOW
            else:
                sc = Fore.RED + Style.BRIGHT

            bar_done = int((cur / total) * 20)
            bar_empty = 20 - bar_done
            bar = f"[{'█' * bar_done}{'░' * bar_empty}]"

            click.echo(
                f"  {Fore.CYAN}{bar} {cur:02d}/{total:02d}  "
                f"{Fore.WHITE}{pkg:<30} "
                f"{sc}{score}/10  {label}{Style.RESET_ALL}"
            )

        elif event["type"] == "summary":
            summary = event
            results = event["results"]
            ecosystem = event["ecosystem"]

    if not summary:
        print(f"{Fore.RED}[!] No packages found in {filepath}")
        return

    safe_pkgs = []
    blocked_pkgs = []
    error_pkgs = []

    for r in results:
        name = r.get("package_spec") or r.get("package_name") or r.get("target", "")
        if r.get("error"):
            error_pkgs.append((name, r))
        elif r.get("blocked"):
            blocked_pkgs.append((name, r))
        elif r.get("score", 0) > threshold:
            blocked_pkgs.append((name, r))
        else:
            safe_pkgs.append((name, r))

    print()
    print("=" * 62)
    print(f"  {Fore.CYAN}{Style.BRIGHT}DEPENDENCY INSTALL SUMMARY{Style.RESET_ALL}")
    print("=" * 62)
    print(f"  {Fore.GREEN}Safe to install      : {len(safe_pkgs)}{Style.RESET_ALL}")
    print(f"  {Fore.RED}Blocked              : {len(blocked_pkgs)}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}Errors (skipped)     : {len(error_pkgs)}{Style.RESET_ALL}")
    print("=" * 62)

    if blocked_pkgs:
        print()
        print(
            f"{Fore.RED}{Style.BRIGHT}  BLOCKED PACKAGES (will NOT be installed):{Style.RESET_ALL}"
        )
        for name, r in blocked_pkgs:
            score = r.get("score", 0)
            reason = r.get("block_reason") or r.get("risk_label", "high risk")
            print(
                f"  {Fore.RED}  ✗ {name:<30} score={score}/10  {reason}{Style.RESET_ALL}"
            )

    if error_pkgs:
        print()
        print(
            f"{Fore.YELLOW}  PACKAGES WITH ERRORS (will be skipped):{Style.RESET_ALL}"
        )
        for name, r in error_pkgs:
            print(
                f"  {Fore.YELLOW}  ! {name:<30} {r.get('error', 'unknown error')[:40]}{Style.RESET_ALL}"
            )

    if not safe_pkgs:
        print()
        print(
            f"{Fore.RED}[!] No packages passed the security check. Nothing installed."
        )
        return

    print()
    print(
        f"{Fore.GREEN}{Style.BRIGHT}  SAFE PACKAGES (will be installed):{Style.RESET_ALL}"
    )
    for name, r in safe_pkgs:
        score = r.get("score", 0)
        print(f"  {Fore.GREEN}  ✓ {name:<30} score={score}/10{Style.RESET_ALL}")

    print()
    if not yes:
        confirm = click.confirm(
            f"{Fore.WHITE}  Install {len(safe_pkgs)} safe package(s)?", default=True
        )
        if not confirm:
            print(f"{Fore.YELLOW}  Aborted. Nothing was installed.")
            return

    print()
    print("=" * 62)
    print(f"  {Fore.CYAN}{Style.BRIGHT}INSTALLING SAFE PACKAGES{Style.RESET_ALL}")
    print("=" * 62)
    print()

    installed_ok = []
    installed_err = []

    for name, r in safe_pkgs:
        print(f"{Fore.CYAN}[*] Installing {name}...")
        if ecosystem == "pip":
            result = subprocess.run(
                _get_pip_base_command() + ["install", name],
                capture_output=True,
                text=True,
            )
        else:
            result = subprocess.run(
                ["npm", "install", name], capture_output=True, text=True
            )

        if result.returncode == 0:
            print(f"{Fore.GREEN}  ✓ Installed successfully")
            installed_ok.append(name)
        else:
            err = result.stderr.strip().splitlines()[-1] if result.stderr else "unknown"
            print(f"{Fore.RED}  ✗ Install failed: {err}")
            installed_err.append(name)

    print()
    print("=" * 62)
    print(f"  {Fore.CYAN}{Style.BRIGHT}INSTALL COMPLETE{Style.RESET_ALL}")
    print("=" * 62)
    print(
        f"  {Fore.GREEN}Installed successfully : {len(installed_ok)}{Style.RESET_ALL}"
    )
    print(f"  {Fore.RED}Install failures       : {len(installed_err)}{Style.RESET_ALL}")
    print(f"  {Fore.RED}Blocked by policy      : {len(blocked_pkgs)}{Style.RESET_ALL}")
    if error_pkgs:
        print(
            f"  {Fore.YELLOW}Skipped (scan error)   : {len(error_pkgs)}{Style.RESET_ALL}"
        )
    print("=" * 62)
    print(f"  {Fore.GREEN}Done. Stay safe with SafeDev.{Style.RESET_ALL}")


if __name__ == "__main__":
    cli()
