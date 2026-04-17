"""
package_scanner.py
──────────────────
Pre-download security checks + optional real install.

Flow:
  1. Blocklist check  (instant — no network)
  2. Typosquat check  (instant — no network)
  3. If both pass → download & scan source
  4. If source scan passes → actually pip/npm install
"""

import os
import sys
import shutil
import tarfile
import zipfile
import tempfile
import subprocess
from pathlib import Path

from safedev.utils.rule_engine import load_rules, scan_directory
from safedev.utils.reporter import build_report
from safedev.utils.blocklist import check_blocklist
from safedev.utils.typosquat import check_typosquat


# ── Helpers ────────────────────────────────────────────────────


def _get_pip_base_command():
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


def _verify_pip_command(pip_cmd):
    """Verify pip command works and supports download subcommand."""
    try:
        result = subprocess.run(
            pip_cmd + ["-V"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return False, result.stderr.strip() or "unknown pip error"
        return True, result.stdout.strip()
    except subprocess.TimeoutExpired:
        return False, "pip command timed out"
    except FileNotFoundError:
        return False, "pip command not found"
    except Exception as e:
        return False, str(e)


def _pre_download_checks(package_name: str, ecosystem: str) -> dict | None:
    """
    Run blocklist + typosquat checks.
    Returns an error report dict if blocked, else None (all clear).
    """
    # 1. Blocklist
    bl = check_blocklist(package_name, ecosystem)
    if bl:
        return {
            "target": package_name,
            "ecosystem": ecosystem,
            "score": 10,
            "risk_label": "BLOCKED",
            "total_findings": 1,
            "findings": [],
            "blocked": True,
            "block_reason": f"KNOWN MALICIOUS: {bl['reason']}",
        }

    # 2. Typosquat
    ts = check_typosquat(package_name, ecosystem)
    if ts:
        return {
            "target": package_name,
            "ecosystem": ecosystem,
            "score": 8,
            "risk_label": "BLOCKED",
            "total_findings": 1,
            "findings": [],
            "blocked": True,
            "block_reason": (
                f"TYPOSQUATTING DETECTED ({ts['confidence']} confidence): "
                f'"{package_name}" looks like "{ts["similar_to"]}" '
                f"(edit distance {ts['distance']}). "
                f"Did you mean: {ts['similar_to']}?"
            ),
        }

    return None  # all clear


# ── Public API ─────────────────────────────────────────────────


def scan_pip_package(package_name: str, do_install: bool = False) -> dict:
    """
    Check + optionally install a pip package.
    If do_install=True and package is safe, runs: pip install <package>
    """
    blocked = _pre_download_checks(package_name, "pip")
    if blocked:
        return blocked

    rules = load_rules()
    tmp_dir = tempfile.mkdtemp(prefix="safedev_pip_")
    pip_cmd = _get_pip_base_command()

    try:
        valid_pip, pip_info = _verify_pip_command(pip_cmd)
        if not valid_pip:
            return {
                "target": package_name,
                "ecosystem": "pip",
                "score": 0,
                "risk_label": "ERROR",
                "total_findings": 0,
                "findings": [],
                "error": f"pip verification failed: {pip_info}",
            }

        result = subprocess.run(
            pip_cmd + ["download", "--no-deps", "--dest", tmp_dir, package_name],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            stderr = result.stderr.strip()
            if not stderr:
                stderr = result.stdout.strip() or "unknown error"
            return {
                "target": package_name,
                "ecosystem": "pip",
                "score": 0,
                "risk_label": "ERROR",
                "total_findings": 0,
                "findings": [],
                "error": f"pip download failed: {stderr}",
            }

        downloaded_files = [
            f for f in os.listdir(tmp_dir) if not f.startswith("extracted")
        ]
        if not downloaded_files:
            return {
                "target": package_name,
                "ecosystem": "pip",
                "score": 0,
                "risk_label": "ERROR",
                "total_findings": 0,
                "findings": [],
                "error": "No packages downloaded - package may not exist or network issue",
            }

        extract_dir = os.path.join(tmp_dir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)

        for fname in os.listdir(tmp_dir):
            if fname == "extracted":
                continue
            fpath = os.path.join(tmp_dir, fname)
            if fname.endswith(".whl"):
                with zipfile.ZipFile(fpath, "r") as zf:
                    zf.extractall(extract_dir)
            elif fname.endswith((".tar.gz", ".tgz")):
                with tarfile.open(fpath, "r:gz") as tf:
                    tf.extractall(extract_dir)
            elif fname.endswith(".zip"):
                with zipfile.ZipFile(fpath, "r") as zf:
                    zf.extractall(extract_dir)

        findings = scan_directory(extract_dir, rules)
        report = build_report(package_name, findings, ecosystem="pip")

        if do_install and report["score"] < 5:
            install = subprocess.run(
                pip_cmd + ["install", package_name],
                capture_output=True,
                text=True,
            )
            report["installed"] = install.returncode == 0
            report["install_output"] = install.stdout.strip() or install.stderr.strip()

        return report

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _verify_npm_command():
    """Verify npm command works."""
    try:
        result = subprocess.run(
            ["npm", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return False, result.stderr.strip() or "unknown npm error"
        return True, result.stdout.strip()
    except subprocess.TimeoutExpired:
        return False, "npm command timed out"
    except FileNotFoundError:
        return False, "npm not found - install Node.js"
    except Exception as e:
        return False, str(e)


def scan_npm_package(package_name: str, do_install: bool = False) -> dict:
    """
    Check + optionally install an npm package.
    If do_install=True and package is safe, runs: npm install <package>
    """
    blocked = _pre_download_checks(package_name, "npm")
    if blocked:
        return blocked

    valid_npm, npm_info = _verify_npm_command()
    if not valid_npm:
        return {
            "target": package_name,
            "ecosystem": "npm",
            "score": 0,
            "risk_label": "ERROR",
            "total_findings": 0,
            "findings": [],
            "error": f"npm verification failed: {npm_info}",
        }

    rules = load_rules()
    tmp_dir = tempfile.mkdtemp(prefix="safedev_npm_")

    try:
        result = subprocess.run(
            ["npm", "pack", package_name, "--pack-destination", tmp_dir],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            stderr = result.stderr.strip()
            if not stderr:
                stderr = result.stdout.strip() or "unknown error"
            return {
                "target": package_name,
                "ecosystem": "npm",
                "score": 0,
                "risk_label": "ERROR",
                "total_findings": 0,
                "findings": [],
                "error": f"npm pack failed: {stderr}",
            }

        downloaded_files = [f for f in os.listdir(tmp_dir) if f.endswith(".tgz")]
        if not downloaded_files:
            return {
                "target": package_name,
                "ecosystem": "npm",
                "score": 0,
                "risk_label": "ERROR",
                "total_findings": 0,
                "findings": [],
                "error": "No package tarball created - package may not exist",
            }

        extract_dir = os.path.join(tmp_dir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)

        for fname in os.listdir(tmp_dir):
            if fname.endswith(".tgz"):
                fpath = os.path.join(tmp_dir, fname)
                with tarfile.open(fpath, "r:gz") as tf:
                    tf.extractall(extract_dir)

        findings = scan_directory(extract_dir, rules)
        report = build_report(package_name, findings, ecosystem="npm")

        if do_install and report["score"] < 5:
            install = subprocess.run(
                ["npm", "install", package_name],
                capture_output=True,
                text=True,
            )
            report["installed"] = install.returncode == 0
            report["install_output"] = install.stdout.strip() or install.stderr.strip()

        return report

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
