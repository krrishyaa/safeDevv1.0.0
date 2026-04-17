"""
╔══════════════════════════════════════════════════════════════╗
║         SafeDev Phase 2A — Dependency Scanner               ║
║                                                              ║
║  Copy this file to:                                          ║
║    D:\safeDev\safedev\safedev\scanners\dep_scanner.py        ║
║                                                              ║
║  Then run:  python update_safedev.py                         ║
║  (update script is the second file — download that too)      ║
╚══════════════════════════════════════════════════════════════╝
"""

# ─────────────────────────────────────────────────────────────
# dep_scanner.py
# ──────────────
# Reads requirements.txt or package.json and scans every
# dependency listed inside it — one by one.
#
# What it does step by step:
#   1. Parse the file → get a list of package names + versions
#   2. For each package → call package_scanner (pip or npm)
#   3. Collect all results → build a combined summary report
#   4. Sort by risk score (most dangerous first)
# ─────────────────────────────────────────────────────────────

import json
import re
import os
from pathlib import Path


def parse_requirements_txt(filepath: str) -> list:
    """
    Reads a requirements.txt file and returns a list of
    package name strings ready to pass to pip download.

    Handles these formats:
        requests                  ← just a name
        requests==2.28.0          ← pinned version
        requests>=2.0,<3.0        ← version range
        # this is a comment       ← skipped
        -r other_requirements.txt ← skipped (nested files)
        git+https://...           ← skipped (git deps)

    Returns list of strings like:
        ["requests==2.28.0", "numpy", "flask>=2.0"]
    """
    packages = []

    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {filepath}")

    for raw_line in lines:
        line = raw_line.strip()

        # Skip empty lines
        if not line:
            continue

        # Skip comments (lines starting with #)
        if line.startswith("#"):
            continue

        # Skip options like -r, -c, -e, --index-url etc.
        if line.startswith("-"):
            continue

        # Skip git/url dependencies
        if line.startswith(("git+", "http://", "https://", "svn+", "hg+")):
            continue

        # Strip inline comments:  requests==2.0  # needed for X
        if " #" in line:
            line = line[:line.index(" #")].strip()

        # Strip any environment markers:  requests; python_version>"3.6"
        if ";" in line:
            line = line[:line.index(";")].strip()

        if line:
            packages.append(line)

    return packages


def parse_package_json(filepath: str) -> list:
    """
    Reads a package.json file and returns a list of
    package name strings for npm scanning.

    Reads both "dependencies" and "devDependencies".

    Handles these version formats:
        "lodash": "^4.17.21"    → "lodash@4.17.21"
        "react": "~18.0.0"      → "react@18.0.0"
        "axios": "*"            → "axios" (latest)
        "axios": "latest"       → "axios"

    Returns list of strings like:
        ["lodash@4.17.21", "react@18.0.0", "axios"]
    """
    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {filepath}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in {filepath}: {e}")

    packages = []

    # Combine both dependency sections
    all_deps = {}
    all_deps.update(data.get("dependencies", {}))
    all_deps.update(data.get("devDependencies", {}))

    for pkg_name, version_spec in all_deps.items():
        # Strip version prefix characters: ^, ~, >=, <=, =
        clean_version = re.sub(r"[^0-9.]", "", version_spec).strip(".")

        if clean_version and clean_version not in ("", "*"):
            packages.append(f"{pkg_name}@{clean_version}")
        else:
            # No specific version → scan latest
            packages.append(pkg_name)

    return packages


def scan_dependencies(filepath: str, max_packages: int = 20) -> dict:
    """
    Main function — parses a dependency file and scans each package.

    Parameters
    ----------
    filepath     : path to requirements.txt or package.json
    max_packages : safety limit (scanning 200 packages would take forever)

    Returns
    -------
    A summary dict with:
        filepath        : the file we scanned
        ecosystem       : 'pip' or 'npm'
        total_packages  : how many packages were found
        scanned         : how many we actually scanned
        skipped         : how many we skipped (over limit)
        results         : list of individual package reports
        summary_score   : average risk score across all packages
        highest_risk    : the single most dangerous package report
        safe_count      : packages with score 0-2
        low_count       : packages with score 3-5
        medium_count    : packages with score 6-8
        high_count      : packages with score 9-10
    """

    # ── Detect file type ──────────────────────────────────
    filename = Path(filepath).name.lower()

    if filename.endswith("requirements.txt"):
        ecosystem = "pip"
        packages  = parse_requirements_txt(filepath)
    elif filename == "package.json":
        ecosystem = "npm"
        packages  = parse_package_json(filepath)
    else:
        raise ValueError(
            f"Unsupported file: {filename}\n"
            f"SafeDev supports: requirements.txt, package.json"
        )

    total_packages = len(packages)

    # ── Apply safety limit ────────────────────────────────
    skipped  = max(0, total_packages - max_packages)
    packages = packages[:max_packages]

    # ── Import scanner (done here to avoid circular imports)
    if ecosystem == "pip":
        from safedev.scanners.package_scanner import scan_pip_package as scan_fn
    else:
        from safedev.scanners.package_scanner import scan_npm_package as scan_fn

    # ── Scan each package ─────────────────────────────────
    results = []

    for i, pkg in enumerate(packages, 1):
        # Strip version specifier to get clean name for display
        clean_name = re.split(r"[=><!@^~]", pkg)[0]

        result = scan_fn(pkg)
        result["package_name"] = clean_name
        result["package_spec"] = pkg       # full spec with version
        results.append(result)

        # Yield progress info as we go (used by CLI for live updates)
        yield {
            "type":     "progress",
            "current":  i,
            "total":    len(packages),
            "package":  clean_name,
            "score":    result.get("score", 0),
            "label":    result.get("risk_label", "UNKNOWN"),
        }

    # ── Build summary ─────────────────────────────────────
    scores = [r.get("score", 0) for r in results]

    safe_count   = sum(1 for s in scores if s <= 2)
    low_count    = sum(1 for s in scores if 3 <= s <= 5)
    medium_count = sum(1 for s in scores if 6 <= s <= 8)
    high_count   = sum(1 for s in scores if s >= 9)

    avg_score = round(sum(scores) / len(scores), 1) if scores else 0.0

    # Sort results: highest score first
    results_sorted = sorted(results, key=lambda r: r.get("score", 0), reverse=True)

    highest_risk = results_sorted[0] if results_sorted else None

    summary = {
        "type":           "summary",
        "filepath":       filepath,
        "ecosystem":      ecosystem,
        "total_packages": total_packages,
        "scanned":        len(packages),
        "skipped":        skipped,
        "results":        results_sorted,
        "summary_score":  avg_score,
        "highest_risk":   highest_risk,
        "safe_count":     safe_count,
        "low_count":      low_count,
        "medium_count":   medium_count,
        "high_count":     high_count,
    }

    yield summary


