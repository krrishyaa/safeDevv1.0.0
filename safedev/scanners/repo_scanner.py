"""
repo_scanner.py
───────────────
Clones a Git repository into a TEMPORARY directory,
scans every file in it, then cleans up.

The real clone to the user's working directory only happens
AFTER the user approves the scan results.
"""

import os
import shutil
import tempfile
import subprocess

from safedev.utils.rule_engine import load_rules, scan_directory
from safedev.utils.reporter   import build_report


def scan_repo(repo_url: str) -> dict:
    """
    Clone repo_url into a temp dir, scan all files, return report.

    Parameters
    ----------
    repo_url : full git URL, e.g. https://github.com/user/project

    Returns
    -------
    Report dict from reporter.build_report()
    Plus a 'tmp_dir' key so the caller can do the real clone from it.
    """
    rules   = load_rules()
    tmp_dir = tempfile.mkdtemp(prefix="safedev_repo_")

    try:
        # ── Step 1: Shallow clone into temp dir ───────────
        # --depth 1 means we only fetch the latest commit.
        # This is faster and uses less disk space.
        result = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, tmp_dir],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            return {
                "target":   repo_url,
                "ecosystem": None,
                "score":    0,
                "risk_label": "ERROR",
                "total_findings": 0,
                "findings": [],
                "error": result.stderr.strip(),
            }

        # ── Step 2: Scan all files in the cloned repo ─────
        findings = scan_directory(tmp_dir, rules)
        report   = build_report(repo_url, findings, ecosystem=None)

        # Attach tmp_dir so cli.py can do the real clone later
        report["_tmp_dir"] = tmp_dir
        return report

    except Exception as exc:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return {
            "target":   repo_url,
            "ecosystem": None,
            "score":    0,
            "risk_label": "ERROR",
            "total_findings": 0,
            "findings": [],
            "error":    str(exc),
        }


def scan_local_directory(path: str) -> dict:
    """
    Scan a directory that already exists on disk (no cloning).
    Used by `safedev scan <path>`.
    """
    rules    = load_rules()
    findings = scan_directory(path, rules)
    return build_report(path, findings, ecosystem=None)
