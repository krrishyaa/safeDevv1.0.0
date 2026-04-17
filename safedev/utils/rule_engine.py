"""
rule_engine.py
──────────────
Loads rules from rules.json and applies them to source files.
Uses per-file behavioral correlation to detect malware patterns.

Key insight:
  - A file with eval() alone = likely legitimate (pandas, etc.)
  - A file with eval() + socket + base64 = likely RAT/malware
  - Scoring is based on COMBINATIONS, not raw hit counts.
"""

import re
import json
import os
from pathlib import Path
from collections import defaultdict


_RULES_PATH = Path(__file__).parent.parent / "rules" / "rules.json"


def load_rules() -> list:
    with open(_RULES_PATH, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return data["rules"]


# ── Behavior tags ──────────────────────────────────────────────
# Each rule is tagged with one or more behavior categories.
# Malware is detected by COMBINATIONS of behaviors in one file.

BEHAVIOR_TAGS = {
    "SD-001": "code_exec",        # eval() with dangerous content
    "SD-002": "code_exec",        # exec()
    "SD-003": "obfuscation",      # base64 decode
    "SD-004": "dynamic_import",   # __import__ of dangerous module
    "SD-005": "shell",            # subprocess / os.system
    "SD-006": "network",          # socket / requests
    "SD-007": "install_script",   # postinstall.js etc.
    "SD-008": "env_harvest",      # os.environ
    "SD-009": "reverse_shell",    # nc -e / /dev/tcp
    "SD-010": "hardcoded_ip",     # 1.2.3.4
    "SD-011": "credentials",      # hardcoded secrets
    "SD-012": "obfuscation",      # hex payload
    "SD-013": "code_exec",        # compile+exec bytecode
    "SD-014": "shell",            # pty / telnetlib
    "SD-015": "reverse_shell",    # curl | bash
}

# ── Malware behavior combinations ─────────────────────────────
# IMPORTANT: These must be tight. Loose combos cause false positives
# on legitimate frameworks (streamlit, django, flask all use
# env vars + network + exec legitimately).
#
# Rules for adding a combo:
#   - Must require 3+ behaviors OR include obfuscation/reverse_shell
#   - "env_harvest + network" alone is NOT enough (every web app does this)
#   - "exec + network" alone is NOT enough (streamlit runs user scripts)
#   - The combo must be something you would NOT find in a normal library

MALWARE_COMBOS = [
    # RAT — needs ALL FOUR: exec + network + obfuscation + shell in one file
    # This is extremely rare in legitimate code
    ({"code_exec", "network", "obfuscation", "shell"},   9, "RAT pattern"),

    # Obfuscated network payload — base64/hex decode + network call + exec
    # Malware hides its C2 URL in base64 then fetches it
    # Uses dynamic_import (not code_exec) to avoid flagging click lazy imports
    ({"code_exec", "network", "obfuscation"},            7, "Obfuscated network payload"),
    # Dynamic import of dangerous module + network = very suspicious
    ({"dynamic_import", "network", "obfuscation"},       8, "Hidden module import with network"),
    ({"dynamic_import", "shell"},                        7, "Hidden module import with shell exec"),

    # Credential stealer — hardcoded secret + outbound network
    # env_harvest alone is normal (every app reads env vars)
    ({"credentials", "network"},                         7, "Credential exfiltration"),
    ({"credentials", "env_harvest", "network"},          8, "Credential stealer"),

    # Reverse shell — always high risk, no combo needed
    ({"reverse_shell"},                                  9, "Reverse shell"),
    ({"reverse_shell", "obfuscation"},                  10, "Obfuscated reverse shell"),

    # Obfuscated shell — ONLY flag if obfuscation + shell + network together
    # numpy uses obfuscation+shell to build Fortran extensions (legitimate)
    # but nobody needs obfuscation+shell+network except malware
    ({"obfuscation", "shell", "network"},                8, "Obfuscated shell with network"),

    # Malicious install script — must combine network AND shell AND install_script
    # setup.cfg alone is fine; only flag if it also does network+shell
    ({"install_script", "network", "shell"},             8, "Malicious install script"),

    # Hardcoded C2 — IP + reverse shell is always bad
    ({"hardcoded_ip", "reverse_shell"},                  9, "C2 reverse shell"),
    # IP + obfuscation + shell = C2 callback hiding its address
    ({"hardcoded_ip", "shell", "obfuscation"},           8, "C2 shell callback"),
]

# ── Context: files/paths that lower suspicion ─────────────────
# Files in these folders get half score even if combos match.
LOW_RISK_PATHS = {
    # Test / docs / examples
    "test", "tests", "spec", "specs", "docs", "doc",
    "examples", "example", "demo", "demos", "fixtures",
    "migrations", "benchmark", "benchmarks",
    # Build / compiled / bundled output — not source code
    "static", "dist", "build", "vendor", "assets", "public",
    # Protobuf generated files — full of hex constants, not malware
    "proto", "_pb2",
    # Scientific / compiler tooling — numpy f2py, cython etc.
    # These legitimately compile and exec Fortran/C code
    "f2py", "_backends", "_build_utils", "meson",
    # Package build configs — not executable install scripts
    "setup.cfg", "_setup",
}


def _is_low_risk_path(filepath: str) -> bool:
    """True if the file lives in a test/docs/static/generated folder."""
    parts  = set(Path(filepath).parts)
    name   = Path(filepath).stem.lower()
    # Check folder names
    if parts & LOW_RISK_PATHS:
        return True
    # Check file name patterns (e.g. Block_pb2.py, Element_pb2.py)
    if name.endswith("_pb2") or name.endswith(".min"):
        return True
    # Minified JS bundles (filename contains hash like BwU7eQR9)
    if re.search(r"\.[a-zA-Z0-9]{8}\.(js|css)$", filepath):
        return True
    return False





def _get_behaviors(findings: list) -> set:
    """Get the set of behavior tags triggered by a list of findings."""
    tags = set()
    for f in findings:
        tag = BEHAVIOR_TAGS.get(f["rule_id"])
        if tag:
            tags.add(tag)
    return tags


def scan_content(content: str, filename: str, rules: list) -> list:
    """
    Applies all rules to a single file's content.
    Returns a list of raw finding dicts.
    """
    findings = []
    ext      = Path(filename).suffix.lower()
    basename = Path(filename).name.lower()

    for rule in rules:
        rule_type  = rule["type"]
        file_types = rule.get("file_types", ["*"])

        applies = (
            "*" in file_types
            or ext in file_types
        )
        if not applies:
            continue

        # Filename rule
        if rule_type == "filename":
            pattern = rule["pattern"]
            if re.search(pattern, basename, re.IGNORECASE):
                findings.append({
                    "rule_id":     rule["id"],
                    "name":        rule["name"],
                    "severity":    rule["severity"],
                    "file":        filename,
                    "line":        None,
                    "description": rule["description"],
                    "advice":      rule["advice"],
                    "match":       basename,
                    "behaviors":   [BEHAVIOR_TAGS.get(rule["id"], "other")],
                })
            continue

        # Regex rule
        try:
            compiled = re.compile(rule["pattern"], re.IGNORECASE)
        except re.error:
            continue

        for lineno, line in enumerate(content.splitlines(), start=1):
            match = compiled.search(line)
            if match:
                findings.append({
                    "rule_id":     rule["id"],
                    "name":        rule["name"],
                    "severity":    rule["severity"],
                    "file":        filename,
                    "line":        lineno,
                    "description": rule["description"],
                    "advice":      rule["advice"],
                    "match":       match.group(0),
                    "behaviors":   [BEHAVIOR_TAGS.get(rule["id"], "other")],
                })
                break  # one hit per rule per file

    return findings


def score_findings(all_findings: list) -> tuple[int, list]:
    """
    Scores findings using per-file behavioral correlation.

    Returns (final_score_0_to_10, list_of_alerts)
    where alerts are high-level malware pattern descriptions.

    Logic:
      - Group findings by file
      - For each file, check which malware combos match
      - Files in test/docs folders get half score
      - Take the MAX single-file score (not sum across all files)
      - Individual rare signals (reverse shell, install script)
        also contribute even without combos
    """
    # Group by file
    by_file = defaultdict(list)
    for f in all_findings:
        by_file[f["file"]].append(f)

    file_scores  = []  # (score, file, alert_label)
    alerts       = []

    for filepath, findings in by_file.items():
        behaviors     = _get_behaviors(findings)
        low_risk_path = _is_low_risk_path(filepath)
        file_score    = 0
        file_alerts   = []

        # Check combos
        for (combo, combo_score, label) in MALWARE_COMBOS:
            if combo.issubset(behaviors):
                adjusted = combo_score // 2 if low_risk_path else combo_score
                if adjusted > file_score:
                    file_score = adjusted
                file_alerts.append(f"{label} in {filepath}")

        # Individual high-severity signals that don't need combos
        for f in findings:
            if f["rule_id"] in ("SD-009", "SD-015"):  # reverse shell / curl|bash
                s = 9 if not low_risk_path else 4
                if s > file_score:
                    file_score = s
                file_alerts.append(f"Reverse shell indicator in {filepath}")
            elif f["rule_id"] == "SD-007":            # install script
                s = 6 if not low_risk_path else 3
                if s > file_score:
                    file_score = s
                file_alerts.append(f"Suspicious install script: {filepath}")
            elif f["rule_id"] == "SD-011":            # hardcoded credentials
                s = 5 if not low_risk_path else 2
                if s > file_score:
                    file_score = s
                file_alerts.append(f"Hardcoded credentials in {filepath}")

        if file_score > 0:
            file_scores.append((file_score, filepath, file_alerts))
            alerts.extend(file_alerts)

    # Final score = highest single-file score (malware lives in one file)
    final_score = max((s for s, _, _ in file_scores), default=0)
    final_score = min(10, final_score)

    return final_score, list(dict.fromkeys(alerts))  # deduplicated


def scan_directory(directory: str, rules: list) -> list:
    """
    Walks a directory recursively and scans every text file.
    Returns flat list of all raw findings.
    """
    all_findings = []

    SKIP_DIRS = {".git", "__pycache__", "node_modules", ".tox",
                 "venv", ".venv", "env", "dist", "build", ".eggs"}

    TEXT_EXTENSIONS = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".sh", ".bash",
        ".rb", ".php", ".go", ".rs", ".java", ".c", ".cpp",
        ".h", ".hpp", ".cs", ".cfg", ".ini", ".env", ".toml",
        ".yaml", ".yml", ".json", ".xml", ".html", ".htm",
        ".txt", ".md", ".bat", ".ps1",
    }

    MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for fname in files:
            filepath = os.path.join(root, fname)
            ext = Path(fname).suffix.lower()

            try:
                if os.path.getsize(filepath) > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue

            if ext not in TEXT_EXTENSIONS:
                continue

            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except OSError:
                continue

            rel_path = os.path.relpath(filepath, directory)
            findings = scan_content(content, rel_path, rules)
            all_findings.extend(findings)

    return all_findings
