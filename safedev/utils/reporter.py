"""
reporter.py
───────────
Formats and prints SafeDev scan results.
Uses behavioral correlation score from rule_engine.
"""

import json
from colorama import Fore, Style
from safedev.utils.rule_engine import score_findings


def build_report(target: str, findings: list, ecosystem: str = None) -> dict:
    """
    Builds a structured report using behavioral correlation scoring.
    Score reflects malware patterns, not raw finding counts.
    """
    score, alerts = score_findings(findings)

    if score == 0:
        risk_label = "SAFE"
    elif score <= 3:
        risk_label = "LOW RISK"
    elif score <= 6:
        risk_label = "MEDIUM RISK"
    else:
        risk_label = "HIGH RISK"

    return {
        "target":         target,
        "ecosystem":      ecosystem,
        "score":          score,
        "risk_label":     risk_label,
        "total_findings": len(findings),
        "findings":       findings,
        "alerts":         alerts,   # high-level malware pattern descriptions
    }


def print_report(report: dict, output_format: str = "text"):
    if output_format == "json":
        print(json.dumps(report, indent=2))
        return

    score      = report["score"]
    risk_label = report["risk_label"]
    findings   = report["findings"]
    alerts     = report.get("alerts", [])
    target     = report["target"]

    if score == 0:
        score_color = Fore.GREEN
    elif score <= 3:
        score_color = Fore.GREEN
    elif score <= 6:
        score_color = Fore.YELLOW + Style.BRIGHT
    else:
        score_color = Fore.RED + Style.BRIGHT

    print()
    print("=" * 62)
    print(f"  {Fore.CYAN}{Style.BRIGHT}SafeDev Scan Report{Style.RESET_ALL}")
    print(f"  Target   : {Fore.WHITE}{target}")
    if report.get("ecosystem"):
        print(f"  Ecosystem: {Fore.WHITE}{report['ecosystem'].upper()}")
    print("-" * 62)
    print(
        f"  {score_color}{Style.BRIGHT}RISK SCORE : {score} / 10   "
        f"[ {risk_label} ]{Style.RESET_ALL}"
    )
    print(f"  Raw findings (individual rule hits): {len(findings)}")
    print("=" * 62)

    # Trusted package
    if report.get("trusted"):
        print(f"\n  {Fore.GREEN}{Style.BRIGHT}✔  TRUSTED PACKAGE{Style.RESET_ALL}")
        print(f"  {report.get('trusted_message', '')}\n")
        return

    # Blocked
    if report.get("blocked"):
        print(f"\n  {Fore.RED}{Style.BRIGHT}✘  BLOCKED{Style.RESET_ALL}")
        print(f"  {report.get('block_reason', '')}\n")
        return

    # Clean
    if score == 0 or not alerts:
        print(f"\n  {Fore.GREEN}{Style.BRIGHT}✔  No malware patterns detected.{Style.RESET_ALL}")
        if findings:
            print(f"  {Fore.GREEN}  ({len(findings)} low-context signals found but no dangerous")
            print(f"   combinations — consistent with legitimate library code.){Style.RESET_ALL}")
        print()
        return

    # Malware alerts (high-level)
    print(f"\n  {Fore.RED}{Style.BRIGHT}⚠  MALWARE PATTERNS DETECTED:{Style.RESET_ALL}\n")
    seen = set()
    for alert in alerts:
        # Show unique pattern labels only (not per-file duplicates)
        label = alert.split(" in ")[0].split(":")[0].strip()
        if label not in seen:
            seen.add(label)
            print(f"  {Fore.RED}  • {label}{Style.RESET_ALL}")
    print()

    # Show only the most suspicious findings (score 4-5 first)
    high_findings = [f for f in findings if f["severity"] >= 4]
    med_findings  = [f for f in findings if f["severity"] == 3]
    show_findings = (high_findings + med_findings)[:15]  # cap at 15

    if show_findings:
        print(f"  {Fore.YELLOW}Top suspicious indicators:\n")
        for i, f in enumerate(show_findings, 1):
            sev   = f["severity"]
            color = Fore.RED if sev >= 4 else Fore.YELLOW
            print(f"  {color}{Style.BRIGHT}[{i}] {f['name']}  (severity: {sev}/5){Style.RESET_ALL}")
            print(f"      Rule    : {f['rule_id']}")
            if f.get("file"):
                loc = f["file"]
                if f.get("line"):
                    loc += f"  line {f['line']}"
                print(f"      Location: {loc}")
            print(f"      Advice  : {Fore.CYAN}{f['advice']}{Style.RESET_ALL}")
            print()

    print("-" * 62 + "\n")
