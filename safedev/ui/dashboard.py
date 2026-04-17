"""
dashboard.py
────────────
SafeDev Streamlit web dashboard
Features:
  - Scan pip packages, npm packages, git repos, local directories
  - Scan history saved to scan_history.json
  - Downloadable PDF or fallback text report
  - Risk gauge, findings summary, command explorer, history insights
Launch: safedev ui
"""

import json
from collections import Counter
from datetime import datetime
from pathlib import Path

import streamlit as st

from safedev.scanners.package_scanner import scan_npm_package, scan_pip_package
from safedev.scanners.repo_scanner import scan_local_directory, scan_repo

BASE_DIR = Path(__file__).resolve().parent.parent.parent
HISTORY_FILE = BASE_DIR / "scan_history.json"

CLI_COMMANDS = {
    "Scanning & analysis": [
        {
            "command": "scan",
            "summary": "Scan a local directory for suspicious files and patterns.",
            "example": "safedev scan ./my-project",
        },
        {
            "command": "scan-deps",
            "summary": "Scan packages listed in requirements.txt or package.json.",
            "example": "safedev scan-deps requirements.txt --threshold 3",
        },
        {
            "command": "clone",
            "summary": "Scan a Git repository before cloning it locally.",
            "example": "safedev clone https://github.com/user/repo --threshold 5",
        },
        {
            "command": "check",
            "summary": "Check installed dependency health or run npm audit behavior.",
            "example": "safedev check --ecosystem npm",
        },
        {
            "command": "audit",
            "summary": "Run npm security audit on the current project.",
            "example": "safedev audit",
        },
    ],
    "Safe install workflow": [
        {
            "command": "install",
            "summary": "Pre-scan packages before installing from pip or npm.",
            "example": "safedev install requests",
        },
        {
            "command": "upgrade",
            "summary": "Pre-scan packages before upgrading to newer versions.",
            "example": "safedev upgrade axios --ecosystem npm",
        },
        {
            "command": "uninstall",
            "summary": "Remove one or more packages from pip or npm.",
            "example": "safedev uninstall flask --yes",
        },
        {
            "command": "install-deps",
            "summary": "Scan dependency files and install only packages within threshold.",
            "example": "safedev install-deps requirements.txt --yes",
        },
    ],
    "Package inventory": [
        {
            "command": "list",
            "summary": "List installed packages or outdated packages.",
            "example": "safedev list --outdated",
        },
        {
            "command": "show",
            "summary": "Show metadata for an installed package.",
            "example": "safedev show requests",
        },
        {
            "command": "freeze",
            "summary": "Output installed pip packages in requirements format.",
            "example": "safedev freeze > requirements.txt",
        },
    ],
    "General & UI": [
        {
            "command": "version",
            "summary": "Display SafeDev, Python, pip, npm, node, and git versions.",
            "example": "safedev version",
        },
        {
            "command": "run",
            "summary": "Run an npm script from package.json.",
            "example": "safedev run build",
        },
        {
            "command": "ui",
            "summary": "Launch this Streamlit dashboard in the browser.",
            "example": "safedev ui",
        },
    ],
}

SCAN_MODE_INFO = {
    "pip": {
        "title": "🐍 pip package",
        "hint": "Scan a PyPI-style package name before installation or upgrade.",
        "placeholder": "requests or numpy==1.26.0",
        "button": "🔍 Scan pip Package",
        "spinner": "Scanning pip package",
    },
    "npm": {
        "title": "📦 npm package",
        "hint": "Check an npm package or exact version tag before using it.",
        "placeholder": "axios or lodash@4.17.21",
        "button": "🔍 Scan npm Package",
        "spinner": "Scanning npm package",
    },
    "git": {
        "title": "🔗 Git repository",
        "hint": "Clone to a temporary directory and inspect repository contents safely.",
        "placeholder": "https://github.com/user/repo",
        "button": "🔍 Scan Repository",
        "spinner": "Cloning and scanning repository",
    },
    "local": {
        "title": "📁 Local directory",
        "hint": "Review an existing local project, extracted package, or source folder.",
        "placeholder": r"C:\projects\my-app or ./my-project",
        "button": "🔍 Scan Directory",
        "spinner": "Scanning local directory",
    },
}

st.set_page_config(
    page_title="SafeDev",
    page_icon="🔒",
    layout="wide",
)

st.markdown(
    """
<style>
    .stApp {
        background:
            radial-gradient(circle at top left, rgba(124, 232, 160, 0.08), transparent 24%),
            radial-gradient(circle at 85% 10%, rgba(110, 231, 249, 0.10), transparent 22%),
            radial-gradient(circle at 80% 80%, rgba(139, 92, 246, 0.08), transparent 20%),
            #050816;
    }
    .hero-card {
        border: 1px solid rgba(120, 120, 160, 0.25);
        border-radius: 24px;
        padding: 1.5rem 1.6rem;
        background: linear-gradient(135deg, rgba(11, 17, 32, 0.96), rgba(13, 65, 84, 0.68));
        box-shadow: 0 0 0 1px rgba(110, 231, 249, 0.05), 0 24px 100px rgba(4, 8, 24, 0.48);
        margin-bottom: 1rem;
    }
    .soft-card {
        border: 1px solid rgba(120, 120, 160, 0.18);
        border-radius: 18px;
        padding: 1rem 1.1rem;
        background: rgba(255, 255, 255, 0.03);
        margin-bottom: 0.9rem;
    }
    .safedev-mark {
        display: inline-flex;
        align-items: center;
        gap: 0.55rem;
        padding: 0.4rem 0.85rem;
        border-radius: 999px;
        border: 1px solid rgba(124, 232, 160, 0.22);
        background: rgba(124, 232, 160, 0.08);
        color: #7ce8a0;
        font-size: 0.78rem;
        letter-spacing: 0.18em;
        text-transform: uppercase;
        margin-bottom: 0.75rem;
    }
    .muted-text {
        color: #b8c0d4;
    }
    .risk-safe     { color: #00c853; font-size: 1.35em; font-weight: 700; }
    .risk-low      { color: #64dd17; font-size: 1.35em; font-weight: 700; }
    .risk-medium   { color: #ffb300; font-size: 1.35em; font-weight: 700; }
    .risk-high     { color: #ff6d00; font-size: 1.35em; font-weight: 700; }
    .risk-blocked  { color: #d50000; font-size: 1.35em; font-weight: 700; }
    .gauge-box     { border-radius: 16px; padding: 20px; text-align: center; margin-bottom: 10px; }
    .alert-card    { border-left: 4px solid #d50000; padding: 8px 12px; margin: 6px 0; border-radius: 8px; background: rgba(213, 0, 0, 0.12); }
    .command-chip {
        display: inline-block;
        background: rgba(0, 200, 83, 0.14);
        border: 1px solid rgba(0, 200, 83, 0.25);
        color: #ccffd8;
        padding: 0.2rem 0.55rem;
        border-radius: 999px;
        font-size: 0.82rem;
        margin-right: 0.4rem;
        margin-bottom: 0.4rem;
    }
</style>
""",
    unsafe_allow_html=True,
)


def load_history() -> list:
    if HISTORY_FILE.exists():
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as file:
                return json.load(file)
        except Exception:
            return []
    return []


def save_to_history(report: dict):
    history = load_history()
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": report.get("target", "unknown"),
        "ecosystem": report.get("ecosystem", ""),
        "score": report.get("score", 0),
        "risk_label": report.get("risk_label", ""),
        "findings": len(report.get("findings", [])),
        "alerts": report.get("alerts", []),
        "blocked": report.get("blocked", False),
    }
    history.insert(0, entry)
    history = history[:50]
    with open(HISTORY_FILE, "w", encoding="utf-8") as file:
        json.dump(history, file, indent=2)


def clear_history():
    if HISTORY_FILE.exists():
        HISTORY_FILE.unlink()


def summarize_history(history: list) -> dict:
    scores = [entry.get("score", 0) for entry in history]
    blocked_count = sum(1 for entry in history if entry.get("blocked"))
    ecosystems = Counter((entry.get("ecosystem") or "unknown").lower() for entry in history)
    top_ecosystem = ecosystems.most_common(1)[0][0] if ecosystems else "n/a"
    avg_score = round(sum(scores) / len(scores), 1) if scores else 0.0
    return {
        "total": len(history),
        "blocked": blocked_count,
        "average": avg_score,
        "top_ecosystem": top_ecosystem.upper(),
    }


def build_findings_table(findings: list) -> list:
    rows = []
    for item in findings:
        location = item.get("file", "")
        if item.get("line"):
            location = f"{location}:{item['line']}"
        rows.append(
            {
                "Rule": item.get("rule_id", ""),
                "Name": item.get("name", ""),
                "Severity": item.get("severity", 0),
                "Location": location,
            }
        )
    return rows


def build_command_rows() -> list:
    rows = []
    for group, commands in CLI_COMMANDS.items():
        for item in commands:
            rows.append(
                {
                    "Group": group,
                    "Command": f"safedev {item['command']}",
                    "What it does": item["summary"],
                    "Example": item["example"],
                }
            )
    return rows


def build_pdf_bytes(report: dict) -> bytes:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
        import io

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            leftMargin=2 * cm,
            rightMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
        )
        styles = getSampleStyleSheet()
        story = []

        score = report.get("score", 0)
        if score == 0:
            risk_color = colors.HexColor("#00c853")
        elif score <= 3:
            risk_color = colors.HexColor("#64dd17")
        elif score <= 6:
            risk_color = colors.HexColor("#ffab00")
        else:
            risk_color = colors.HexColor("#d50000")

        title_style = ParagraphStyle("title", parent=styles["Title"], textColor=colors.HexColor("#1a237e"), fontSize=22)
        story.append(Paragraph("SafeDev Security Scan Report", title_style))
        story.append(Spacer(1, 0.3 * cm))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1a237e")))
        story.append(Spacer(1, 0.4 * cm))

        meta = [
            ["Target", report.get("target", "")],
            ["Ecosystem", report.get("ecosystem", "").upper()],
            ["Scanned", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["Risk Score", f"{score} / 10"],
            ["Risk Level", report.get("risk_label", "")],
            ["Raw Findings", str(len(report.get("findings", [])))],
        ]
        table = Table(meta, colWidths=[4 * cm, 12 * cm])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e8eaf6")),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                    ("PADDING", (0, 0), (-1, -1), 6),
                    ("TEXTCOLOR", (1, 3), (1, 3), risk_color),
                    ("TEXTCOLOR", (1, 4), (1, 4), risk_color),
                    ("FONTNAME", (1, 3), (1, 4), "Helvetica-Bold"),
                ]
            )
        )
        story.append(table)
        story.append(Spacer(1, 0.5 * cm))

        if report.get("blocked"):
            blocked_style = ParagraphStyle(
                "blocked",
                parent=styles["Normal"],
                textColor=colors.red,
                fontSize=13,
                fontName="Helvetica-Bold",
            )
            story.append(Paragraph(f"INSTALLATION BLOCKED: {report.get('block_reason', '')}", blocked_style))
            story.append(Spacer(1, 0.3 * cm))

        alerts = report.get("alerts", [])
        if alerts:
            story.append(Paragraph("Malware Patterns Detected", styles["Heading2"]))
            for alert in set(a.split(" in ")[0].split(":")[0].strip() for a in alerts):
                story.append(Paragraph(f"• {alert}", styles["Normal"]))
            story.append(Spacer(1, 0.4 * cm))

        findings = report.get("findings", [])
        if findings:
            story.append(Paragraph("Detailed Findings", styles["Heading2"]))
            story.append(Spacer(1, 0.2 * cm))

            rows = [["#", "Rule", "Name", "Severity", "Location"]]
            for index, item in enumerate(findings[:30], 1):
                location = item.get("file", "")
                if item.get("line"):
                    location += f" :{item['line']}"
                rows.append(
                    [
                        str(index),
                        item.get("rule_id", ""),
                        item.get("name", "")[:40],
                        f"{item.get('severity', 0)}/5",
                        location[:50],
                    ]
                )

            findings_table = Table(rows, colWidths=[0.8 * cm, 2 * cm, 5.5 * cm, 1.5 * cm, 7.2 * cm])
            findings_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a237e")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
                        ("BOX", (0, 0), (-1, -1), 0.5, colors.grey),
                        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                        ("PADDING", (0, 0), (-1, -1), 4),
                    ]
                )
            )
            story.append(findings_table)

            if len(findings) > 30:
                story.append(Spacer(1, 0.2 * cm))
                story.append(
                    Paragraph(
                        f"... and {len(findings) - 30} more findings. Run safedev in CLI for full output.",
                        styles["Normal"],
                    )
                )
        else:
            story.append(
                Paragraph(
                    "✔ No suspicious patterns detected.",
                    ParagraphStyle(
                        "safe",
                        parent=styles["Normal"],
                        textColor=colors.HexColor("#00c853"),
                        fontSize=12,
                        fontName="Helvetica-Bold",
                    ),
                )
            )

        story.append(Spacer(1, 1 * cm))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.grey))
        story.append(Spacer(1, 0.2 * cm))
        story.append(
            Paragraph(
                "Generated by SafeDev — Universal Developer Security Tool",
                ParagraphStyle("footer", parent=styles["Normal"], textColor=colors.grey, fontSize=8),
            )
        )

        doc.build(story)
        return buffer.getvalue()

    except ImportError:
        lines = [
            "SafeDev Security Scan Report",
            "=" * 50,
            f"Target    : {report.get('target', '')}",
            f"Ecosystem : {report.get('ecosystem', '')}",
            f"Score     : {report.get('score', 0)} / 10",
            f"Risk      : {report.get('risk_label', '')}",
            f"Findings  : {len(report.get('findings', []))}",
            "",
            "Install reportlab for PDF: pip install reportlab",
        ]
        return "\n".join(lines).encode("utf-8")


def render_gauge(score: int, risk_label: str, blocked: bool):
    if blocked:
        color, icon, css = "#d50000", "🛑", "risk-blocked"
    elif score == 0:
        color, icon, css = "#00c853", "✅", "risk-safe"
    elif score <= 3:
        color, icon, css = "#64dd17", "✔", "risk-low"
    elif score <= 6:
        color, icon, css = "#ffab00", "⚠️", "risk-medium"
    else:
        color, icon, css = "#ff6d00", "🚨", "risk-high"

    pct = max(0, min(score * 10, 100))
    st.markdown(
        f"""
        <div class="gauge-box" style="background:{color}22; border: 2px solid {color};">
            <div class="{css}">{icon} {risk_label} — {score}/10</div>
            <div style="background:#333; border-radius:8px; height:16px; margin-top:10px;">
                <div style="background:{color}; width:{pct}%; height:16px; border-radius:8px; transition:width 0.5s;"></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def severity_badge(severity: int) -> str:
    if severity >= 4:
        return "🔴 Critical"
    if severity >= 3:
        return "🟠 Elevated"
    if severity >= 2:
        return "🟡 Moderate"
    return "🟢 Low"


def run_selected_scan(scan_mode: str, target: str):
    if scan_mode == "pip":
        return scan_pip_package(target)
    if scan_mode == "npm":
        return scan_npm_package(target)
    if scan_mode == "git":
        report = scan_repo(target)
        report.pop("_tmp_dir", None)
        return report
    return scan_local_directory(target)


def render_sidebar():
    st.sidebar.markdown("## 🔧 SafeDev")
    st.sidebar.caption("SafeDev dashboard for fast reviews in Streamlit, then switch to CLI for scripting and CI.")

    history = load_history()
    summary = summarize_history(history)

    st.sidebar.markdown("### Quick actions")
    st.sidebar.code("safedev ui", language="bash")
    st.sidebar.code("safedev scan ./project", language="bash")
    st.sidebar.code("safedev install requests", language="bash")

    st.sidebar.markdown("### History snapshot")
    c1, c2 = st.sidebar.columns(2)
    c1.metric("Scans", summary["total"])
    c2.metric("Blocked", summary["blocked"])
    c3, c4 = st.sidebar.columns(2)
    c3.metric("Avg risk", summary["average"])
    c4.metric("Top eco", summary["top_ecosystem"])

    st.sidebar.markdown("### Scan tips")
    st.sidebar.info(
        "Start with a package name, repo URL, or local path. Thresholds above 5 are more permissive; lower thresholds are stricter."
    )

    if not history:
        st.sidebar.markdown("### Recent scans")
        st.sidebar.info("No scans yet. Run your first SafeDev scan to populate history.")
        return

    if st.sidebar.button("🗑 Clear History", use_container_width=True):
        clear_history()
        st.rerun()

    st.sidebar.markdown("### Recent scans")
    for entry in history[:8]:
        score = entry.get("score", 0)
        if entry.get("blocked"):
            icon = "🛑"
        elif score == 0:
            icon = "✅"
        elif score <= 3:
            icon = "🟢"
        elif score <= 6:
            icon = "🟡"
        else:
            icon = "🔴"

        st.sidebar.markdown(
            f"{icon} **{entry.get('target', 'unknown')}**  \n"
            f"`{entry.get('ecosystem', '').upper() or 'N/A'}` • `{score}/10`  \n"
            f"<small>{entry.get('timestamp', '')}</small>",
            unsafe_allow_html=True,
        )
        st.sidebar.divider()


def render_intro(history: list):
    history_summary = summarize_history(history)
    st.markdown(
        """
        <div class="hero-card">
            <div class="safedev-mark">🔒 SafeDev</div>
            <h2 style="margin-bottom:0.3rem;">SafeDev Supply Chain Security Dashboard</h2>
            <p style="margin-bottom:0.6rem;">
                Review packages and repositories <strong>before</strong> you install, clone, or trust them.
                This dashboard keeps the core SafeDev scanners intact while giving you a faster visual workflow.
            </p>
            <div>
                <span class="command-chip">pip packages</span>
                <span class="command-chip">npm packages</span>
                <span class="command-chip">git repositories</span>
                <span class="command-chip">local directories</span>
                <span class="command-chip">CLI command explorer</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Supported scan modes", "4")
    m2.metric("CLI commands showcased", str(len(build_command_rows())))
    m3.metric("Saved scan history", history_summary["total"])
    m4.metric("Average historic risk", history_summary["average"])


def render_scan_workspace():
    st.markdown("### 🧪 SafeDev scan workspace")
    st.caption("Pick a target type, set a threshold, and run a scan. Results will appear below and be saved to local history.")

    tabs = st.tabs(["🐍 pip Package", "📦 npm Package", "🔗 Git Repository", "📁 Local Directory"])
    selected_scan = None
    tab_map = [("pip", tabs[0]), ("npm", tabs[1]), ("git", tabs[2]), ("local", tabs[3])]

    for key, tab in tab_map:
        info = SCAN_MODE_INFO[key]
        with tab:
            st.markdown(f"#### {info['title']}")
            st.caption(info["hint"])
            target = st.text_input("Target", placeholder=info["placeholder"], key=f"{key}_target")
            threshold = st.slider(
                "Risk threshold",
                0,
                10,
                5,
                key=f"{key}_threshold",
                help="If the resulting score is above this threshold, treat the target as unsafe.",
            )
            run_clicked = st.button(
                info["button"],
                type="primary",
                disabled=not target,
                key=f"{key}_run",
                use_container_width=True,
            )

            if not target:
                st.info("Enter a value to enable scanning.")
            else:
                st.caption(f"Ready to scan: `{target}`")

            if run_clicked:
                selected_scan = {
                    "mode": key,
                    "target": target,
                    "threshold": threshold,
                    "spinner": info["spinner"],
                }

    return selected_scan


def render_command_explorer():
    st.markdown("### 🧭 Command explorer")
    st.caption("The dashboard is a visual companion to the SafeDev CLI. Use these commands in terminals, scripts, or CI pipelines.")

    command_rows = build_command_rows()
    st.dataframe(command_rows, hide_index=True, use_container_width=True)

    groups = st.tabs(list(CLI_COMMANDS.keys()))
    for group_tab, (group_name, items) in zip(groups, CLI_COMMANDS.items()):
        with group_tab:
            st.markdown(f"#### {group_name}")
            for item in items:
                st.markdown(
                    f"""
                    <div class="soft-card">
                        <strong>safedev {item['command']}</strong><br>
                        <span class="muted-text">{item['summary']}</span>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                st.code(item["example"], language="bash")


def render_empty_state():
    st.markdown("### Ready when you are")
    col1, col2 = st.columns([1.2, 1])
    with col1:
        st.info("No active scan results yet. Use one of the scan tabs above to inspect a package, repository, or local directory.")
        st.markdown(
            """
            **Good first checks**
            - `safedev install requests`
            - `safedev clone https://github.com/user/repo`
            - `safedev scan ./my-project`
            - `safedev scan-deps requirements.txt`
            """
        )
    with col2:
        st.markdown(
            """
            <div class="soft-card">
                <strong>What the score means</strong><br><br>
                0 = clean signal<br>
                1-3 = low concern<br>
                4-6 = investigate further<br>
                7-10 = high risk / likely unsafe
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_report(report: dict, threshold: int):
    score = report.get("score", 0)
    risk = report.get("risk_label", "")
    findings = report.get("findings", [])
    alerts = report.get("alerts", [])
    blocked = report.get("blocked", False)

    st.markdown("## 📋 Scan results")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Risk Score", f"{score} / 10")
    c2.metric("Risk Level", risk or "Unknown")
    c3.metric("Raw Findings", len(findings))
    c4.metric("Malware Alerts", len(set(alert.split(" in ")[0].split(":")[0].strip() for alert in alerts)))

    summary_col, meta_col = st.columns([1.3, 1])
    with summary_col:
        st.markdown("### Risk assessment")
        render_gauge(score, risk or "Unknown", blocked)
        if blocked:
            st.error(f"🛑 BLOCKED: {report.get('block_reason', 'Blocked by SafeDev policy.')}")
        elif score > threshold:
            st.error(f"🚨 Score {score} exceeds your threshold of {threshold}. Avoid installing or trusting this target.")
        else:
            st.success(f"✅ Score {score} is within your threshold of {threshold}.")

    with meta_col:
        st.markdown("### Scan metadata")
        st.markdown(
            f"""
            <div class="soft-card">
                <strong>Target</strong><br>{report.get('target', 'unknown')}<br><br>
                <strong>Ecosystem</strong><br>{(report.get('ecosystem', '') or 'n/a').upper()}<br><br>
                <strong>Blocked</strong><br>{'Yes' if blocked else 'No'}
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.divider()

    if alerts:
        st.markdown("### ⚠️ Malware patterns detected")
        unique_alerts = list(dict.fromkeys(alert.split(" in ")[0].split(":")[0].strip() for alert in alerts))
        for alert in unique_alerts:
            st.markdown(f'<div class="alert-card">🔴 {alert}</div>', unsafe_allow_html=True)
        st.divider()

    if findings:
        st.markdown("### 📊 Findings breakdown")
        severity_counts = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
        for item in findings:
            severity = item.get("severity", 1)
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        rule_counts = Counter(item.get("rule_id", "unknown") for item in findings)

        chart_col, rules_col = st.columns(2)
        with chart_col:
            chart_rows = [{"Severity": f"Severity {level}", "Count": count} for level, count in severity_counts.items() if count > 0]
            if chart_rows:
                st.bar_chart(chart_rows, x="Severity", y="Count")
            else:
                st.info("No severity data available for charting.")

        with rules_col:
            top_rules = [{"Rule": rule, "Hits": hits} for rule, hits in rule_counts.most_common(8)]
            st.dataframe(top_rules, hide_index=True, use_container_width=True)

        st.divider()

        st.markdown("### 🔎 Detailed findings")
        filter_col, table_col = st.columns([1, 2])
        with filter_col:
            severity_filter = st.select_slider(
                "Minimum severity",
                options=[1, 2, 3, 4, 5],
                value=1,
                help="Only show findings at or above the selected severity.",
            )
            filtered_findings = [item for item in findings if item.get("severity", 1) >= severity_filter]
            st.caption(f"Showing {len(filtered_findings)} of {len(findings)} findings")

        with table_col:
            st.dataframe(build_findings_table(filtered_findings), hide_index=True, use_container_width=True)

        for item in filtered_findings:
            severity = item.get("severity", 1)
            with st.expander(f"{severity_badge(severity)} [{item.get('rule_id', '?')}] {item.get('name', 'Unnamed finding')}"):
                if item.get("file"):
                    location = item["file"]
                    if item.get("line"):
                        location += f" — line {item['line']}"
                    st.markdown(f"**Location:** `{location}`")
                if item.get("match"):
                    st.code(item["match"], language="text")
                st.markdown(f"**Why it matters:** {item.get('description', 'No description provided.')}")
                st.markdown(f"**Advice:** {item.get('advice', 'No advice provided.')}")

    else:
        st.success("✅ No suspicious patterns found in this target.")
        st.markdown(
            """
            <div class="soft-card">
                SafeDev did not detect suspicious rules in this scan. That is a strong positive signal,
                but you should still combine it with normal dependency hygiene such as version pinning,
                lockfiles, source review, and CI checks.
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.divider()

    st.markdown("### 📄 Export report")
    pdf_bytes = build_pdf_bytes(report)
    base_name = str(report.get("target", "scan")).replace("/", "_").replace("\\", "_").replace(":", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pdf_name = f"safedev_{base_name}_{timestamp}.pdf"
    json_name = f"safedev_{base_name}_{timestamp}.json"

    download_col1, download_col2 = st.columns(2)
    with download_col1:
        st.download_button(
            label="⬇️ Download PDF Report",
            data=pdf_bytes,
            file_name=pdf_name,
            mime="application/pdf",
            type="primary",
            use_container_width=True,
        )
    with download_col2:
        st.download_button(
            label="⬇️ Download JSON Report",
            data=json.dumps(report, indent=2),
            file_name=json_name,
            mime="application/json",
            use_container_width=True,
        )

    with st.expander("View raw JSON report"):
        st.json(report)


render_sidebar()
history = load_history()

render_intro(history)
selected_scan = render_scan_workspace()
st.divider()
render_command_explorer()
st.divider()

report = None
threshold = 5

if selected_scan:
    threshold = selected_scan["threshold"]
    target = selected_scan["target"]
    mode = selected_scan["mode"]
    with st.spinner(f"{selected_scan['spinner']}: {target}"):
        try:
            report = run_selected_scan(mode, target)
        except Exception as exc:
            st.error(f"Scan failed: {exc}")

if report:
    if report.get("error"):
        st.error(f"Error: {report['error']}")
    else:
        save_to_history(report)
        render_report(report, threshold)
else:
    render_empty_state()
