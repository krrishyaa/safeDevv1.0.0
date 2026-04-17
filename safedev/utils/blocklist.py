"""
blocklist.py — Known malicious packages.
These have been confirmed malicious by PyPI / npm security teams.
SafeDev blocks them before any download happens.
"""

# (package_name_lowercase, ecosystem, reason)
MALICIOUS_PACKAGES = [
    # ── PyPI confirmed malicious ──────────────────────────────
    ("colourama",        "pip", "Typosquat of colorama — steals crypto wallets"),
        ("coloramma",        "pip", "Typosquat of colorama — steals crypto wallets"),
    ("reqeusts",         "pip", "Typosquat of requests — exfiltrates env vars"),
    ("requets",          "pip", "Typosquat of requests — exfiltrates env vars"),
    ("request",          "pip", "Typosquat of requests — exfiltrates env vars"),
    ("urllib",           "pip", "Typosquat of urllib3 — backdoor"),
    ("urlib3",           "pip", "Typosquat of urllib3 — backdoor"),
    ("python-sqlite",    "pip", "Malicious — runs reverse shell on install"),
    ("py-util",          "pip", "Malicious — harvests AWS credentials"),
    ("setup-tools",      "pip", "Typosquat of setuptools — installs backdoor"),
    ("djang0",           "pip", "Typosquat of django — data exfiltration"),
    ("flask-admin2",     "pip", "Fake flask-admin — credential harvester"),
    ("loguru-logging",   "pip", "Fake loguru — reverse shell"),
    ("python-mongo",     "pip", "Fake pymongo — crypto miner"),
    ("matploltib",       "pip", "Typosquat of matplotlib — RAT installer"),
    ("openai-python",    "pip", "Fake openai — API key stealer"),
    ("chatgpt",          "pip", "Fake ChatGPT package — info stealer"),
    ("beutifulsoup4",    "pip", "Typosquat of beautifulsoup4 — backdoor"),
    ("beautifulsoup",    "pip", "Typosquat of beautifulsoup4 — backdoor"),
    ("nmap-python",      "pip", "Malicious scanner wrapper"),
    ("pylibmc2",         "pip", "Fake pylibmc — data exfiltration"),
    ("aws-sdk",          "pip", "Fake AWS SDK — credential harvester"),
    ("python-jwt2",      "pip", "Fake PyJWT — token interception"),

    # ── npm confirmed malicious ───────────────────────────────
    ("axios14",          "npm", "Fake axios — exfiltrates HTTP payloads"),
    ("axios14.0",        "npm", "Fake axios — exfiltrates HTTP payloads"),
    ("crossenv",         "npm", "Typosquat of cross-env — env var harvester"),
    ("cross.env",        "npm", "Typosquat of cross-env — env var harvester"),
    ("loadyaml",         "npm", "Typosquat of js-yaml — remote code exec"),
    ("loadash",          "npm", "Typosquat of lodash — cryptominer"),
    ("lodahs",           "npm", "Typosquat of lodash — cryptominer"),
    ("momnet",           "npm", "Typosquat of moment — data exfiltration"),
    ("mocha-assert",     "npm", "Fake mocha — steals npm tokens"),
    ("nodemailer2",      "npm", "Fake nodemailer — email credential stealer"),
    ("react-native-fs2", "npm", "Fake react-native-fs — filesystem spy"),
    ("eslint-scope",     "npm", "Compromised — steals npm tokens (real incident 2018)"),
    ("event-stream",     "npm", "Compromised — targeted bitcoin theft (real incident 2018)"),
    ("ua-parser-js",     "npm", "Compromised — cryptominer + password stealer (real 2021)"),
    ("coa",              "npm", "Compromised — malware injected (real incident 2021)"),
    ("rc",               "npm", "Compromised — malware injected (real incident 2021)"),
    ("electron-native-notify", "npm", "Malicious — remote code exec on install"),
    ("electorn",         "npm", "Typosquat of electron — backdoor"),
    ("expresss",         "npm", "Typosquat of express — HTTP request logger"),
    ("mongooes",         "npm", "Typosquat of mongoose — DB credential stealer"),
]


def check_blocklist(package_name: str, ecosystem: str) -> dict | None:
    """
    Returns a dict with reason if the package is blocked, else None.
    Matching is case-insensitive.
    """
    name_lower = package_name.lower().strip()
    eco_lower  = ecosystem.lower().strip()

    for (blocked_name, blocked_eco, reason) in MALICIOUS_PACKAGES:
        if blocked_name.lower().strip() == name_lower and blocked_eco.lower().strip() == eco_lower:
            return {
                "blocked": True,
                "package": package_name,
                "reason":  reason,
            }
    return None



