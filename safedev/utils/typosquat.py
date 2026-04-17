"""
typosquat.py — Detects typosquatting attempts.
Uses edit distance (Levenshtein) to find names suspiciously
close to popular trusted packages.
"""

# 60 most downloaded / most targeted packages on PyPI + npm
POPULAR_PACKAGES = {
    "pip": [
        "requests", "numpy", "pandas", "flask", "django", "boto3",
        "setuptools", "pip", "six", "urllib3", "certifi",
        "charset-normalizer", "idna", "packaging", "cryptography",
        "pyopenssl", "pyyaml", "toml", "click", "colorama", "pillow",
        "scipy", "matplotlib", "tensorflow", "torch", "scikit-learn",
        "sqlalchemy", "psycopg2", "pymongo", "redis", "celery",
        "paramiko", "pytest", "black", "isort", "mypy", "pylint",
        "flake8", "virtualenv", "coverage", "aiohttp", "httpx",
        "fastapi", "uvicorn", "pydantic", "stripe", "twilio",
        "beautifulsoup4", "lxml", "openpyxl", "loguru", "rich",
        "tqdm", "arrow", "dateutil", "jinja2", "werkzeug",
        "openai", "anthropic", "transformers", "langchain",
    ],
    "npm": [
        "axios", "react", "vue", "express", "lodash", "moment",
        "webpack", "babel-core", "eslint", "prettier", "typescript",
        "jest", "mocha", "chai", "mongoose", "sequelize", "knex",
        "socket.io", "nodemailer", "dotenv", "cors", "helmet",
        "passport", "jsonwebtoken", "bcrypt", "multer", "sharp",
        "cheerio", "puppeteer", "playwright", "electron", "next",
        "nuxt", "gatsby", "vite", "rollup", "parcel", "esbuild",
        "cross-env", "concurrently", "nodemon", "pm2", "forever",
        "uuid", "dayjs", "date-fns", "rxjs", "redux", "zustand",
    ],
}


def _levenshtein(a: str, b: str) -> int:
    """Classic dynamic-programming edit distance."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(prev[j] + 1,
                            curr[j - 1] + 1,
                            prev[j - 1] + (ca != cb)))
        prev = curr
    return prev[-1]


def check_typosquat(package_name: str, ecosystem: str) -> dict | None:
    """
    Returns a dict if the package looks like a typosquat, else None.

    Thresholds:
      - distance == 1  → almost certain typosquat (1 char off)
      - distance == 2  → suspicious if name is short (<=8 chars)
    """
    eco   = ecosystem.lower()
    name  = package_name.lower().strip()
    pool  = POPULAR_PACKAGES.get(eco, [])

    # Exact match means it IS the popular package — not a typosquat
    if name in pool:
        return None

    best_dist   = 999
    best_match  = ""

    for popular in pool:
        d = _levenshtein(name, popular)
        if d < best_dist:
            best_dist  = d
            best_match = popular

    # Flag if suspiciously close
    if best_dist == 1:
        return {
            "typosquat": True,
            "package":   package_name,
            "similar_to": best_match,
            "distance":  best_dist,
            "confidence": "HIGH",
        }
    if best_dist == 2 and len(name) <= 8:
        return {
            "typosquat": True,
            "package":   package_name,
            "similar_to": best_match,
            "distance":  best_dist,
            "confidence": "MEDIUM",
        }
    return None
