# SafeDev — Universal Developer Security Tool

Protects against software supply chain attacks by scanning
packages and repositories BEFORE you install or run them.

## Install

```bash
pip install click colorama streamlit
pip install -e .
```

## Usage

```bash
safedev install requests
safedev install lodash --ecosystem npm
safedev clone https://github.com/user/repo
safedev scan ./my-project
safedev scan ./my-project --output json
safedev ui        # launches Streamlit dashboard
```

## Options

| Flag | Meaning |
|------|---------|
| `--ecosystem pip\|npm` | Which package manager (default: pip) |
| `--threshold N` | Block if score > N (default: 5) |
| `--force` | Skip confirmation prompt |
| `--output text\|json` | Output format for `scan` |

## Risk Score

| Score | Label | Action |
|-------|-------|--------|
| 0–2 | Safe | Proceed |
| 3–5 | Low risk | Warn + confirm |
| 6–8 | Medium risk | Warn + confirm |
| 9–10 | High risk | Block |
