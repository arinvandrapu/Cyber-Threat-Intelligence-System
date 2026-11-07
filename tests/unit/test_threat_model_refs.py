"""docs/threat-model.md cites controls as `file::symbol` and by test name; keep them real.

A cited file must exist; a cited symbol (and any bare symbol chained after it, as in
"`a.py::f`, `g`") must still be defined in that file; a cited test must still exist. The
doc then fails CI instead of silently describing code that has moved or gone.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs" / "threat-model.md"
TOKEN = re.compile(r"`([^`\n]+)`")
PATH = re.compile(r"^(?:src|web|infra|tests|\.github|requirements)[\w./-]*$")
SYMBOL = re.compile(r"^[A-Za-z_]\w*(?:\.\w+)?$")


def _defines(source: str, name: str) -> bool:
    pattern = rf"^\s*(?:def|class)\s+{re.escape(name)}\b|^\s*{re.escape(name)}\s*[:=]"
    return re.search(pattern, source, re.MULTILINE) is not None


def _citations(text: str):
    """Yield (kind, value, path) for every checkable citation."""
    current, prev_end = None, None
    for m in TOKEN.finditer(text):
        token = m.group(1)
        chained = prev_end is not None and text[prev_end : m.start()] == ", "
        if token.startswith("test_"):
            yield "test", token, None
            current = None
        elif PATH.match(token.split("::")[0]):
            path, _, symbol = token.partition("::")
            yield "file", path, None
            current = path
            if symbol:
                yield "symbol", symbol, path
        elif current and chained and SYMBOL.match(token):
            yield "symbol", token, current
        else:
            current = None
        prev_end = m.end()


def test_every_citation_in_the_threat_model_exists():
    text = DOC.read_text(encoding="utf-8")
    tests = "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "tests").rglob("test_*.py"))
    missing, checked = [], 0
    for kind, value, path in _citations(text):
        checked += 1
        gone_file = kind == "file" and not (ROOT / value).exists()
        gone_test = kind == "test" and not re.search(rf"^def {value}\(", tests, re.MULTILINE)
        if gone_file or gone_test:
            missing.append(value)
        elif kind == "symbol":
            source = (ROOT / path).read_text(encoding="utf-8")
            if not all(_defines(source, part) for part in value.split(".")):
                missing.append(f"{path}::{value}")
    assert checked > 50  # the parser still finds the citations
    assert missing == []


def test_the_checker_catches_a_stale_citation():
    stale = "`src/cti/http/safe_fetch.py::no_such_function`, `test_no_such_test`"
    found = list(_citations(stale))
    assert ("symbol", "no_such_function", "src/cti/http/safe_fetch.py") in found
    assert ("test", "test_no_such_test", None) in found
