"""The dashboard's contract with `cti export`: fixture, documentation-only values, TS types."""

import ipaddress
import json
import re
from pathlib import Path

import pytest

from cti.dashboard import schema
from cti.defang import refang

WEB = Path(__file__).resolve().parents[2] / "web"
FIXTURES = WEB / "fixtures"
# RFC 5737 / RFC 3849 documentation ranges, plus RFC 1918 10/8 for the fixture's one
# deliberately non-public IP (it exercises the "hide non-public IPs" filter)
ALLOWED_NETS = [
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "10.0.0.0/8")
]
DOC_DOMAINS = ("example.com", "example.org", "example.net")  # RFC 2606
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7}\b", re.I)
_HOST = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)


def strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for k, v in node.items():
            yield from strings(k)
            yield from strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from strings(v)


def test_fixture_is_valid_and_matches_a_fresh_build(tmp_path):
    pytest.importorskip("sklearn")
    from cti.dashboard import export
    from tests.web_fixture import build

    for name, model in schema.FILES.items():
        model.model_validate_json((FIXTURES / name).read_text())
    export.write(tmp_path, build())
    for name in schema.FILES:
        assert (tmp_path / name).read_bytes() == (FIXTURES / name).read_bytes(), (
            f"{name} is stale: run `python -m tests.web_fixture web/fixtures`"
        )


def test_fixture_holds_only_documentation_network_values():
    for name in schema.FILES:
        data = json.loads((FIXTURES / name).read_text())
        for text in strings(data):
            plain = refang(text)
            for ip in _IP.findall(plain):
                try:
                    addr = ipaddress.ip_address(ip)
                except ValueError:
                    continue  # versions, CVE fragments
                assert any(addr in net for net in ALLOWED_NETS), f"{name}: {ip} is not allowed"
            for host in _HOST.findall(plain):
                h = host.lower()
                if re.fullmatch(r"[\d.]+", h):
                    continue
                ok = any(h == d or h.endswith("." + d) for d in DOC_DOMAINS)
                assert ok, f"{name}: {host} is not an RFC 2606 domain"


@pytest.mark.parametrize("bad", ["8[.]8[.]8[.]8", "hxxps://google[.]com/x", "notexample[.]com"])
def test_documentation_check_catches_real_values(bad, monkeypatch):
    real = json.loads((FIXTURES / "iocs.json").read_text())
    real["title"] = bad
    monkeypatch.setattr(json, "loads", lambda _text, _real=real: _real)
    with pytest.raises(AssertionError):
        test_fixture_holds_only_documentation_network_values()


def test_fixture_cves_are_visibly_synthetic():
    risk = json.loads((FIXTURES / "risk.json").read_text())
    assert all(r["cve"].startswith("CVE-2099-") for r in risk["rows"])
    meta = json.loads((FIXTURES / "meta.json").read_text())
    assert meta["disclosures"][0].startswith("SYNTHETIC FIXTURE")


def ts_interfaces() -> dict[str, str]:
    text = (WEB / "src" / "types.ts").read_text()
    return {
        m.group(1): m.group(2)
        for m in re.finditer(r"export interface (\w+) \{(.*?)\n\}", text, re.S)
    }


MODELS = sorted(
    (
        m
        for m in vars(schema).values()
        if isinstance(m, type) and issubclass(m, schema._Model) and m is not schema._Model
    ),
    key=lambda m: m.__name__,
)


@pytest.mark.parametrize("model", MODELS, ids=lambda m: m.__name__)
def test_typescript_types_mirror_the_schema(model):
    body = ts_interfaces().get(model.__name__)
    assert body is not None, f"web/src/types.ts has no interface {model.__name__}"
    for field in model.model_fields:
        assert re.search(rf'^\s*"?{re.escape(field)}"?\??:', body, re.M), (
            f"{model.__name__}.{field} is missing from web/src/types.ts"
        )
