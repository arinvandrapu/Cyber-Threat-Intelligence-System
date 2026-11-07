"""`cti report`: the analyst brief generated from a dashboard export (Phase 9.1)."""

import json
import re
import shutil
from pathlib import Path

import pytest

from cti.cli import main
from cti.dashboard import brief

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "web" / "fixtures"
GOLDEN = ROOT / "tests" / "golden" / "brief_fixture.md"
CVE = re.compile(r"CVE-\d{4}-\d{4,}")


def _render(export_dir=FIXTURE):
    return brief.render(brief.facts(export_dir))


def test_matches_the_golden_brief():
    """Catches any change to the generator's output; regenerate deliberately with
    `cti report --export-dir web/fixtures --out tests/golden/brief_fixture.md`."""
    assert _render() == GOLDEN.read_text(encoding="utf-8")


def test_is_deterministic_and_tlp_marked():
    text = _render()
    assert text == _render()
    lines = text.strip().splitlines()
    assert lines[0] == lines[-1] == "**TLP:CLEAR**"


def test_every_cve_is_in_the_export():
    export = {name: json.loads((FIXTURE / name).read_text()) for name in ("risk.json", "kev.json")}
    threats = json.loads((FIXTURE / "threats.json").read_text())
    known = (
        {r["cve"] for r in export["risk.json"]["rows"]}
        | {e["cve"] for e in export["kev.json"]["entries"]}
        | {x["cve"] for f in threats["families"] for x in f["links"]}
    )
    assert set(CVE.findall(_render())) <= known


def test_states_no_indicators_or_urls():
    text = _render()
    assert "://" not in text and "[.]" not in text and "hxxp" not in text
    assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", text)  # no IPv4 literal


def test_wording_rules():
    text = _render()
    assert "not a risk ranking" in text and "not a prediction" in text
    assert "does not show the family exploited the CVE" in text
    assert " exploits CVE" not in text


@pytest.mark.parametrize(
    ("stale", "expected"),
    [(True, "built before the risk tiers last changed"), (False, "has not been run")],
)
def test_without_threats(tmp_path, stale, expected):
    export_dir = tmp_path / "export"
    shutil.copytree(FIXTURE, export_dir)
    doc = json.loads((export_dir / "threats.json").read_text())
    doc.update(available=False, stale=stale, families=[], families_total=0, review=None)
    doc.update(categories=[], linked_cves=[], snapshot_date=None, kev_ransomware_cves=0)
    (export_dir / "threats.json").write_text(json.dumps(doc))
    text = _render(export_dir)
    assert text.count(expected) == 2  # sections 3 and 4
    assert "no threat catalog in this export" in text
    assert "Hunt:" not in text


def test_confidence_key():
    assert brief.confidence(6, False) == "low"
    assert brief.confidence(68, True) == "moderate"
    assert brief.confidence(40, False) == "moderate"
    assert brief.confidence(68, False) == "high"


def test_feature_labels_match_the_dashboard():
    ts = (ROOT / "web" / "src" / "format.ts").read_text()
    body = ts.split("export const FEATURE_LABEL")[1].split("};")[0]
    web = dict(re.findall(r'(\w+): "([^"]*)"', body))
    assert web == brief.FEATURE_LABEL


def test_cli_writes_and_checks(tmp_path, capsys):
    out = tmp_path / "brief.md"
    assert main(["report", "--export-dir", str(FIXTURE), "--out", str(out)]) == 0
    assert out.read_text() == _render()
    assert main(["report", "--export-dir", str(FIXTURE), "--check", str(out)]) == 0
    out.write_text(out.read_text().replace(brief.export_sha256(FIXTURE), "0" * 64))
    assert main(["report", "--export-dir", str(FIXTURE), "--check", str(out)]) == 1
    assert "regenerate it" in capsys.readouterr().err
