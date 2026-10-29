import csv

import pytest

from cti.threats import config, review


def _ioc(name, mid):
    return {"metadata": {"malware": name, "malware_id": mid}}


IOCS = (
    [_ioc("Mirai", "elf.mirai")] * 3
    + [_ioc("Mirai", "win.mirai")]
    + [_ioc("Unknown malware", "unknown")] * 9
    + [_ioc("Unknown Loader", "unknown_loader")] * 5
    + [_ioc("Vidar", "win.vidar")] * 2
    + [_ioc("AMOS", "osx.amos")] * 2
)


def test_vocabulary_is_stix_plus_declared_extensions():
    assert len(config.STIX_MALWARE_TYPES) == 22 and "remote-access-trojan" in config.CATEGORIES
    assert len(set(config.CATEGORIES)) == len(config.CATEGORIES)
    mapped = {c for c in config.MISP_FILE_CATEGORY.values() if c}
    assert mapped | set(config.THREATFOX_UNKNOWN_IDS.values()) <= set(config.CATEGORIES)


def test_families_merge_platform_ids_and_sort_by_rows():
    fams = review.families(IOCS)
    assert fams[0] == review.Family("Unknown malware", ("unknown",), 9)
    mirai = next(f for f in fams if f.name == "Mirai")
    assert mirai.ids == ("elf.mirai", "win.mirai") and mirai.rows == 4
    assert [f.name for f in fams if f.rows == 2] == ["AMOS", "Vidar"]  # ties by name


def test_sheet_lists_named_families_only_and_never_overwrites(tmp_path):
    path = tmp_path / "sheet.csv"
    top = review.write_sheet(path, review.families(IOCS), top_n=2)
    assert [f.name for f in top] == ["Mirai", "AMOS"]
    rows = list(csv.DictReader(path.open()))
    assert list(rows[0]) == list(review.COLUMNS)
    assert rows[0]["malware_ids"] == "elf.mirai;win.mirai" and rows[0]["categories"] == ""
    with pytest.raises(FileExistsError):
        review.write_sheet(path, review.families(IOCS))


def test_read_labels_validates_vocabulary(tmp_path):
    path = tmp_path / "sheet.csv"
    review.write_sheet(path, review.families(IOCS), top_n=2)
    text = path.read_text().splitlines()
    text[1] = text[1].replace(",4,,", ",4,Bot; DDoS ,")
    text[2] = text[2].replace(",2,,", ",2,infostealer,")
    path.write_text("\n".join(text) + "\n")
    assert review.read_labels(path) == {"Mirai": ("bot", "ddos"), "AMOS": ("infostealer",)}
    path.write_text(path.read_text().replace("infostealer", "stealer"))
    with pytest.raises(ValueError, match="unknown categories"):
        review.read_labels(path)
    path.write_text(path.read_text().replace("stealer", ""))
    with pytest.raises(ValueError, match="no category"):
        review.read_labels(path)


# ---- catalog ---------------------------------------------------------------------------
from datetime import date  # noqa: E402

from cti.threats import catalog  # noqa: E402

DAY = date(2026, 10, 26)


def _tf(name, mid, published="2026-10-20T00:00:00", alias=None, tags=()):
    return {
        "published": published,
        "metadata": {
            "malware": name,
            "malware_id": mid,
            "malware_alias": alias,
            "tags": list(tags),
        },
    }


def _sw(sid, name, stix_type="malware", aliases=()):
    return {
        "source_id": sid,
        "title": name,
        "metadata": {"stix_type": stix_type, "aliases": [name, *aliases]},
    }


def _mention(cve, surface, origin="reference_page", doc="references:1", ambiguous=False):
    return {
        "cve": cve,
        "origin": origin,
        "doc_id": doc,
        "aliases": [{"surface": surface, "ambiguous": ambiguous, "ids": ["x"]}],
    }


CLUSTERS = {
    "ransomware": {"values": [{"value": "Akira", "meta": {"synonyms": ["Akira Locker"]}}]},
    "rat": {"values": [{"value": "Async RAT"}]},
    "tool": {"values": [{"value": "QakBot"}]},
}
ATTACK = [
    _sw("S0650", "QakBot", aliases=["QBot"]),
    _sw("S1129", "Akira"),
    _sw("S0002", "Mimikatz", stix_type="tool"),
]
USES = {"S0650": {"T1059", "T1055"}, "S1129": {"T1486"}}
TACTICS = {"T1059": ("execution",), "T1055": ("privilege-escalation",), "T1486": ("impact",)}


def _build(iocs, mentions=(), kev=(), tiers=None, owner=None):
    return catalog.build(
        iocs=iocs,
        clusters=CLUSTERS,
        attack_docs=ATTACK,
        uses=USES,
        tactics=TACTICS,
        alias_rows=list(mentions),
        kev=list(kev),
        tiers=tiers or {},
        owner=owner or {},
        day=DAY,
    )


def _fam(result, name):
    return next(f for f in result["families"] if f["family"] == name)


def test_categories_from_misp_names_and_owner_labels_win():
    iocs = [_tf("Akira", "win.akira"), _tf("AsyncRAT", "win.asyncrat"), _tf("QakBot", "win.qakbot")]
    result = _build(iocs, owner={"AsyncRAT": ("remote-access-trojan", "loader")})
    akira = _fam(result, "Akira")
    assert (akira["categories"], akira["category_source"]) == (["ransomware"], "misp")
    rat = _fam(result, "AsyncRAT")  # "Async RAT" normalises to the same name
    assert rat["category_source"] == "owner" and rat["misp_categories"] == ["remote-access-trojan"]
    assert rat["categories"] == ["remote-access-trojan", "loader"]
    qak = _fam(result, "QakBot")  # tool.json gives names, never a category
    assert (qak["categories"], qak["category_source"]) == ([], "none")


def test_attack_join_uses_the_family_name_not_threatfox_aliases():
    iocs = [_tf("QakBot", "win.qakbot"), _tf("Bashlite", "elf.bashlite", alias="Gafgyt,Qbot")]
    result = _build(iocs)
    qak = _fam(result, "QakBot")["attack"]
    assert qak["software"] == "S0650" and qak["techniques"] == ["T1055", "T1059"]
    assert qak["tactics"] == ["execution", "privilege-escalation"]
    assert _fam(result, "Bashlite")["attack"]["software"] is None


def test_mentions_link_only_reference_pages_and_names_one_family_claims():
    iocs = [
        _tf("QakBot", "win.qakbot"),
        _tf("Bashlite", "elf.bashlite", alias="Gafgyt,Qbot"),
        _tf("Mimikatz", "win.mimikatz"),
    ]
    mentions = [
        _mention("CVE-2026-0001", "Gafgyt", doc="references:a"),  # Bashlite's own alias
        _mention("CVE-2026-0002", "Qbot"),  # claimed by QakBot (ATT&CK) and Bashlite
        _mention("CVE-2026-0003", "QakBot", origin="nvd_description"),  # vulnerable product
        _mention("CVE-2026-0004", "QakBot", ambiguous=True),
        _mention("CVE-2026-0005", "Mimikatz"),
    ]
    result = _build(iocs, mentions=mentions, tiers={"CVE-2026-0001": "high"})
    [link] = _fam(result, "Bashlite")["cves"]
    assert link == {
        "cve": "CVE-2026-0001",
        "via": "mention:reference_page",
        "evidence": [{"doc_id": "references:a", "surface": "Gafgyt"}],
        "tier": "high",
        "in_kev": False,
    }
    assert _fam(result, "QakBot")["cves"] == []
    assert [c["cve"] for c in _fam(result, "Mimikatz")["cves"]] == ["CVE-2026-0005"]


def test_threatfox_cve_tags_link_with_provenance():
    iocs = [_tf("RedTail", "elf.redtail", tags=["cve-2024-4577", "miner"])]
    [link] = _fam(_build(iocs, kev=[{"source_id": "CVE-2024-4577", "metadata": {}}]), "RedTail")[
        "cves"
    ]
    assert (link["cve"], link["via"], link["in_kev"], link["evidence"]) == (
        "CVE-2024-4577",
        "threatfox_tag",
        True,
        [],
    )


def test_priority_order_and_why():
    iocs = (
        [_tf("Akira", "win.akira", "2026-09-10T00:00:00")]  # ransomware, 1 older row
        + [_tf("Vidar", "win.vidar")] * 5  # 5 recent rows
        + [_tf("Vidar", "win.vidar", "2026-09-10T00:00:00")] * 2  # 2 in the prior window
        + [_tf("QakBot", "win.qakbot", tags=["CVE-2026-0009"])]
    )
    result = _build(iocs, tiers={"CVE-2026-0009": "critical"})
    assert [f["family"] for f in result["families"]] == ["QakBot", "Akira", "Vidar"]
    assert _fam(result, "QakBot")["why"][0] == "linked to 1 critical/high-tier CVE in the queue"
    assert _fam(result, "Akira")["why"] == ["ransomware", "1 IOC"]
    vidar = _fam(result, "Vidar")
    assert vidar["priority_keys"]["ioc_growth"] == 3
    assert vidar["why"] == ["IOCs up +3 in the last 30 days (5 vs 2)", "7 IOCs"]
    assert [f["rank"] for f in result["families"]] == [1, 2, 3]


def test_category_rows_count_unattributed_roles_and_kev_ransomware():
    iocs = [_tf("Akira", "win.akira")] * 2 + [
        _tf("Unknown Loader", "unknown_loader"),
        _tf("Unknown Webinject", "unknown_webinject"),
        _tf("Mystery", "win.mystery"),
    ]
    kev = [
        {"source_id": "CVE-1", "metadata": {"ransomware_use": "Known"}},
        {"source_id": "CVE-2", "metadata": {"ransomware_use": "Unknown"}},
    ]
    result = _build(iocs, kev=kev)
    assert result["category_rows"] == {
        "loader": 1,
        "ransomware": 2,
        "unknown": 1,
        "unlabelled": 1,
    }
    assert result["kev_ransomware_cves"] == ["CVE-1"]
    # an unattributed name spanning two role IDs is counted once
    two = [_tf("Unknown X", "unknown_loader"), _tf("Unknown X", "unknown_stealer")]
    assert _build(two)["category_rows"] == {"unknown": 2}
    assert "Unknown Loader" not in {f["family"] for f in result["families"]}


def test_build_is_deterministic():
    iocs = [
        _tf("Akira", "win.akira"),
        _tf("QakBot", "win.qakbot"),
        _tf("Bashlite", "elf.bashlite", alias="Gafgyt,Qbot,Lizkebab"),
    ]
    mentions = [
        _mention("CVE-2026-0001", "Gafgyt", doc="references:b"),
        _mention("CVE-2026-0001", "Lizkebab", doc="references:a"),
        _mention("CVE-2026-0002", "QakBot"),
    ]
    one = _build(list(iocs), mentions=mentions)
    assert one == _build(list(reversed(iocs)), mentions=list(reversed(mentions)))
    assert [e["doc_id"] for e in _fam(one, "Bashlite")["cves"][0]["evidence"]] == [
        "references:a",
        "references:b",
    ]


def test_growth_and_volume_break_ties_in_that_order():
    iocs = (
        [_tf("Big", "win.big", "2026-08-01T00:00:00")] * 9  # most rows, no growth
        + [_tf("Rising", "win.rising")] * 3  # +3
        + [_tf("Steady", "win.steady")] * 2  # +2 ...
        + [_tf("Steady", "win.steady", "2026-08-01T00:00:00")] * 5  # ... and more rows
        + [_tf("Shrinking", "win.shrink", "2026-09-20T00:00:00")] * 4  # -4
    )
    result = _build(iocs)
    assert [f["family"] for f in result["families"]] == ["Rising", "Steady", "Big", "Shrinking"]


def test_growth_window_edges():
    iocs = [
        _tf("A", "w.a", "2026-10-26T23:00:00"),  # snapshot day: recent
        _tf("A", "w.a", "2026-09-26T12:00:00"),  # day - 30: prior, not recent
        _tf("A", "w.a", "2026-09-27T00:00:00"),  # day - 29: recent
        _tf("A", "w.a", "2026-08-27T00:00:00"),  # day - 60: outside both
        _tf("A", "w.a", "2026-10-27T00:00:00"),  # after the snapshot: outside
    ]
    assert catalog.growth(iocs, DAY) == {"A": (2, 1)}


def test_agreement_per_category():
    owner = {"A": ("ransomware",), "B": ("bot", "ddos"), "C": ("loader",), "D": ("bot",)}
    auto = {"A": ("ransomware",), "B": ("bot",), "C": ("infostealer",), "D": ()}
    result = catalog.agreement(owner, auto)
    assert result["families_compared"] == 3 and result["without_auto_label"] == ["D"]
    per = result["per_category"]
    assert per["ransomware"]["specific_agreement"] == 1.0
    assert (per["ddos"]["owner_only"], per["ddos"]["specific_agreement"]) == (1, 0.0)
    assert per["bot"]["both"] == 1 and per["infostealer"]["auto_only"] == 1


def test_link_sheet_round_trip_and_precision(tmp_path):
    path = tmp_path / "links.csv"
    link = {
        "family": "Mirai",
        "cve": "CVE-1",
        "via": "threatfox_tag",
        "surface": "",
        "evidence_url": "u",
    }
    assert review.write_link_sheet(path, [link, dict(link, cve="CVE-2"), link]) == 2
    assert review.status(path, "correct") == "blank"
    with pytest.raises(FileExistsError):
        review.write_link_sheet(path, [link])
    path.write_text(path.read_text().replace("u,,", "u,yes,", 1).replace("u,,", "u,no,", 1))
    labels = review.read_link_labels(path)
    assert labels == {
        ("Mirai", "CVE-1", "threatfox_tag"): True,
        ("Mirai", "CVE-2", "threatfox_tag"): False,
    }
    assert review.link_keys(path) == set(labels)
    prec = catalog.link_precision(labels)
    assert prec["all"]["n"] == 2 and prec["all"]["precision"] == 0.5
    assert prec["threatfox_tag"]["correct"] == 1
