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
