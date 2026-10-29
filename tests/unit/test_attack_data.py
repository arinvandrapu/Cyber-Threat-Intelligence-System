from collections import Counter

from cti.nlp import attack_data as ad


def _cve(cid, *, status="Analyzed", cwes=(), metrics=None, cna="cna@x"):
    return {
        "id": cid,
        "vulnStatus": status,
        "sourceIdentifier": cna,
        "descriptions": [{"lang": "es", "value": "x"}, {"lang": "en", "value": f"{cid} text"}],
        "weaknesses": [{"description": [{"value": c} for c in cwes]}],
        "metrics": metrics or {},
    }


def _v3(vector, source="nvd@nist.gov"):
    return {"source": source, "cvssData": {"version": "3.1", "vectorString": vector}}


def _v2(vector, source="nvd@nist.gov", **flags):
    return {"source": source, "cvssData": {"version": "2.0", "vectorString": vector}, **flags}


def test_record_prefers_nvd_then_cna_and_newest_version_and_drops_rejected():
    metrics = {
        "cvssMetricV31": [_v3("CVSS:3.1/AV:L/UI:N/PR:L", source="cna@x")],
        "cvssMetricV2": [_v2("AV:N/AC:L/Au:N", userInteractionRequired=True)],
    }
    rec = ad._record(_cve("CVE-1", cwes=("CWE-79", "NVD-CWE-Other"), metrics=metrics))
    assert rec.text == "CVE-1 text" and rec.cwes == ("CWE-79",)
    # NVD's own score wins even though it is older (v2); its booleans are kept
    assert rec.cvss["family"] == "v2" and rec.cvss["source"] == "nvd"
    assert rec.cvss["flags"]["userInteractionRequired"] is True
    cna_only = ad._record(_cve("CVE-2", metrics={"cvssMetricV31": [_v3("CVSS:3.1/AV:L", "cna@x")]}))
    assert cna_only.cvss["family"] == "v3" and cna_only.cvss["vector"] == {"AV": "L"}
    assert ad._record(_cve("CVE-3", status="Rejected")) is None
    assert ad._record(_cve("CVE-4")).cvss is None


def test_cvss_rule_v3_and_v2():
    def rule(family, vector, **flags):
        base = dict.fromkeys(ad._V2_FLAGS, False)
        return ad.cvss_parents(
            {"family": family, "vector": ad._vector(vector), "flags": base | flags}
        )

    assert rule("v3", "CVSS:3.1/AV:N/UI:N/PR:N") == {"T1190"}
    assert rule("v3", "CVSS:3.1/AV:N/UI:R/PR:N") == {"T1204", "T1189"}
    assert rule("v3", "CVSS:3.1/AV:L/UI:N/PR:L") == {"T1068"}
    assert rule("v3", "CVSS:3.1/AV:N/UI:N/PR:H") == {"T1190", "T1078"}
    assert rule("v2", "AV:N/AC:L/Au:N") == {"T1190"}
    assert rule("v2", "AV:N/AC:L/Au:S", userInteractionRequired=True) == {"T1204", "T1189", "T1078"}
    assert rule("v2", "AV:N/AC:L/Au:N", obtainUserPrivilege=True) == {"T1190"}  # impact flag
    assert rule("v2", "AV:L/AC:L/Au:N") == {"T1068"}
    assert rule("v2", "AV:A/AC:L/Au:N") == set()
    assert ad.cvss_parents(None) == set()


def test_capec_paths_count_every_route():
    cwe_capec = {"CWE-1": {"CAPEC-1", "CAPEC-2"}, "CWE-2": {"CAPEC-2"}}
    capec_attack = {"CAPEC-1": {"T1190"}, "CAPEC-2": {"T1190", "T1059"}}
    assert ad.capec_paths(["CWE-1", "CWE-2", "CWE-9"], cwe_capec, capec_attack) == Counter(
        {"T1190": 3, "T1059": 2}
    )


def test_load_test_merges_rows_remaps_and_counts(tmp_path, monkeypatch):
    csv_text = (
        "﻿CVE ID,Primary Impact,Secondary Impact,Exploitation Technique,Uncategorized,Phase\n"
        "CVE-A,T1059.004,,T1190; T1078,,Phase 2\n"
        "CVE-A,,,T1204.002,T828,Phase 1\n"  # second row: merged; Uncategorized ignored
        "CVE-B,T9999,,T1086,,Phase 1\n"  # unknown dropped; revoked remapped
        "CVE-T,T1068,,T1190,,Phase 1\n"  # a training CVE: excluded
    )
    monkeypatch.setattr(ad.reference, "read_pinned", lambda d, n: csv_text.encode())
    current = {"T1059.004", "T1190", "T1078", "T1204.002", "T1059.001", "T1068"}
    labels = ad.load_test(tmp_path, current, {"T1086": "T1059.001"}, exclude={"CVE-T"})
    assert labels.gold == {
        "CVE-A": {
            "exploitation_technique": {"T1190", "T1078", "T1204"},
            "primary_impact": {"T1059"},
        },
        "CVE-B": {"exploitation_technique": {"T1059"}},
    }
    assert labels.counts["labels_remapped"] == 1
    assert labels.counts["labels_unknown_dropped"] == 1
    assert labels.counts["cves_with_two_rows"] == 1
    assert labels.counts["training_overlap_cves"] == 1
