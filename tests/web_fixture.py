"""A synthetic `cti export` for building and testing the dashboard without real data.

CI has no `data/` (feed data is never committed), so the dashboard is built against this
fixture. It runs the real export code on made-up records, so it exercises the same shapes.
Everything is visibly fake: CVE IDs use the year 2099, and every network value comes from
the documentation ranges (RFC 5737 IPv4, RFC 3849 IPv6, RFC 2606 domains).

Regenerate after a schema change (the test fails until you do):

    python -m tests.web_fixture web/fixtures
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

from cti.dashboard import export
from cti.nlp import risk_config as cfg
from cti.nlp import risk_eval
from cti.nlp.attack_catalog import Technique

DATES = {
    "cutoff4": "2024-11-05",
    "cutoff3": "2025-05-04",
    "cutoff2": "2025-10-31",
    "cutoff": "2026-04-29",
    "snapshot": "2026-10-26",
}
CWES = [
    ("CWE-79", "Cross-site Scripting", "CWE-707"),
    ("CWE-89", "SQL Injection", "CWE-707"),
    ("CWE-78", "OS Command Injection", "CWE-707"),
    ("CWE-22", "Path Traversal", "CWE-664"),
    ("CWE-502", "Deserialization of Untrusted Data", "CWE-664"),
    ("CWE-287", "Improper Authentication", "CWE-284"),
    ("CWE-862", "Missing Authorization", "CWE-284"),
]
PILLARS = {
    "CWE-707": "Improper Neutralization",
    "CWE-664": "Improper Control of a Resource",
    "CWE-284": "Improper Access Control",
}
HOSTS = ["vendor.example.com", "advisories.example.org", "research.example.net", "lab.example.com"]


def _cve(i: int) -> str:
    return f"CVE-2099-{10000 + i}"


def _epss(p: float, day: str) -> dict:
    return {
        "epss": round(p * 0.6, 5),
        "percentile": round(p, 5),
        "model_version": "v-fixture",
        "score_date": f"{day}T00:00:00Z",
    }


def records(n: int = 2400, seed: int = 7) -> list[dict]:
    rng = np.random.default_rng(seed)
    out = []
    for i in range(n):
        published = f"2024-{1 + i % 12:02d}-{1 + i % 27:02d}"
        if i % 9 == 0:  # some recent CVEs, as in real data
            published = f"2026-{9 + i % 2:02d}-{1 + i % 25:02d}"
        p = float(rng.beta(0.6, 2.0))
        kev = None
        if rng.uniform() < p**3 * 0.08:
            kev = ["2025-02-01", "2025-08-01", "2026-02-01", "2026-08-01"][i % 4]
        signals = {}
        for label, day in DATES.items():
            if published > day:
                continue
            s = {"epss": _epss(min(p + rng.normal(0, 0.03), 0.9999), day)}
            if i % 3:
                s["vulnrichment"] = {
                    "exploitation": "poc" if p > 0.6 else "none",
                    "automatable": "yes" if i % 2 else "no",
                    "technical_impact": "total" if p > 0.3 else "partial",
                    "decided_at": f"{min(day, published)}T00:00:00Z",
                }
            if p > 0.7 and i % 4 == 0:
                s["nuclei"] = {}
            if p > 0.8 and i % 5 == 0:
                s["metasploit"] = {"module_count": 1}
            signals[label] = s
        cwe = CWES[i % len(CWES)]
        out.append(
            {
                "cve": _cve(i),
                "published": f"{published}T00:00:00",
                "signals": signals,
                "eligible": {
                    label: published <= day and not (kev and kev <= day)
                    for label, day in DATES.items()
                },
                "kev": {"date_added": kev} if kev else None,
                "context_snapshot": {
                    "cvss_nvd": {"base_score": round(4 + 6 * p, 1)},
                    "cvss_cna": None,
                    "cwes": [{"id": cwe[0], "kind": "weakness", "name": cwe[1], "pillar": cwe[2]}],
                },
            }
        )
    return out


def _risk_eval_result() -> dict:
    """A made-up risk-eval.json with the real structure (values are illustrative)."""
    pooled = {
        "positives": 40,
        "hits@100": 5,
        "recall@100": 0.125,
        "recall@100_wilson95": [0.05, 0.26],
        "hits@1%": 9,
        "recall@1%": 0.225,
        "recall@1%_wilson95": [0.12, 0.38],
        "mean_average_precision": 0.02,
    }
    fold = {"n": 600, "positives": 13, "hits@100": 2, "hits@1%": 3, "average_precision": 0.02}
    folds = {
        f: {"cutoff": DATES[f], "window_end": DATES[nxt], "eligible": 600, "positives": 13}
        for f, nxt in (("cutoff3", "cutoff2"), ("cutoff2", "cutoff"), ("cutoff", "snapshot"))
    }
    method = {"pooled": pooled, "per_fold": {f: fold for f in folds}}
    tiers = {
        "critical": {"cves": 6, "kev_positives": 1, "hit_rate": 0.1667, "wilson95": [0.03, 0.56]},
        "high": {"cves": 48, "kev_positives": 3, "hit_rate": 0.0625, "wilson95": [0.02, 0.17]},
        "elevated": {"cves": 240, "kev_positives": 6, "hit_rate": 0.025, "wilson95": [0.01, 0.05]},
        "baseline": {
            "cves": 4506,
            "kev_positives": 30,
            "hit_rate": 0.0067,
            "wilson95": [0.0046, 0.0095],
        },
    }
    paired = {"difference_hits": 3, "ci95": [1, 6], "excludes_zero": True}
    return {
        "headline": "fixture headline",
        "decision": {
            "rule": "fixture rule",
            "verdict": "logistic better",
            "logistic_minus_epss_hits@100": paired,
        },
        "secondary_paired": {
            "logistic_minus_epss_hits@1%": {**paired, "ci95": [-2, 4], "excludes_zero": False}
        },
        "random_expected": {"recall@100": 0.02, "recall@1%": 0.01},
        "folds": folds,
        "tiers_logistic": {"tiers": tiers, "monotonic": True},
        "methods": {m: method for m in ("logistic", "boosting", "epss", "ssvc_rule", "cvss_cna")},
        "logistic_coefficients_last_fold_standardized": dict.fromkeys(risk_eval.FEATURES, 0.1),
        "provenance": {"kev_catalog_version": "fixture"},
    }


def _evals() -> dict:
    metric = {
        "cves": 50,
        "hit@1": {"value": 0.2, "ci95": [0.1, 0.3]},
        "hit@5": {"value": 0.5, "ci95": [0.4, 0.6]},
        "mrr": {"value": 0.3, "ci95": [0.2, 0.4]},
    }
    cwe_cell = {
        "n": 500,
        "macro_f1": 0.4,
        "macro_f1_ci95": [0.38, 0.42],
        "accuracy": 0.55,
        "top5": 0.8,
    }
    prec = {"precision": 0.95, "ci95": [0.9, 1.0], "labelled": 50, "population": 1000}
    ner = {"Malware": {"f1": 0.3, "precision": 0.3, "recall": 0.3, "gold": 10, "predicted": 10}}
    return {
        "risk": _risk_eval_result(),
        "attack": {
            "primary": {
                "mapping_type": "exploitation_technique",
                "split": "test",
                "variant": "nvd",
            },
            "splits": {"dev": 100, "test": 50},
            "results": {
                "test": {
                    "nvd": {
                        m: {"exploitation_technique": metric}
                        for m in ("majority", "prior+biencoder")
                    }
                }
            },
        },
        "cwe": {
            "headline": "fixture",
            "classes": {"known": 7},
            "test": {m: {"name_absent": cwe_cell} for m in ("tfidf", "embedding")},
        },
        "extract": {
            "review": {
                "overall": prec,
                "per_type": {"ipv4": prec},
                "per_origin": {"reference_page": prec},
            }
        },
        "ner": {"model": {"repo": "fixture"}, "text_derived_spans": {"exact": ner, "overlap": ner}},
    }


def _ioc_docs(cves: list[str]) -> list[dict]:
    docs = []
    for i, cve in enumerate(cves[:300]):
        host = HOSTS[i % len(HOSTS)]
        iocs = [
            {"type": "url", "value": export.defang_text(f"https://{host}/advisory/{i}")},
            {"type": "domain", "value": export.defang_text(host)},
            {
                "type": "ipv4",
                "value": f"{['192.0.2', '198.51.100', '203.0.113'][i % 3]}[.]{1 + i % 250}",
                "public": True,
            },
            {"type": "sha256", "value": f"{i:064x}"},
        ]
        if i % 10 == 0:
            iocs.append({"type": "ipv6", "value": f"2001[:]db8[:][:]{i:x}", "public": True})
        if i % 7 == 0:
            iocs.append({"type": "ipv4", "value": "10.0.0[.]1", "public": False})
        docs.append({"cve": cve, "origin": "reference_page", "iocs": iocs})
    docs.append(
        {
            "cve": cves[0],
            "origin": "nvd_description",
            "iocs": [{"type": "domain", "value": "example[.]com"}],
        }
    )
    return docs


def _feeds() -> tuple[list[dict], list[dict]]:
    families = ["Example Family A", "Example Family B", "Example Family C"]
    threatfox = [
        {
            "published": f"2026-{1 + i % 10:02d}-01T00:00:00",
            "metadata": {
                "ioc_type": ["domain", "url", "ip:port"][i % 3],
                "threat_type": ["botnet_cc", "payload"][i % 2],
                "malware": families[i % 3],
            },
        }
        for i in range(120)
    ]
    urlhaus = [
        {
            "published": f"2026-{1 + i % 10:02d}-01T00:00:00",
            "metadata": {"ioc_type": "url", "threat": "malware_download"},
        }
        for i in range(80)
    ]
    return threatfox, urlhaus


def _threats_doc(tiers: dict[str, str], kev_cve: str) -> dict:
    """A synthetic ``cti threats`` document: three families, links to fixture CVEs."""
    queued = sorted(tiers)[:2]

    def link(cve, via, review, counts):
        return {
            "cve": cve,
            "via": via,
            "evidence": [] if via == "threatfox_tag" else [{"doc_id": "x", "surface": "Family A"}],
            "tier": tiers.get(cve),
            "in_kev": cve == kev_cve,
            "review": review,
            "counts_for_priority": counts,
        }

    def family(rank, name, cats, source, cves, kev, high, rows, growth, why, sw=None):
        return {
            "rank": rank,
            "family": name,
            "categories": cats,
            "category_source": source,
            "attack": {
                "software": sw,
                "name": "Example Software" if sw else None,
                "techniques": ["T1190", "T1059"] if sw else [],
                "tactics": ["execution", "initial-access"] if sw else [],
            },
            "cves": cves,
            "priority_keys": {
                "linked_kev_cves": kev,
                "linked_high_tier_cves": high,
                "ioc_rows": rows,
                "ioc_growth": growth,
            },
            "why": why,
        }

    return {
        "snapshot_date": DATES["snapshot"],
        "families": [
            family(
                1,
                "Example Family A",
                ["ransomware"],
                "owner",
                [
                    link(kev_cve, "threatfox_tag", "unreviewed", True),
                    link(queued[0], "mention:reference_page", "correct", True),
                ],
                1,
                1,
                40,
                12,
                ["linked to 1 CVE in CISA KEV (confirmed exploited)", "ransomware", "40 IOCs"],
                sw="S9999",
            ),
            family(
                2,
                "Example Family B",
                ["bot", "ddos"],
                "owner",
                [link(queued[1], "mention:reference_page", "rejected", False)],
                0,
                0,
                40,
                3,
                ["IOCs up +3 in the last 30 days (9 vs 6)", "40 IOCs"],
            ),
            family(3, "Example Family C", ["unknown"], "owner", [], 0, 0, 40, -2, ["40 IOCs"]),
            family(
                30,
                "Example Family D",
                ["remote-access-trojan"],
                "misp",
                [link(queued[1], "mention:reference_page", "correct", True)],
                0,
                1,
                12,
                0,
                ["linked to 1 critical/high-tier CVE in the queue", "12 IOCs"],
            ),
        ],
        "category_rows": {
            "bot": 40,
            "ddos": 40,
            "ransomware": 40,
            "remote-access-trojan": 12,
            "unknown": 40,
        },
        "kev_ransomware_cves": ["CVE-2099-0001", "CVE-2099-0002"],
        "summary": {"category_source": {"owner": 3, "misp": 1}},
        "review": {
            "labeller": "fixture labeller",
            "links": {"precision": {"all": {"n": 2, "correct": 1, "ci95": [0.09, 0.91]}}},
        },
    }


def build() -> dict[str, dict]:
    recs = records()
    results = _evals()
    fitted = export.refit(risk_eval.build_windows(recs, DATES))
    windows = risk_eval.build_windows(recs, DATES)
    positives = {w: int(windows[w].y.sum()) for w in cfg.CUTOFFS}
    rows_n = sum(len(windows[w].y) for w in cfg.CUTOFFS)
    scored = export.score_snapshot(recs, DATES["snapshot"], fitted)
    tiered = [
        r["cve"] for r, t in zip(scored["records"], scored["tier"], strict=True) if t != "baseline"
    ]
    context = {
        c: {
            "assigner": "fixture-cna@example.org",
            "affected": [{"vendor": "Example Vendor", "product": "Example Product"}],
            "description": export.truncate(
                export.defang_text(
                    f"Synthetic fixture record {c}: an example product at https://vendor.example.com/"
                    f"product lets a remote attacker do something; see 192.0.2.10 for the test lab."
                )
            ),
        }
        for c in tiered
    }
    risk = export.build_risk(
        scored, fitted, positives, rows_n, results["risk"], context, DATES["snapshot"]
    )
    docs = _ioc_docs([r["cve"] for r in scored["records"]])
    iocs = export.build_iocs(docs, *_feeds())
    slim = {r["cve"]: r for r in scored["records"]}
    techniques = [
        Technique("T1190", "Exploit Public-Facing Application", ("initial-access",), ""),
        Technique("T1203", "Exploitation for Client Execution", ("execution",), ""),
        Technique("T1068", "Exploitation for Privilege Escalation", ("privilege-escalation",), ""),
        Technique("T1059", "Command and Scripting Interpreter", ("execution",), ""),
    ]
    ctid = [
        {"cve": _cve(90000 + i), "type": t, "technique": techniques[(i + k) % len(techniques)].id}
        for i in range(60)
        for k, t in enumerate(("exploitation_technique", "primary_impact", "secondary_impact"))
    ]
    graphs = {
        "weakness": export.weakness_graph(risk["rows"], slim, PILLARS),
        "attack": export.attack_graphs(ctid, {}, techniques),
        "shared_hosts": export.shared_host_graph(
            docs, export.tier_lookup(scored), scored["in_kev"]
        ),
    }
    shown_tiers = {c: t for c, t in export.tier_lookup(scored).items() if t != "baseline"}
    kev_cve = next(iter(sorted(scored["in_kev"])), _cve(99999))
    threats = export.build_threats(
        _threats_doc(shown_tiers, kev_cve),
        shown_tiers,
        {
            "T1190": "Exploit Public-Facing Application",
            "T1059": "Command and Scripting Interpreter",
        },
    )
    evals = export.build_eval(results)
    evals["sources_sha256"] = {n: "0" * 64 for n in export.EVALS}
    versions = export.epss_versions(recs)
    meta = {
        "schema_version": 1,
        "snapshot_date": DATES["snapshot"],
        "as_of_dates": DATES,
        "kev_catalog_version": "fixture",
        "epss_model_versions": versions,
        "git": {"commit": "fixture", "dirty": False},
        "config_sha256": "0" * 64,
        "inputs_sha256": {"fixture": "0" * 64},
        "disclosures": [
            "SYNTHETIC FIXTURE: every number on this dashboard is made up.",
            *export.disclosures(
                versions,
                sum(positives.values()) / rows_n,
                results["risk"]["folds"],
                sum(r["age_days"] <= export.RECENT_DAYS for r in risk["rows"]),
                len(risk["rows"]),
                -0.5,
            ),
        ],
    }
    return export.validate(
        {
            "meta.json": meta,
            "risk.json": risk,
            "iocs.json": iocs,
            "graphs.json": graphs,
            "eval.json": evals,
            "threats.json": threats,
        }
    )


if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "web/fixtures")
    for name, size in export.write(out, build()).items():
        print(f"  wrote {out / name} ({size / 1e3:.0f} kB)")
