"""``cti report``: a short analyst brief (Markdown) generated from a dashboard export.

Two steps, so each can be tested: ``facts(export_dir)`` reads and validates the export
and computes every number the brief states; ``render(facts)`` only words them. Nothing
comes from the clock or the network, so the same export always gives the same brief.

Conventions (Phase 9.1 due diligence): TLP:CLEAR (public data only), bottom line up
front, observed facts kept apart from assessed judgements, a confidence label never in
the same sentence as a likelihood word (ICD 203), each source named with its version.
Wording rules from the dashboard: the KEV order is a fixed sort, not a risk ranking; the
risk queue is a ranking, not a prediction; a threat link records that a source connects
a family and a CVE, never that the family exploited it. No indicators and no CVE
descriptions appear (abuse.ch terms: family names and counts only).
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from cti.dashboard import schema
from cti.threats.config import KEV_LINK_SOURCES

TOP = 10  # rows in the KEV and watch-list tables
TOP_FAMILIES = 5
RECENT_DAYS = 30

# Mirrors FEATURE_LABEL in web/src/format.ts (a test keeps them in sync), except that a
# positive age contribution reads as what it is: recently published.
FEATURE_LABEL = {
    "epss_logit": "EPSS percentile",
    "epss_missing": "No EPSS score",
    "ssvc_exploitation": "SSVC: PoC / exploited",
    "ssvc_automatable": "SSVC: automatable",
    "ssvc_total_impact": "SSVC: full-control impact",
    "ssvc_missing": "No SSVC assessment",
    "exploitdb": "ExploitDB entry",
    "metasploit": "Metasploit module",
    "nuclei": "Nuclei template",
    "log_age_days": "Age (older ranks lower)",
}
RECENT_LABEL = "Recently published"


def export_sha256(export_dir: Path) -> str:
    """One hash over the export's files (name and bytes, in name order)."""
    h = hashlib.sha256()
    for name in sorted(schema.FILES):
        h.update(name.encode() + b"\0" + (export_dir / name).read_bytes() + b"\0")
    return h.hexdigest()


def confidence(positives: int, counter_evidence: bool) -> str:
    """The brief's confidence key: low under 10 positives; moderate under 50 or when
    another measure points the other way; otherwise high."""
    if positives < 10:
        return "low"
    if positives < 50 or counter_evidence:
        return "moderate"
    return "high"


def _load(export_dir: Path) -> dict[str, dict]:
    docs = {}
    for name, model in schema.FILES.items():
        raw = json.loads((export_dir / name).read_text(encoding="utf-8"))
        model.model_validate(raw)  # the brief only states what the schema guarantees
        docs[name] = raw
    return docs


def _drivers(contributions: dict[str, float], n: int = 3) -> list[str]:
    top = sorted(((v, k) for k, v in contributions.items() if v > 0), reverse=True)[:n]
    return [RECENT_LABEL if k == "log_age_days" else FEATURE_LABEL[k] for _, k in top]


def facts(export_dir: Path) -> dict:
    d = _load(export_dir)
    meta, risk, ev, threats, kev = (
        d["meta.json"],
        d["risk.json"],
        d["eval.json"]["risk"],
        d["threats.json"],
        d["kev.json"]["entries"],
    )
    day = meta["snapshot_date"]
    versions = meta["epss_model_versions"]
    rows = sorted(risk["rows"], key=lambda r: r["rank"])
    tiers = {t["name"]: t["cves"] for t in risk["tiers"]}
    hist = {t["name"]: t for t in risk["historical_tiers"]}
    pooled = {m: ev["methods"][m]["pooled"] for m in ("logistic", "epss")}
    top1 = ev["secondary_paired"]["logistic_minus_epss_hits@1%"]
    decision = ev["decision"]["logistic_minus_epss_hits@100"]
    ap_counter = (
        pooled["epss"]["mean_average_precision"] > pooled["logistic"]["mean_average_precision"]
    )
    watch = rows[:TOP]
    queued = {r["cve"]: r for r in rows}

    out = {
        "snapshot_date": day,
        "kev_catalog_version": meta["kev_catalog_version"],
        "epss_snapshot": ", ".join(versions.get("snapshot", [])) or "unknown",
        "epss_train": sorted({v for k, vs in versions.items() if k != "snapshot" for v in vs}),
        "commit": meta["git"]["commit"],
        "dirty": meta["git"]["dirty"],
        "export_sha256": export_sha256(export_dir),
        "disclosures": meta["disclosures"],
        "kev_total": len(kev),
        "kev_linked": sum(1 for e in kev if e["families"]),
        "kev_ransomware": sum(1 for e in kev if e["ransomware_use"] == "Known"),
        "kev_past_due": sum(1 for e in kev if e["due_date"] and e["due_date"] < day),
        "kev_top": [
            {
                "rank": e["priority_rank"],
                "cve": e["cve"],
                "product": " ".join(x for x in (e["vendor"], e["product"]) if x),
                "why": e["why"],
            }
            for e in kev[:TOP]
        ],
        "ranked_cves": risk["ranked_cves"],
        "queue": len(rows),
        "tiers": {t: tiers[t] for t in ("critical", "high", "elevated")},
        "watch": [
            {
                "rank": r["rank"],
                "cve": r["cve"],
                "tier": r["tier"],
                "name": r["context"].get("name") or "",
                "age_days": r["age_days"],
                "epss": r["epss"],
                "epss_percentile": r["epss_percentile"],
                "exploit_code": bool(r["exploit_sources"]),
                "drivers": _drivers(r["contributions"]),
            }
            for r in watch
        ],
        "watch_recent": sum(1 for r in watch if r["age_days"] <= RECENT_DAYS),
        "watch_exploit_code": sum(1 for r in watch if r["exploit_sources"]),
        "history": [hist[t] for t in ("critical", "high", "elevated", "baseline")],
        "test_windows": len(ev["folds"]),
        "positives": pooled["logistic"]["positives"],
        "hits_model": pooled["logistic"]["hits@100"],
        "hits_epss": pooled["epss"]["hits@100"],
        "diff": decision["difference_hits"],
        "diff_ci": decision["ci95"],
        "verdict": ev["decision"]["verdict"],
        "rule": ev["decision"]["rule"],
        "ap_model": pooled["logistic"]["mean_average_precision"],
        "ap_epss": pooled["epss"]["mean_average_precision"],
        "top1_diff": top1["difference_hits"],
        "top1_ci": top1["ci95"],
        "confidence_model": confidence(
            int(pooled["logistic"]["positives"]), ap_counter or not top1["excludes_zero"]
        ),
        "confidence_tier": confidence(hist["critical"]["kev_positives"], False),
        "threats_available": threats["available"],
        "threats_stale": threats["stale"],
    }
    if not threats["available"]:
        return out | {"families": [], "early": [], "review": None, "families_total": 0}

    def links(family: dict) -> list[dict]:
        return [
            {"cve": x["cve"], "source": KEV_LINK_SOURCES[x["via"]], "in_kev": x["in_kev"]}
            for x in family["links"]
            if x["review"] != "rejected"
        ]

    early: dict[str, dict] = {}
    for f in threats["families"]:
        for x in f["links"]:
            if x["counts_for_priority"] and x["cve"] in queued:
                row = queued[x["cve"]]
                e = early.setdefault(
                    x["cve"], {"cve": x["cve"], "rank": row["rank"], "tier": row["tier"], "via": []}
                )
                e["via"].append(f"{f['family']} ({KEV_LINK_SOURCES[x['via']]})")
    return out | {
        "families_total": threats["families_total"],
        "families": [
            {
                "rank": f["rank"],
                "family": f["family"],
                "attack": f["attack_software"],
                "techniques": len(f["techniques"]),
                "categories": f["categories"],
                "kev_cves": f["linked_kev_cves"],
                "queued_cves": f["linked_high_tier_cves"],
                "ioc_rows": f["ioc_rows"],
                "ioc_growth": f["ioc_growth"],
                "links": links(f),
            }
            for f in threats["families"][:TOP_FAMILIES]
        ],
        "early": sorted(early.values(), key=lambda e: e["rank"]),
        "review": threats["review"],
    }


# ---- rendering ---------------------------------------------------------------------------


def _n(x: float) -> str:
    return f"{x:,.0f}" if float(x).is_integer() else f"{x:,.1f}"


def _pct(x: float, digits: int = 1) -> str:
    return f"{x * 100:.{digits}f}%"


def _ci(ci: list[float], pct: bool = False, digits: int = 1) -> str:
    if pct:
        return f"{_pct(ci[0], digits)} to {_pct(ci[1], digits)}"
    lo, hi = ci
    return f"{lo:+,.0f} to {hi:+,.0f}"


def _cell(text: str, limit: int | None = None) -> str:
    if limit and len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text.replace("|", "\\|")


def _epss(p: float, percentile: float) -> str:
    """EPSS as a probability, with its rank as "top x%" (clearer than "99.98th")."""
    prob = f"{p * 100:.2f}%" if p >= 0.995 else _pct(p)
    top = (1 - percentile) * 100
    return f"{prob} (top {top:.2g}%)" if top < 1 else f"{prob} (top {top:.0f}%)"


def _cves(n: int, what: str = "") -> str:
    """ "1 threat-linked KEV CVE", "26 threat-linked KEV CVEs"."""
    return f"{_n(n)} {what + ' ' if what else ''}CVE{'' if n == 1 else 's'}"


def _all_or(k: int, n: int) -> str:
    return f"all {n}" if k == n else f"{k} of the top {n}"


def render(f: dict) -> str:
    day = f["snapshot_date"]
    crit, hist = f["tiers"]["critical"], {h["name"]: h for h in f["history"]}
    c = hist["critical"]
    lines: list[str] = []
    add = lines.append

    add("**TLP:CLEAR**\n")
    add(f"# Vulnerability Intelligence Brief: {day}\n")
    add(
        f"Data cut-off {day} · CISA KEV catalog {f['kev_catalog_version']} · "
        f"EPSS model {f['epss_snapshot']} · generated by `cti report` from the dashboard "
        "export\n"
    )
    add(
        "> Portfolio sample built only from public data; not an operational product. "
        "Every number is read from the export; judgements are labelled as such.\n"
    )

    add("## Bottom line up front\n")
    add(
        f"- **Known exploited (observed):** all {_n(f['kev_total'])} CVEs in CISA KEV are "
        f"confirmed exploited and warrant remediation. {_n(f['kev_linked'])} "
        f"{'is' if f['kev_linked'] == 1 else 'are'} linked to a tracked threat family and "
        f"{_n(f['kev_ransomware'])} have known ransomware use; Section 1 lists them in that "
        "order."
    )
    add(
        f"- **Watch (ranked, not predicted):** {_n(crit)} CVEs not yet in KEV sit in the "
        f"critical tier (top 0.1% of {_n(f['ranked_cves'])} scored); "
        f"{_all_or(f['watch_exploit_code'], TOP)} of the highest-ranked have public exploit "
        "code (Section 2)."
    )
    if f["threats_available"]:
        add(
            f"- **Early warning (observed):** {len(f['early'])} of {_n(f['queue'])} queued CVEs "
            "is linked to a threat family before any KEV listing (Section 3)."
            if len(f["early"]) == 1
            else f"- **Early warning (observed):** {len(f['early'])} of {_n(f['queue'])} queued "
            "CVEs are linked to a threat family before any KEV listing (Section 3)."
        )
    add(
        f"- **Judgement:** over {f['test_windows']} forward test windows the model's top 100 "
        f"caught {_n(f['hits_model'])} of {_n(f['positives'])} later KEV additions against "
        f"{_n(f['hits_epss'])} for EPSS ({f['diff']:+.0f}, 95% CI {_ci(f['diff_ci'])}; "
        f"pre-registered verdict: {f['verdict']}). *Confidence: {f['confidence_model']}* "
        f"({_n(f['positives'])} positives; EPSS has the higher mean average precision)."
        if f["ap_epss"] > f["ap_model"]
        else f"- **Judgement:** over {f['test_windows']} forward test windows the model's top "
        f"100 caught {_n(f['hits_model'])} of {_n(f['positives'])} later KEV additions against "
        f"{_n(f['hits_epss'])} for EPSS ({f['diff']:+.0f}, 95% CI {_ci(f['diff_ci'])}; "
        f"pre-registered verdict: {f['verdict']}). *Confidence: {f['confidence_model']}* "
        f"({_n(f['positives'])} positives)."
    )
    add(
        f"- **Judgement:** historically, critical-tier CVEs entered KEV within 180 days at "
        f"{_pct(c['hit_rate'])} (95% CI {_ci(c['wilson95'], True)}) against "
        f"{_pct(hist['baseline']['hit_rate'], 3)} for the baseline tier. "
        f"*Confidence: {f['confidence_tier']}* ({c['kev_positives']} critical-tier positives).\n"
    )

    order = (
        "linked to a tracked threat family (by a link that counts for priority), then CISA's "
        "known ransomware use, then the newest CISA listing"
        if f["threats_available"]
        else "CISA's known ransomware use, then the newest CISA listing (no threat catalog in "
        "this export)"
    )
    add("## 1. Known exploited: threat-linked first\n")
    add(
        "Every CVE here is in CISA's Known Exploited Vulnerabilities catalog, so exploitation "
        "is confirmed and all of them warrant remediation. The order is a fixed sort, not a "
        f'risk ranking: {order}. "Known ransomware use" is CISA\'s '
        f"`knownRansomwareCampaignUse` field ({_n(f['kev_ransomware'])} of "
        f'{_n(f["kev_total"])}); "Unknown" means CISA is not aware of ransomware use, not '
        f"that there is none. CISA's due dates bind US federal civilian agencies; "
        f"{_n(f['kev_past_due'])} of {_n(f['kev_total'])} have passed.\n"
    )
    add("| # | CVE | Product | Why it is first |")
    add("|---|---|---|---|")
    for e in f["kev_top"]:
        add(f"| {e['rank']} | {e['cve']} | {_cell(e['product'])} | {_cell(e['why'])} |")
    add("")

    add("## 2. Watch list: highest-ranked CVEs not yet in KEV\n")
    add(
        "A ranking, not a prediction: the model's score is not a probability and this "
        "snapshot's ranking is not itself evaluated (only past tiers are, below). Newer CVEs "
        f"rank higher: {f['watch_recent']} of these {TOP} were published within {RECENT_DAYS} "
        f"days of the snapshot. Snapshot EPSS is model {f['epss_snapshot']}; the model was "
        f"trained on {' and '.join(f['epss_train'])}.\n"
    )
    add("| Rank | CVE | Name | Age (days) | EPSS (rank among all CVEs) | Top drivers |")
    add("|---|---|---|---|---|---|")
    for r in f["watch"]:
        epss = _epss(r["epss"], r["epss_percentile"]) if r["epss"] is not None else "none"
        add(
            f"| {_n(r['rank'])} | {r['cve']} | {_cell(r['name'], 60)} | {r['age_days']} | {epss} | "
            f"{', '.join(r['drivers'])} |"
        )
    add("")
    add("Tier back-test (the same procedure on past windows; KEV listing within 180 days):\n")
    add("| Tier | CVEs | Entered KEV | Rate (95% CI) |")
    add("|---|---|---|---|")
    for h in f["history"]:
        digits = 1 if h["hit_rate"] >= 0.001 else 3
        add(
            f"| {h['name']} | {_n(h['cves'])} | {h['kev_positives']} | "
            f"{_pct(h['hit_rate'], digits)} ({_ci(h['wilson95'], True, digits)}) |"
        )
    add("")

    add("## 3. Early warnings\n")
    if not f["threats_available"]:
        add(_threats_missing(f))
    elif not f["early"]:
        add("No queued CVE is linked to a threat family in this export.\n")
    else:
        k = len(f["early"])
        add(
            f"{k} of {_n(f['queue'])} queued CVEs {'carries' if k == 1 else 'carry'} a "
            "threat-family link that counts for priority. Threat links never change the rank, "
            "and this signal has not been evaluated as a predictor.\n"
        )
        for e in f["early"]:
            add(f"- {e['cve']} (rank {_n(e['rank'])}, {e['tier']}): {'; '.join(e['via'])}")
        add("")

    add("## 4. Threat context\n")
    if not f["threats_available"]:
        add(_threats_missing(f))
    else:
        add(
            f"The first {len(f['families'])} of {_n(f['families_total'])} tracked families by a "
            "declared priority heuristic (not validated). A link records that a source "
            "connects the family and the CVE (its ATT&CK entry cites it, a ThreatFox reporter "
            "tagged it, or a reference page names both); it does not show the family "
            "exploited the CVE. Rejected links are left out.\n"
        )
        add(
            "| # | Family | Categories | KEV / queued CVEs | IOC rows (30-day change) "
            "| Linked CVEs |"
        )
        add("|---|---|---|---|---|---|")
        for fam in f["families"]:
            name = fam["family"] + (f" (ATT&CK {fam['attack']})" if fam["attack"] else "")
            shown = [f"{x['cve']} ({x['source']})" for x in fam["links"][:3]]
            more = len(fam["links"]) - len(shown)
            linked = "; ".join(shown) + (f"; +{more} more" if more else "") or "none"
            add(
                f"| {fam['rank']} | {_cell(name)} | {', '.join(fam['categories']) or 'none'} | "
                f"{fam['kev_cves']} / {fam['queued_cves']} | {_n(fam['ioc_rows'])} "
                f"({fam['ioc_growth']:+,}) | {_cell(linked)} |"
            )
        add("")
        rv = f["review"]
        if rv:
            add(
                f"Link review: {rv['links_correct']} of {rv['links_reviewed']} links correct "
                f"(95% CI {_ci(rv['link_precision_ci95'], True, 0)}); judged from evidence "
                f"alone, {rv['links_judged_correct']} of {rv['links_judged']} "
                f"({_ci(rv['judged_precision_ci95'], True, 0)}). Labeller: {rv['labeller']}.\n"
            )

    add("## 5. Recommended actions\n")
    add(
        f"1. Confirm exposure to the {_cves(f['kev_linked'], 'threat-linked KEV')}, then the "
        f"{_n(f['kev_ransomware'])} with known ransomware use; remediate per vendor guidance."
    )
    add(
        f"2. Triage the {_cves(crit, 'critical-tier')}, starting with the highest-ranked that "
        "have public exploit code (Section 2); recheck as EPSS and KEV update."
    )
    step = 3
    if f["threats_available"] and f["early"]:
        add(f"{step}. Track the early-warning CVEs in Section 3 for a KEV listing.")
        step += 1
    hunts = [x for x in f["families"] if x["attack"]]
    if hunts:
        add(
            f"{step}. Hunt: check detection coverage against the ATT&CK technique sets of "
            + ", ".join(
                f"{x['family']} ({x['attack']}, {x['techniques']} techniques)" for x in hunts
            )
            + "."
        )
    add("")

    add("## 6. Confidence and method\n")
    add(
        f"- Forward test: {f['rule']}; {f['test_windows']} rolling windows, "
        f"{_n(f['positives'])} KEV additions. Model {_n(f['hits_model'])} vs EPSS "
        f"{_n(f['hits_epss'])} in the top 100 ({f['diff']:+.0f}, 95% CI {_ci(f['diff_ci'])})."
    )
    add(
        f"- Against it: EPSS has mean average precision {f['ap_epss']:.4f} vs "
        f"{f['ap_model']:.4f} for the model, and at the top 1% the difference is "
        f"{f['top1_diff']:+.0f} (95% CI {_ci(f['top1_ci'])})."
    )
    add(
        "- Confidence key: low under 10 positives; moderate under 50 or when another "
        "measure points the other way; otherwise high. Confidence labels never share a "
        "sentence with a likelihood word.\n"
    )

    add("## 7. Limitations\n")
    add("From the export's own disclosures, verbatim:\n")
    for line in f["disclosures"]:
        add(f"- {line}")
    add("")

    add("## 8. Sources\n")
    add("| Source | Version / date | Use and reliability |")
    add("|---|---|---|")
    add(
        f"| CISA KEV | catalog {f['kev_catalog_version']} | Confirmed exploitation; "
        "authoritative for listing, not for exploitation start dates |"
    )
    add(
        f"| FIRST EPSS | model {f['epss_snapshot']}, scores of {day} | Model estimate of "
        "exploitation activity in the next 30 days; a probability, not a risk measure |"
    )
    add(f"| NVD | snapshot {day} | CVE records and dates; context only, not a model input |")
    add(
        f"| CISA Vulnrichment (SSVC); ExploitDB, Metasploit, Nuclei | snapshot {day} | Model "
        "inputs as of each test cutoff |"
    )
    add(
        f"| MITRE ATT&CK | snapshot {day} | Software entries and the CVEs they cite; "
        "authoritative curation |"
    )
    add(
        f"| abuse.ch ThreatFox; MISP galaxy | snapshot {day} | Family names, tags and counts "
        "only (no indicators); community-reported, unvetted |"
    )
    add("")
    state = "dirty working tree" if f["dirty"] else "clean"
    add(
        f"Reproducibility: export from commit `{f['commit']}` ({state}); export files SHA-256 "
        f"`{f['export_sha256']}`. Regenerate with `cti report --date {day}`.\n"
    )
    add("**TLP:CLEAR**")
    return "\n".join(lines) + "\n"


def _threats_missing(f: dict) -> str:
    if f["threats_stale"]:
        return (
            "Not in this export: the threat catalog was built before the risk tiers last "
            "changed. Rerun `cti threats`, then `cti export`.\n"
        )
    return "Not in this export: `cti threats` has not been run for this snapshot.\n"


_HASH = re.compile(r"export files SHA-256 `([0-9a-f]{64})`")


def stated_export_sha256(text: str) -> str | None:
    """The export hash a brief states in its reproducibility line."""
    m = _HASH.search(text)
    return m.group(1) if m else None
