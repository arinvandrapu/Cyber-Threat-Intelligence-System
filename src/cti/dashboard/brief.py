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
from cti.stats import wilson
from cti.threats.config import KEV_LINK_SOURCES

TOP = 10  # rows in the KEV and watch-list tables
EXPLOIT_CODE = ("exploitdb", "metasploit")  # Nuclei templates are mostly detection checks
Z95 = 1.959964  # as risk-eval
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
    """The brief's confidence key, on the number of positive events a judgement rests on:
    low under 10; moderate under 50 or when another measure points the other way; else
    high."""
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
        "commit": meta["git"].get("commit"),
        "dirty": meta["git"].get("dirty"),
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
        "critical_fraction": next(
            t["max_rank_fraction"] for t in risk["tiers"] if t["name"] == "critical"
        ),
        "watch": [
            {
                "rank": r["rank"],
                "cve": r["cve"],
                "tier": r["tier"],
                "name": r["context"].get("name") or "",
                "age_days": r["age_days"],
                "epss": r["epss"],
                "epss_percentile": r["epss_percentile"],
                "exploit_code": any(s in EXPLOIT_CODE for s in r["exploit_sources"]),
                "drivers": _drivers(r["contributions"]),
            }
            for r in watch
        ],
        "watch_recent": sum(1 for r in watch if r["age_days"] <= RECENT_DAYS),
        "watch_exploit_code": sum(
            1 for r in watch if any(s in EXPLOIT_CODE for s in r["exploit_sources"])
        ),
        # recomputed from the counts: the export's interval is rounded to 4 places, too
        # coarse for the baseline tier's 0.016%
        "history": [
            hist[t] | {"wilson95": list(wilson(hist[t]["kev_positives"], hist[t]["cves"], Z95, 6))}
            for t in ("critical", "high", "elevated", "baseline")
        ],
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
        # rests on the model's top-100 hits (6 today), not on all 68 positives
        "confidence_model": confidence(
            int(pooled["logistic"]["hits@100"]), ap_counter or not top1["excludes_zero"]
        ),
        "ap_counter": ap_counter,
        "top1_excludes_zero": top1["excludes_zero"],
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


def _plural(n: float, one: str, many: str) -> str:
    return one if n == 1 else many


_MD = re.compile(r"([|*_`\\])")


def _cell(text: str, limit: int | None = None) -> str:
    """Escape Markdown; shorten at a word boundary to ``limit`` characters."""
    if limit and len(text) > limit:
        cut = text[: limit - 1].rsplit(" ", 1)[0]
        text = cut.rstrip(" ([{'\"-:,;\u2013") + "…"  # \u2013: en dash
    return _MD.sub(r"\\\1", text)


def _epss(p: float, percentile: float | None) -> str:
    """EPSS as a probability, with its rank as "top x%" (clearer than "99.98th")."""
    prob = f"{p * 100:.2f}%" if p >= 0.995 else _pct(p)
    if percentile is None:
        return prob
    top = (1 - percentile) * 100
    if top <= 0:
        return f"{prob} (highest)"
    return f"{prob} (top {top:.2g}%)" if top < 1 else f"{prob} (top {top:.0f}%)"


def render(f: dict) -> str:
    day = f["snapshot_date"]
    crit, hist = f["tiers"]["critical"], {h["name"]: h for h in f["history"]}
    c, base = hist["critical"], hist["baseline"]
    shown = len(f["watch"])
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
        "Every number is read or computed from the export; judgements are labelled as such.\n"
    )

    add("## Bottom line up front\n")
    add(
        f"- **Known exploited (observed):** CISA lists {_n(f['kev_total'])} CVEs with reliable "
        f"evidence of active exploitation; all warrant remediation. {_n(f['kev_linked'])} "
        f"{_plural(f['kev_linked'], 'is', 'are')} linked to a tracked threat family and "
        f"{_n(f['kev_ransomware'])} {_plural(f['kev_ransomware'], 'has', 'have')} known "
        f"ransomware use (the groups overlap); Section 1 shows the first {len(f['kev_top'])} "
        "in that order."
    )
    ex = f["watch_exploit_code"]
    add(
        f"- **Watch (ranked, not predicted):** {_n(crit)} "
        f"{_plural(crit, 'CVE', 'CVEs')} not yet in KEV sit in the critical tier (top "
        f"{f['critical_fraction'] * 100:g}% of {_n(f['ranked_cves'])} scored); "
        f"{'all' if ex == shown else ex} of the {shown} highest-ranked "
        f"{_plural(ex, 'has', 'have')} a public exploit (ExploitDB or Metasploit; Section 2)."
    )
    if f["threats_available"]:
        k = len(f["early"])
        add(
            f"- **Early warning (observed):** {k} of {_n(f['queue'])} queued CVEs "
            f"{_plural(k, 'is', 'are')} linked to a threat family and not yet in KEV "
            "(Section 3)."
        )
    counter = f["ap_counter"] or not f["top1_excludes_zero"]
    judged = (
        "the model adds value over EPSS only at the very top of the list"
        if counter
        else "the model ranks future KEV additions better than EPSS"
    )
    against = []
    if f["ap_counter"]:
        against.append("EPSS has the higher mean average precision")
    if not f["top1_excludes_zero"]:
        against.append("the two are level at the top 1%")
    add(
        f"- **Judgement:** {judged}. Over {f['test_windows']} forward test windows its top 100 "
        f"caught {_n(f['hits_model'])} of {_n(f['positives'])} later KEV additions against "
        f"{_n(f['hits_epss'])} for EPSS ({f['diff']:+.0f}, 95% CI {_ci(f['diff_ci'])}; "
        f"pre-registered verdict: {f['verdict']})"
        + (f", but {' and '.join(against)}." if against else ".")
        + f" *Confidence: {f['confidence_model']}* (rests on {_n(f['hits_model'])} hits)."
    )
    ratio = c["hit_rate"] / base["hit_rate"] if base["hit_rate"] else None
    add(
        "- **Judgement:** the critical tier concentrates future KEV listings. Historically its "
        f"CVEs entered KEV within 180 days at {_pct(c['hit_rate'])} (95% CI "
        f"{_ci(c['wilson95'], True)})"
        + (
            f", about {float(f'{ratio:.2g}'):,.0f} times the baseline tier's "
            f"{_pct(base['hit_rate'], 3)}"
            if ratio
            else ""
        )
        + f". *Confidence: {f['confidence_tier']}* ({c['kev_positives']} critical-tier "
        f"{_plural(c['kev_positives'], 'positive', 'positives')}).\n"
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
        "Every CVE here is in CISA's Known Exploited Vulnerabilities catalog (reliable "
        "evidence of active exploitation), so all of them warrant remediation. The order is a "
        f'fixed sort, not a risk ranking: {order}. "Known ransomware use" is CISA\'s '
        f"`knownRansomwareCampaignUse` field ({_n(f['kev_ransomware'])} of "
        f'{_n(f["kev_total"])}); "Unknown" means CISA is not aware of ransomware use, not '
        "that there is none. CISA's due dates bind US federal civilian agencies; "
        f"{_n(f['kev_past_due'])} of {_n(f['kev_total'])} have passed. A family named on a "
        "reference page is the weakest link type (see the link review in Section 4).\n"
    )
    add("| # | CVE | Product | Why it is in this position |")
    add("|---|---|---|---|")
    for e in f["kev_top"]:
        add(f"| {e['rank']} | {e['cve']} | {_cell(e['product'])} | {_cell(e['why'])} |")
    add("")

    add("## 2. Watch list: highest-ranked CVEs not yet in KEV\n")
    train = " and ".join(f["epss_train"])
    add(
        "A ranking, not a prediction: the model's score is not a probability and this "
        "snapshot's ranking is not itself evaluated (only past tiers are, below). Newer CVEs "
        f"rank higher: {f['watch_recent']} of these {shown} were published within "
        f"{RECENT_DAYS} days of the snapshot. Snapshot EPSS is model {f['epss_snapshot']}"
        + (f"; the model was trained on {train}." if train else ".")
        + " Nuclei templates are mostly detection checks, not exploits.\n"
    )
    add("| Rank | CVE | Name | Age (days) | EPSS (rank among all CVEs) | Top drivers |")
    add("|---|---|---|---|---|---|")
    for r in f["watch"]:
        epss = _epss(r["epss"], r["epss_percentile"]) if r["epss"] is not None else "none"
        add(
            f"| {_n(r['rank'])} | {r['cve']} | {_cell(r['name'], 60)} | {r['age_days']} | "
            f"{epss} | {', '.join(r['drivers'])} |"
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
            f"{k} of {_n(f['queue'])} queued CVEs {_plural(k, 'carries', 'carry')} a "
            "threat-family link that counts for priority. Threat links never change the rank, "
            "and this signal has not been evaluated as a predictor.\n"
        )
        for e in f["early"]:
            add(f"- {e['cve']} (rank {_n(e['rank'])}, {e['tier']}): {_cell('; '.join(e['via']))}")
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
            "exploited the CVE. Rejected links are left out. IOC counts are the family's "
            "ThreatFox rows in the snapshot; the change is IOCs first seen in the last 30 days "
            "minus the 30 days before.\n"
        )
        add(
            "| # | Family | Categories | KEV / queued CVEs | ThreatFox IOCs (30-day change) "
            "| Linked CVEs |"
        )
        add("|---|---|---|---|---|---|")
        for fam in f["families"]:
            name = fam["family"] + (f" (ATT&CK {fam['attack']})" if fam["attack"] else "")
            listed = [f"{x['cve']} ({x['source']})" for x in fam["links"][:3]]
            more = len(fam["links"]) - len(listed)
            linked = "; ".join(listed) + (f"; +{more} more" if more else "") or "none"
            add(
                f"| {fam['rank']} | {_cell(name)} | {_cell(', '.join(fam['categories']) or 'none')}"
                f" | {fam['kev_cves']} / {fam['queued_cves']} | {_n(fam['ioc_rows'])} "
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
        f"1. Confirm exposure to the {_n(f['kev_linked'])} threat-linked KEV "
        f"{_plural(f['kev_linked'], 'CVE', 'CVEs')}, then the rest of the "
        f"{_n(f['kev_ransomware'])} with known ransomware use; remediate per vendor guidance."
    )
    add(
        f"2. Triage the {_n(crit)} critical-tier {_plural(crit, 'CVE', 'CVEs')}, starting with "
        "the highest-ranked that have a public exploit (Section 2); recheck as EPSS and KEV "
        "update."
    )
    step = 3
    if f["threats_available"] and f["early"]:
        add(f"{step}. Track the early-warning CVEs in Section 3 for a KEV listing.")
        step += 1
    hunts = [x for x in f["families"] if x["attack"]]
    if hunts:
        add(
            f"{step}. Hunt: map detection coverage against the ATT&CK techniques attributed to "
            + ", ".join(
                f"{x['family']} ({x['attack']}, {x['techniques']} techniques)" for x in hunts
            )
            + " (e.g. as ATT&CK Navigator layers) and close gaps, rather than hunting every "
            "technique."
        )
    add("")

    add("## Annex\n")
    add("### A. Confidence and method\n")
    add(
        f"- Forward test: {f['rule']}; {f['test_windows']} rolling windows, "
        f"{_n(f['positives'])} KEV additions. Model {_n(f['hits_model'])} vs EPSS "
        f"{_n(f['hits_epss'])} in the top 100 ({f['diff']:+.0f}, 95% CI {_ci(f['diff_ci'])})."
    )
    add(
        f"- Against it: EPSS mean average precision {f['ap_epss']:.4f} vs {f['ap_model']:.4f} "
        f"for the model; at the top 1% the difference is {f['top1_diff']:+.0f} "
        f"(95% CI {_ci(f['top1_ci'])})."
    )
    add(
        "- Confidence key, on the number of positive events a judgement rests on: low under "
        "10; moderate under 50 or when another measure points the other way; otherwise high. "
        "A confidence label never shares a sentence with a likelihood word.\n"
    )

    add("### B. Limitations\n")
    add("From the export's own disclosures, verbatim:\n")
    for line in f["disclosures"]:
        add(f"- {line}")
    add("")

    add("### C. Sources\n")
    add("| Source | Version / date | Use and reliability |")
    add("|---|---|---|")
    add(
        f"| CISA KEV | catalog {f['kev_catalog_version']} | Labels and Section 1: reliable "
        "evidence of active exploitation; authoritative for listing, not for when "
        "exploitation began |"
    )
    add(
        f"| FIRST EPSS | model {f['epss_snapshot']}, scores of {day} | Model input "
        "(percentile at each cutoff). FIRST's estimate of the probability that exploitation "
        "activity is observed in the next 30 days: threat only, not a risk score (no impact "
        "or exposure) |"
    )
    add(
        f"| NVD | snapshot {day} | Scope and the age input (publication date); CVSS, CWE, "
        "assigner and descriptions are context only |"
    )
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
    commit = f"`{f['commit']}`" if f["commit"] else "an unknown commit"
    state = {True: "dirty working tree", False: "clean"}.get(f["dirty"], "state unknown")
    add(
        f"Reproducibility: export from {commit} ({state}); export files SHA-256 "
        f"`{f['export_sha256']}`. Regenerate with `cti report --date {day}`; "
        f"`cti report --check <this file>` confirms it.\n"
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
