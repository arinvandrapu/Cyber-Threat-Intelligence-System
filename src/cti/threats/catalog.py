"""The threat catalog: ThreatFox families with categories, ATT&CK links, CVEs and priority.

Every rule is fixed in :mod:`cti.threats.config`. Inputs are counted and looked up only;
nothing here fits a model (abuse.ch terms §7.3). The output holds per-family aggregates,
never an IOC value.

- **Categories.** Owner labels (blind review sheet) when present, else MISP galaxy
  matches on the normalised family name or synonym. Each family says which it used.
- **ATT&CK.** The ATT&CK malware or tool whose name or alias equals the family's own name
  (exactly one, else none), then that software's ``uses`` techniques and their tactics.
  ThreatFox's alias lists are not used for this join: Bashlite lists "Qbot", which is
  also QakBot's ATT&CK alias, and the Phase 5a alias index merges the two that way.
- **CVE links** carry their provenance: a ThreatFox CVE tag on the family's IOCs, or an
  unambiguous alias match (``cti extract``) in a CVE's reference page (``MENTION_ORIGINS``) whose
  surface name exactly one family claims (its name, its ATT&CK software's aliases, its
  ThreatFox aliases). KEV's ransomware flag names no family, so it links a CVE to the
  category only.
- **Priority** sorts families by ``PRIORITY_KEYS``; ``why`` lists the rules each met.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from datetime import date, datetime, timedelta

import numpy as np

from cti.nlp.aliases import key
from cti.threats import config as cfg
from cti.threats.review import Family, families, is_named

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
SOFTWARE_TYPES = ("malware", "tool")  # ATT&CK STIX types a family may resolve to
N_BOOT = 2000
SEED = 20261029


def norm(name: str) -> str:
    """``NAME_NORMALISATION``: lower case, only [a-z0-9] kept."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


def misp_index(clusters: Mapping[str, dict]) -> dict[str, set[tuple[str, str]]]:
    """Normalised name or synonym -> {(cluster file, MISP value)}."""
    index: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for cluster, data in clusters.items():
        for value in data["values"]:
            for name in (value["value"], *value.get("meta", {}).get("synonyms", [])):
                if key := norm(name):
                    index[key].add((cluster, value["value"]))
    return index


def misp_categories(matches: Iterable[tuple[str, str]]) -> tuple[str, ...]:
    cats = {cfg.MISP_FILE_CATEGORY[cluster] for cluster, _ in matches}
    return tuple(sorted(c for c in cats if c))


def attack_software(attack_docs: Iterable[dict]) -> dict[str, dict]:
    """ATT&CK software ID -> {name, type, names}: its name and aliases, unique by key."""
    out = {}
    for doc in attack_docs:
        meta = doc["metadata"]
        if meta["stix_type"] in SOFTWARE_TYPES:
            names = {doc["title"], *meta.get("aliases", [])}
            out[doc["source_id"]] = {
                "name": doc["title"],
                "type": meta["stix_type"],
                "names": names,
            }
    return out


def software_by_name(software: Mapping[str, dict]) -> dict[str, set[str]]:
    """Alias key -> software IDs claiming it."""
    by_key: dict[str, set[str]] = defaultdict(set)
    for sid, sw in software.items():
        for name in sw["names"]:
            by_key[key(name)].add(sid)
    return by_key


def threatfox_aliases(iocs: Iterable[dict]) -> dict[str, set[str]]:
    """Family -> the aliases ThreatFox lists for it."""
    out: dict[str, set[str]] = defaultdict(set)
    for doc in iocs:
        meta = doc["metadata"]
        for alias in (meta.get("malware_alias") or "").split(","):
            if alias.strip() and alias.strip() != "None":
                out[meta["malware"]].add(alias.strip())
    return out


def cve_tags(iocs: Iterable[dict]) -> dict[str, set[str]]:
    """Family -> CVEs tagged on its ThreatFox IOCs."""
    tags: dict[str, set[str]] = defaultdict(set)
    for doc in iocs:
        meta = doc["metadata"]
        for tag in meta.get("tags", []):
            if _CVE.match(tag):
                tags[meta["malware"]].add(tag.upper())
    return tags


def mentions(
    alias_rows: Iterable[dict], claims: Mapping[str, set[str]]
) -> dict[str, dict[tuple[str, str], set[tuple[str, str]]]]:
    """Family -> (CVE, origin) -> {(doc_id, surface)}: unambiguous alias matches in
    ``MENTION_ORIGINS`` whose surface name (by alias key) exactly one family claims.
    Names two families share link neither."""
    out: dict[str, dict] = defaultdict(lambda: defaultdict(set))
    for row in alias_rows:
        if row["origin"] not in cfg.MENTION_ORIGINS:
            continue
        for match in row["aliases"]:
            owners = claims.get(key(match["surface"]), set())
            if not match["ambiguous"] and len(owners) == 1:
                link = (row["cve"], row["origin"])
                out[next(iter(owners))][link].add((row["doc_id"], match["surface"]))
    return out


def growth(iocs: Iterable[dict], day: date) -> dict[str, tuple[int, int]]:
    """Family -> (IOCs first seen in the last GROWTH_DAYS, in the GROWTH_DAYS before)."""
    recent_start = day - timedelta(days=cfg.GROWTH_DAYS)
    prior_start = recent_start - timedelta(days=cfg.GROWTH_DAYS)
    counts: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for doc in iocs:
        if not doc.get("published"):
            continue
        seen = datetime.fromisoformat(doc["published"]).date()
        if recent_start < seen <= day:
            counts[doc["metadata"]["malware"]][0] += 1
        elif prior_start < seen <= recent_start:
            counts[doc["metadata"]["malware"]][1] += 1
    return {k: (v[0], v[1]) for k, v in counts.items()}


def category_rows(fams: list[Family], labels: Mapping[str, tuple[str, ...]]) -> dict:
    """IOC rows per category: named families by their labels, unattributed rows by role ID.

    Categories overlap: a family with two categories adds its rows to both, so the values
    can sum to more than the IOC total. Not a partition; never show them as shares of 100%.
    """
    rows: Counter[str] = Counter()
    for fam in fams:
        if is_named(fam):
            for cat in labels.get(fam.name) or ("unlabelled",):
                rows[cat] += fam.rows
        else:  # one category per unattributed name, even if it spans several IDs
            roles = {cfg.THREATFOX_UNKNOWN_IDS.get(fid, "unknown") for fid in fam.ids}
            rows[roles.pop() if len(roles) == 1 else "unknown"] += fam.rows
    return dict(sorted(rows.items()))


def _review_state(correct: bool | None) -> str:
    return {True: "correct", False: "rejected", None: "unreviewed"}[correct]


def _why(keys: dict[str, int], recent: int, prior: int) -> list[str]:
    why = []
    if keys["linked_kev_cves"]:
        n = keys["linked_kev_cves"]
        why.append(f"linked to {n} CVE{'s' * (n != 1)} in CISA KEV (confirmed exploited)")
    if keys["linked_high_tier_cves"]:
        n = keys["linked_high_tier_cves"]
        why.append(f"linked to {n} critical/high-tier CVE{'s' * (n != 1)} in the queue")
    if keys["ransomware"]:
        why.append("ransomware")
    if keys["ioc_growth"] > 0:
        why.append(
            f"IOCs up {keys['ioc_growth']:+,} in the last {cfg.GROWTH_DAYS} days "
            f"({recent:,} vs {prior:,})"
        )
    why.append(f"{keys['ioc_rows']:,} IOC{'s' * (keys['ioc_rows'] != 1)}")
    return why


def build(
    iocs: list[dict],
    clusters: Mapping[str, dict],
    attack_docs: Iterable[dict],
    uses: Mapping[str, set[str]],
    tactics: Mapping[str, tuple[str, ...]],
    alias_rows: Iterable[dict],
    kev: Iterable[dict],
    tiers: Mapping[str, str],
    owner: Mapping[str, tuple[str, ...]],
    day: date,
    link_review: Mapping[tuple[str, str, str], bool] | None = None,
    software_cves: Mapping[str, Mapping[str, str]] | None = None,
) -> dict:
    """The threat catalog. ``tiers``: queue CVE -> risk tier; ``owner``: blind labels;
    ``link_review``: (family, CVE, via) -> reviewed correct, which decides with
    ``TRUSTED_LINKS`` which links count toward priority; ``software_cves``: ATT&CK software
    ID -> CVE -> the ATT&CK sentence citing it (``attack_catalog.software_cves``)."""
    link_review = link_review or {}
    software_cves = software_cves or {}
    fams = families(iocs)
    named = [f for f in fams if is_named(f)]
    misp = misp_index(clusters)
    tagged = cve_tags(iocs)
    software = attack_software(attack_docs)
    by_name = software_by_name(software)
    tf_aliases = threatfox_aliases(iocs)
    resolved: dict[str, str | None] = {}
    claims: dict[str, set[str]] = defaultdict(set)
    for fam in named:
        sids = by_name.get(key(fam.name), set())
        sid = next(iter(sids)) if len(sids) == 1 else None
        resolved[fam.name] = sid
        names = {fam.name, *tf_aliases.get(fam.name, ()), *(software[sid]["names"] if sid else ())}
        for name in names:
            claims[key(name)].add(fam.name)
    mentioned = mentions(alias_rows, claims)
    grown = growth(iocs, day)
    kev_rows = list(kev)
    in_kev = {r["source_id"] for r in kev_rows}

    out, labels = [], {}
    for fam in named:
        matches = sorted(misp.get(norm(fam.name), ()))
        auto = misp_categories(matches)
        if fam.name in owner:
            cats, source = owner[fam.name], "owner"
        else:
            cats, source = auto, "misp" if auto else "none"
        labels[fam.name] = cats
        sid = resolved[fam.name]
        techniques = sorted(uses.get(sid, ())) if sid else []
        links = {(cve, "threatfox_tag"): [] for cve in tagged.get(fam.name, ())}
        for (cve, origin), found in mentioned.get(fam.name, {}).items():
            links[(cve, f"mention:{origin}")] = [
                {"doc_id": d, "surface": s} for d, s in sorted(found)
            ]
        for cve, sentence in sorted(software_cves.get(sid, {}).items()) if sid else ():
            links[(cve, "attack:software")] = [
                {"doc_id": f"attack:{sid}", "surface": software[sid]["name"], "text": sentence}
            ]
        cves = [
            {
                "cve": cve,
                "via": via,
                "evidence": links[(cve, via)],
                "tier": tiers.get(cve),
                "in_kev": cve in in_kev,
                "review": _review_state(link_review.get((fam.name, cve, via))),
            }
            for cve, via in sorted(links)
        ]
        for c in cves:
            c["counts_for_priority"] = c["review"] == "correct" or (
                c["review"] == "unreviewed" and c["via"] in cfg.TRUSTED_LINKS
            )
        ranked = [c for c in cves if c["counts_for_priority"]]
        recent, prior = grown.get(fam.name, (0, 0))
        high = {c["cve"] for c in ranked if c["tier"] in cfg.HIGH_TIERS}
        keys = {
            "linked_kev_cves": len({c["cve"] for c in ranked if c["in_kev"]}),
            "linked_high_tier_cves": len(high),
            "ransomware": int("ransomware" in cats),
            "ioc_growth": recent - prior,
            "ioc_rows": fam.rows,
        }
        out.append(
            {
                "family": fam.name,
                "malware_ids": list(fam.ids),
                "categories": list(cats),
                "category_source": source,
                "misp_categories": list(auto),
                "misp_matches": [{"cluster": c, "value": v} for c, v in matches],
                "attack": {
                    "software": sid,
                    "name": software[sid]["name"] if sid else None,
                    "type": software[sid]["type"] if sid else None,
                    "techniques": techniques,
                    "tactics": sorted({t for tid in techniques for t in tactics.get(tid, ())}),
                },
                "cves": cves,
                "priority_keys": keys,
                "why": _why(keys, recent, prior),
            }
        )
    out.sort(key=lambda f: (*(-f["priority_keys"][k] for k in cfg.PRIORITY_KEYS), f["family"]))
    for rank, fam in enumerate(out, 1):
        fam["rank"] = rank
    ransomware_kev = sorted(
        r["source_id"] for r in kev_rows if r["metadata"].get("ransomware_use") == "Known"
    )
    return {
        "snapshot_date": day.isoformat(),
        "families": out,
        "category_rows": category_rows(fams, labels),
        "kev_ransomware_cves": ransomware_kev,
        "summary": {
            "ioc_rows": sum(f.rows for f in fams),
            "named_families": len(named),
            "named_rows": sum(f.rows for f in named),
            "category_source": dict(Counter(f["category_source"] for f in out)),
            "with_attack_software": sum(f["attack"]["software"] is not None for f in out),
            "with_cve_links": sum(bool(f["cves"]) for f in out),
            "cve_links": dict(Counter(c["via"] for f in out for c in f["cves"])),
            "cve_links_by_review": dict(Counter(c["review"] for f in out for c in f["cves"])),
            "cve_links_ranked": sum(c["counts_for_priority"] for f in out for c in f["cves"]),
        },
    }


def agreement(owner: Mapping[str, tuple[str, ...]], auto: Mapping[str, tuple[str, ...]]) -> dict:
    """Owner vs automatic labels per category, on families both labelled.

    Specific agreement 2a / (2a + b + c) (a = both, b/c = one only) with a seeded
    bootstrap 95% interval over families. No pooled kappa: categories are not exclusive
    and most are rare, so a pooled figure would hide which ones disagree. Resamples in
    which a category never occurs are dropped, so a rare category's interval comes from
    fewer resamples; ``both`` + ``owner_only`` + ``auto_only`` show how thin it is.
    """
    fams = sorted(f for f in owner if auto.get(f))
    cats = sorted({c for f in fams for c in (*owner[f], *auto[f])})
    rng = np.random.default_rng(SEED)
    draws = rng.integers(0, len(fams), size=(N_BOOT, len(fams))) if fams else None
    result = {}
    for cat in cats:
        o = np.array([cat in owner[f] for f in fams])
        a = np.array([cat in auto[f] for f in fams])
        both, owner_only, auto_only = int((o & a).sum()), int((o & ~a).sum()), int((~o & a).sum())
        denom = 2 * both + owner_only + auto_only
        boot = []
        for idx in draws:
            ob, ab = o[idx], a[idx]
            d = 2 * (ob & ab).sum() + (ob & ~ab).sum() + (~ob & ab).sum()
            if d:
                boot.append(2 * (ob & ab).sum() / d)
        result[cat] = {
            "both": both,
            "owner_only": owner_only,
            "auto_only": auto_only,
            "specific_agreement": round(2 * both / denom, 3) if denom else None,
            "ci95": [round(float(q), 3) for q in np.percentile(boot, [2.5, 97.5])]
            if boot
            else None,
        }
    return {
        "families_compared": len(fams),
        "owner_labelled": len(owner),
        "without_auto_label": sorted(f for f in owner if f in auto and not auto[f]),
        "per_category": result,
    }


def link_precision(labels: Mapping[tuple[str, str, str], bool]) -> dict:
    """Share of reviewed links marked correct, overall and per ``via``, with Wilson 95%."""
    from cti.nlp.evaluate import wilson

    groups: dict[str, list[bool]] = defaultdict(list)
    for (_, _, via), ok in labels.items():
        groups["all"].append(ok)
        groups[via].append(ok)
    return {
        g: {
            "n": len(oks),
            "correct": sum(oks),
            "precision": round(sum(oks) / len(oks), 3),
            "ci95": [round(x, 3) for x in wilson(sum(oks), len(oks))],
        }
        for g, oks in sorted(groups.items())
    }
