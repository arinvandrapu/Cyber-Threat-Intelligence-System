"""Pre-declared configuration for the threat layer (Phase 10a).

Every choice here was committed before any automatic category label was computed and
before the owner labelled the review sheet (``git log -- src/cti/threats/config.py`` is
the evidence). Changing a rule afterwards must be disclosed in ``vault/threat-layer.md``.

Threats explain CVEs; they never feed the CVE risk score (vault/threat-layer.md). The
threat priority below is a heuristic, not a model, and is labelled as not validated.
abuse.ch data is counted and looked up only, never used to fit a model (terms §7.3).
"""

from __future__ import annotations

# ---- vocabulary --------------------------------------------------------------------------
# STIX 2.1 malware-type-ov (spec section 10.13), unchanged
STIX_MALWARE_TYPES = (
    "adware",
    "backdoor",
    "bot",
    "bootkit",
    "ddos",
    "downloader",
    "dropper",
    "exploit-kit",
    "keylogger",
    "ransomware",
    "remote-access-trojan",
    "resource-exploitation",
    "rogue-security-software",
    "rootkit",
    "screen-capture",
    "spyware",
    "trojan",
    "unknown",
    "virus",
    "webshell",
    "wiper",
    "worm",
)
# Roles analysts use that the STIX list lacks. "banker" was added to the plan's five
# because MISP has a banker cluster and STIX would flatten it to "trojan".
EXTENSIONS = ("infostealer", "loader", "c2-framework", "web-skimmer", "fake-update", "banker")
CATEGORIES = STIX_MALWARE_TYPES + EXTENSIONS
# A family can hold several categories at once (Emotet: banker, then loader, then bot).
LABEL_SEPARATOR = ";"

# ---- automatic labels --------------------------------------------------------------------
# MISP galaxy cluster file -> category. ``tool`` ("tools used by adversaries") mixes
# malware with dual-use software, so it supplies names and links but no category.
MISP_FILE_CATEGORY: dict[str, str | None] = {
    "ransomware": "ransomware",
    "stealer": "infostealer",
    "rat": "remote-access-trojan",
    "botnet": "bot",
    "banker": "banker",
    "backdoor": "backdoor",
    "exploit-kit": "exploit-kit",
    "cryptominers": "resource-exploitation",
    "tool": None,
}
# Family names are joined after this normalisation: lower case, only [a-z0-9] kept, so
# "Cobalt Strike", "cobalt-strike" and "CobaltStrike" meet. No fuzzy matching.
NAME_NORMALISATION = "lower, keep [a-z0-9]"
# ThreatFox names unattributed IOCs by role ("unknown_loader"): the category is known,
# the family is not. Counted under the category, never as a family. Any other
# unknown_<role> ID (e.g. unknown_webinject, 51 rows) counts as "unknown".
THREATFOX_UNKNOWN_IDS: dict[str, str] = {
    "unknown": "unknown",
    "unknown_loader": "loader",
    "unknown_stealer": "infostealer",
    "unknown_rat": "remote-access-trojan",
}

# ---- owner review (blind) ----------------------------------------------------------------
# The owner labels the most frequent named families without seeing any automatic label,
# then the two are compared per category. Owner labels win; other families say "auto".
# In the 2026-10-26 snapshot the top 34 of 467 named families hold 86.6% of the 108,716
# named rows (22 / 46 / 79 / 197 families reach 80 / 90 / 95 / 99%). The planning
# estimate of 99% was a miscount; 34 is kept as a feasible hand-labelling load.
REVIEW_TOP_N = 34
# A family is "named" unless its printable name contains "unknown" (case-insensitive).
UNKNOWN_MARKER = "unknown"

# ---- threat priority (heuristic, not validated) ------------------------------------------
# Families are ordered by these keys, highest first, in this order. Each row lists the
# rules it met as its "why". Raw IOC volume mostly reflects who submits to ThreatFox, so
# it only breaks ties.
PRIORITY_KEYS = (
    "linked_high_tier_cves",  # CVEs linked to the family with risk tier critical or high
    "ransomware",  # 1 if a category is ransomware
    "ioc_growth",  # IOCs first seen in the last GROWTH_DAYS minus the GROWTH_DAYS before
    "ioc_rows",  # total IOC rows
)
HIGH_TIERS = ("critical", "high")
GROWTH_DAYS = 30
