"""Alias normalizer: map threat-actor and malware names to one canonical entity.

Names come from ATT&CK (groups' ``aliases``, software's ``x_mitre_aliases``) and ThreatFox
(``malware`` and ``malware_alias``). The canonical ID is the ATT&CK ID (``G0007``,
``S0154``) when one exists, else ``threatfox:<name>``. A ThreatFox name joins an ATT&CK
entity when its key matches exactly one ATT&CK entity.

``lookup`` keys ignore case, spaces, hyphens, and underscores, so "APT 28", "apt-28", and
"APT28" are one name. A key shared by several entities (e.g. "UAC-0056" is both Saint Bear
and Ember Bear in ATT&CK v20) is ambiguous: every candidate is returned and none is picked.

``find`` (names in running text) is stricter, because many names are ordinary words:

- the text must match a known spelling's case and word count (separators may differ;
  "APT 28" also matches "APT28"), so "in C" is not INC and "or at" is not oRAT;
- a name never starts after an apostrophe ("user's type" is not S-Type);
- ``STOPLIST`` names never match in text (``lookup`` still resolves them);
- a plain word ("Royal", "Ninja", "James", "STOP") needs a threat cue such as
  "ransomware" or "group" within ``CUE_WINDOW`` characters; distinctive names (digits,
  inner capitals, long all-caps, dots: APT28, ScreenConnect, BRICKSTORM, cmd.exe) don't.

The stoplist and the cue rule were set by reading the most frequent matches over the
reference corpus and NVD descriptions (2026-10-26).
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from itertools import pairwise

_SEPARATORS = re.compile(r"[\s_-]+")
_TOKEN = re.compile(r"\w(?:[\w.]*\w)?")  # "Agent.btz" is one token; a trailing dot is not
_GAP = re.compile(r"[ \t_-]{1,3}")  # what may sit between the words of one name in text
_SPLIT_ID = re.compile(r"[A-Za-z]+\d+")  # APT28, UNC3886: may be written "APT 28"
_DISTINCTIVE = re.compile(r"\d|[a-z][A-Z]|\.|^[A-Z]{5,}$")
_APOSTROPHES = ("'", "\u2019")
MIN_KEY = 3  # shorter names ("at", "Tor") are too ambiguous to match in prose
CUE_WINDOW = 80
_CUES = re.compile(
    r"\b(?:malware|ransomware|backdoor|trojan|rat|botnet|loader|stealer|infostealer|implant"
    r"|wiper|rootkit|webshell|web shell|dropper|c2|c&c|apt|group|actor|threat|campaign"
    r"|toolkit|framework|payload|beacon|family|variant|operators?|attributed|intrusion)\b",
    re.IGNORECASE,
)

# names that are ordinary words or phrases even with a cue nearby
STOPLIST = frozenset(
    {
        *("play", "epic", "cuba", "net", "ping", "cmd", "reg", "ftp", "tor", "arp", "mori"),
        *("maze", "pony", "page", "expand", "route", "silence", "inception", "patchwork"),
        *("equation", "machete", "emissary", "payload", "hook", "void", "stop", "inc"),
        *("remotecommandexecution", "remotecontrol", "remoteadmin", "httpclient"),
        *("systeminfo", "tasklist", "clipper", "loremipsum", "responder", "wiper", "photo"),
        "ps1",
    }
)


def key(name: str) -> str:
    return _SEPARATORS.sub("", name).casefold()


def _squash(name: str) -> str:
    return _SEPARATORS.sub("", name)


@dataclass(frozen=True, slots=True)
class Entity:
    id: str  # ATT&CK ID, or "threatfox:<name>"
    name: str
    kind: str  # group | malware | tool | threatfox


@dataclass(frozen=True, slots=True)
class AliasMatch:
    start: int
    end: int
    surface: str
    ids: tuple[str, ...]  # sorted; more than one means ambiguous

    @property
    def ambiguous(self) -> bool:
        return len(self.ids) > 1

    def as_dict(self) -> dict:
        return {
            "start": self.start,
            "end": self.end,
            "surface": self.surface,
            "ids": list(self.ids),
            "ambiguous": self.ambiguous,
        }


class AliasIndex:
    def __init__(self) -> None:
        self.entities: dict[str, Entity] = {}
        self._by_key: dict[str, set[str]] = defaultdict(set)
        # squashed, case-kept spelling -> word counts it may appear with in text
        self._spellings: dict[str, set[int]] = defaultdict(set)
        self._max_words = 1

    def add(self, entity: Entity, names: Iterable[str]) -> None:
        self.entities[entity.id] = entity
        for name in {entity.name, *names}:
            name = name.strip()
            k = key(name)
            if len(k) < MIN_KEY:
                continue
            self._by_key[k].add(entity.id)
            words = len(_TOKEN.findall(name))
            counts = {words, 2} if words == 1 and _SPLIT_ID.fullmatch(name) else {words}
            self._spellings[_squash(name)].update(counts)
            self._max_words = max(self._max_words, words)

    def stats(self) -> dict:
        kinds = Counter(e.kind for e in self.entities.values())
        return {
            "entities": dict(sorted(kinds.items())),
            "names": len(self._by_key),
            "ambiguous_names": sum(len(ids) > 1 for ids in self._by_key.values()),
        }

    def lookup(self, name: str) -> tuple[Entity, ...]:
        ids = sorted(self._by_key.get(key(name), ()))
        return tuple(self.entities[i] for i in ids)

    def _accepts(self, text: str, start: int, end: int, words: int) -> bool:
        surface = text[start:end]
        if key(surface) in STOPLIST or words not in self._spellings.get(_squash(surface), ()):
            return False
        if start and text[start - 1] in _APOSTROPHES:
            return False
        if words > 1 or _DISTINCTIVE.search(surface):
            return True
        window = text[max(0, start - CUE_WINDOW) : end + CUE_WINDOW]
        return bool(_CUES.search(window))

    def find(self, text: str) -> list[AliasMatch]:
        """Non-overlapping name mentions in ``text``, longest match first, left to right."""
        tokens = list(_TOKEN.finditer(text))
        out: list[AliasMatch] = []
        i = 0
        while i < len(tokens):
            for n in range(min(self._max_words, len(tokens) - i), 0, -1):
                span = tokens[i : i + n]
                if any(not _GAP.fullmatch(text, a.end(), b.start()) for a, b in pairwise(span)):
                    continue
                start, end = span[0].start(), span[-1].end()
                ids = self._by_key.get(key(text[start:end]))
                if ids and self._accepts(text, start, end, n):
                    out.append(AliasMatch(start, end, text[start:end], tuple(sorted(ids))))
                    i += n
                    break
            else:
                i += 1
        return out


_ATTACK_KINDS = {"intrusion-set": "group", "malware": "malware", "tool": "tool"}


def build_index(attack_docs: Iterable[dict], threatfox_docs: Iterable[dict]) -> AliasIndex:
    """From parsed ``attack`` and ``threatfox`` rows (``data/processed/<date>/``)."""
    index = AliasIndex()
    for doc in attack_docs:
        kind = _ATTACK_KINDS.get(doc["metadata"]["stix_type"])
        if kind:
            index.add(Entity(doc["source_id"], doc["title"], kind), doc["metadata"]["aliases"])
    families: dict[str, set[str]] = defaultdict(set)
    for doc in threatfox_docs:
        meta = doc["metadata"]
        name = (meta.get("malware") or "").strip()
        if not name or name.lower().startswith("unknown"):
            continue
        alias = meta.get("malware_alias") or ""
        families[name].update(a.strip() for a in alias.split(",") if a.strip() not in ("", "None"))
    attack_keys = {k: set(v) for k, v in index._by_key.items()}  # join ATT&CK names only
    for name in sorted(families):
        names = {name, *families[name]}
        matches = {i for n in names for i in attack_keys.get(key(n), ())}
        if len(matches) == 1:
            index.add(index.entities[matches.pop()], names)
        else:
            index.add(Entity(f"threatfox:{name}", name, "threatfox"), names)
    return index
