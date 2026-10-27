import pytest

from cti.nlp.aliases import build_index, key


def attack(ext_id, title, stix_type, aliases=()):
    return {
        "source_id": ext_id,
        "title": title,
        "metadata": {"stix_type": stix_type, "aliases": list(aliases)},
    }


def threatfox(malware, alias="None"):
    return {"metadata": {"malware": malware, "malware_alias": alias}}


@pytest.fixture
def index():
    return build_index(
        [
            attack("G0007", "APT28", "intrusion-set", ["APT28", "Fancy Bear", "Sednit"]),
            attack("G1047", "Saint Bear", "intrusion-set", ["Saint Bear", "UAC-0056"]),
            attack("G1003", "Ember Bear", "intrusion-set", ["Ember Bear", "UAC-0056"]),
            attack("S0154", "Cobalt Strike", "tool", ["Cobalt Strike"]),
            attack("S1073", "Royal", "malware", ["Royal"]),
            attack("S9001", "INC", "malware", ["INC"]),
            attack("S0085", "S-Type", "malware", ["S-Type"]),
            attack("S0013", "PlugX", "malware", ["PlugX", "Korplug"]),
            attack("G0129", "Mustang Panda", "intrusion-set", ["Mustang Panda", "RedDelta"]),
            attack("T1059", "Command and Scripting Interpreter", "attack-pattern"),
        ],
        [
            threatfox("Cobalt Strike", "BEACON,CobaltStrike"),
            threatfox("Mirai", "Katana"),
            threatfox("PlugX", "Korplug,RedDelta"),  # an alias list that names a group
            threatfox("Unknown malware"),
        ],
    )


def test_key_ignores_case_and_separators():
    assert key("APT 28") == key("apt-28") == key("APT_28") == "apt28"


def test_lookup_normalizes_and_joins_threatfox(index):
    assert [e.id for e in index.lookup("fancy bear")] == ["G0007"]
    assert [e.id for e in index.lookup("cobaltstrike")] == ["S0154"]  # ThreatFox alias
    assert [e.id for e in index.lookup("Katana")] == ["threatfox:Mirai"]
    assert index.lookup("Unknown malware") == ()
    assert index.lookup("Command and Scripting Interpreter") == ()  # techniques aren't names


def test_threatfox_family_joins_software_not_groups(index):
    assert [e.id for e in index.lookup("PlugX")] == ["S0013"]
    assert [e.id for e in index.lookup("RedDelta")] == ["G0129", "S0013"]  # truly ambiguous


def test_ambiguous_alias_returns_every_candidate(index):
    assert [e.id for e in index.lookup("UAC 0056")] == ["G1003", "G1047"]
    [m] = index.find("activity by UAC-0056 this week")
    assert m.ambiguous and m.ids == ("G1003", "G1047")


def test_find_spellings_and_separators(index):
    text = "APT 28 (Fancy Bear, aka fancy-bear) used Cobalt Strike BEACON."
    got = [(m.surface, m.ids) for m in index.find(text)]
    assert got == [
        ("APT 28", ("G0007",)),
        ("Fancy Bear", ("G0007",)),
        ("Cobalt Strike", ("S0154",)),
        ("BEACON", ("S0154",)),
    ]


def test_find_rejects_word_salad(index):
    assert index.find("written in C and built or at runtime") == []  # INC, oRAT-style joins
    assert index.find("the user's type field") == []  # S-Type after an apostrophe
    assert index.find("Royal Mail delivered it") == []  # plain word, no threat cue


def test_plain_word_needs_a_threat_cue(index):
    [m] = index.find("Royal ransomware encrypted the share")
    assert m.ids == ("S1073",)


def test_offsets(index):
    text = "seen: the Sednit group"
    [m] = index.find(text)
    assert text[m.start : m.end] == m.surface == "Sednit"
    assert m.as_dict()["ambiguous"] is False


def test_stats(index):
    stats = index.stats()
    assert stats["ambiguous_names"] == 2  # UAC-0056, RedDelta
    assert stats["entities"] == {"group": 4, "malware": 4, "threatfox": 1, "tool": 1}
