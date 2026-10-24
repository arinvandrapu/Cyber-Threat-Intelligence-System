import json
from datetime import date

import httpx
import pytest
import respx

from cti.models import CveSignal, Document
from cti.sources import abusech, attack, cwe, epss, exploitdb, kev, nvd
from cti.sources.metasploit import MetasploitSource
from cti.sources.nuclei import NucleiSource
from cti.sources.vulnrichment import VulnrichmentSource

from .conftest import KEY, gzip_bytes, jsonl, nvd_meta, pin_github, tar_gz, zip_bytes


def nvd_feed(cves):
    return json.dumps({"format": "NVD_CVE", "vulnerabilities": [{"cve": c} for c in cves]}).encode()


def nvd_cve(cve_id, published, **extra):
    return {
        "id": cve_id,
        "published": published,
        "lastModified": "2026-06-01T00:00:00.000",
        "vulnStatus": extra.pop("vulnStatus", "Analyzed"),
        "descriptions": [{"lang": "en", "value": f"{cve_id} desc"}, {"lang": "es", "value": "x"}],
        "metrics": {
            "cvssMetricV31": [
                {
                    "source": "other",
                    "type": "Secondary",
                    "cvssData": {"version": "3.1", "baseScore": 5.0, "vectorString": "S"},
                },
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N",
                    },
                },
            ]
        },
        "weaknesses": [{"description": [{"value": "CWE-79"}, {"value": "NVD-CWE-noinfo"}]}],
        "references": [{"url": "https://vendor.example/adv", "tags": ["Vendor Advisory"]}],
        **extra,
    }


@respx.mock
def test_nvd_fetch_verifies_checksum_and_parse_filters(ctx, settings, snapshot):
    source = nvd.NVDSource(settings)
    for year in source.years(2026):
        payload = nvd_feed(
            [
                nvd_cve(
                    f"CVE-{year}-0001",
                    f"{year}-03-01T10:00:00.000",
                    cisaExploitAdd="2026-01-01",
                    cisaActionDue="2026-01-21",
                ),
                nvd_cve(f"CVE-{year}-0002", f"{year}-03-01T10:00:00.000", vulnStatus="Rejected"),
            ]
        )
        stem = f"{nvd.BASE}/nvdcve-2.0-{year}"
        respx.get(f"{stem}.meta").mock(return_value=httpx.Response(200, content=nvd_meta(payload)))
        respx.get(f"{stem}.json.gz").mock(
            return_value=httpx.Response(200, content=gzip_bytes(payload))
        )
    source.fetch(ctx)
    docs = list(source.parse(snapshot))
    # 2023 is fetched (IDs from 2023 can be published in 2024) but filtered by date;
    # rejected CVEs are dropped.
    assert [d.source_id for d in docs] == ["CVE-2024-0001", "CVE-2025-0001", "CVE-2026-0001"]
    doc = docs[0]
    assert doc.metadata["cvss"]["base_score"] == 9.8  # Primary preferred
    assert doc.metadata["cwes"] == ["CWE-79"]
    assert doc.text == "CVE-2024-0001 desc"
    # leakage: NVD's KEV copy and reference tags ("Exploit", ...) are dropped
    dumped = doc.model_dump_json()
    assert "2026-01-21" not in dumped and "Vendor Advisory" not in dumped
    assert doc.metadata["references"] == ["https://vendor.example/adv"]


@respx.mock
def test_nvd_checksum_mismatch_fails(ctx, settings):
    source = nvd.NVDSource(settings)
    respx.get(url__regex=r".*\.meta$").mock(
        return_value=httpx.Response(200, content=nvd_meta(b"something else"))
    )
    respx.get(url__regex=r".*\.json\.gz$").mock(
        return_value=httpx.Response(200, content=gzip_bytes(nvd_feed([])))
    )
    with pytest.raises(ValueError, match="checksum"):
        source.fetch(ctx)


@respx.mock
def test_kev(ctx, settings, snapshot):
    catalog = {
        "catalogVersion": "2026.10.24",
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-1111",
                "vendorProject": "Acme",
                "product": "Widget",
                "vulnerabilityName": "Acme Widget RCE",
                "dateAdded": "2026-10-20",
                "shortDescription": "RCE",
                "dueDate": "2026-11-10",
                "knownRansomwareCampaignUse": "Known",
                "cwes": ["CWE-78"],
            }
        ],
    }
    respx.get(kev.URL).mock(return_value=httpx.Response(200, json=catalog))
    source = kev.KEVSource(settings)
    source.fetch(ctx)
    [entry] = snapshot.entries("kev")
    assert entry.source_version == "2026.10.24"
    [doc] = source.parse(snapshot)
    assert doc.id == "kev:CVE-2026-1111"
    assert doc.metadata["ransomware_use"] == "Known"


@respx.mock
def test_epss_cutoff_and_snapshot_with_fallback(ctx, settings, snapshot):
    def csv_gz(model, day):
        return gzip_bytes(
            f"#model_version:{model},score_date:{day}T00:00:00Z\n"
            "cve,epss,percentile\nCVE-2026-1111,0.5,0.99\n".encode()
        )

    respx.get(epss.url_for(date(2026, 4, 28))).mock(
        return_value=httpx.Response(200, content=csv_gz("v2025.03.14", "2026-04-28"))
    )
    respx.get(epss.url_for(date(2026, 10, 25))).mock(return_value=httpx.Response(404))
    respx.get(epss.url_for(date(2026, 10, 24))).mock(
        return_value=httpx.Response(200, content=csv_gz("v2026.06.15", "2026-10-24"))
    )
    source = epss.EPSSSource(settings)
    source.fetch(ctx)
    signals = {s.as_of: s for s in source.parse(snapshot)}
    assert signals["cutoff"].values["model_version"] == "v2025.03.14"
    assert signals["snapshot"].values["score_date"].startswith("2026-10-24")
    assert signals["cutoff"].values["epss"] == 0.5


EDB_HEADER = (
    "id,file,description,date_published,author,type,platform,port,date_added,"
    "date_updated,verified,codes,tags,aliases,screenshot_url,application_url,source_url\n"
)


@respx.mock
def test_exploitdb_point_in_time_copies(ctx, settings, snapshot):
    def commits(request):
        params = request.url.params
        assert params["first_parent"] == "true" and params["ref_name"] == "main"
        sha = "cut" if params["until"].startswith("2026-04-28") else "snap"
        return httpx.Response(200, json=[{"id": sha}])

    respx.get(url__startswith=exploitdb.API).mock(side_effect=commits)
    old_exploit = '1,f,"Acme RCE",2020-01-02,Some Person,remote,linux,,2020-01-03,,1,"",,,,,\n'
    # Later the CVE code was added, and an old exploit (published 2019) was imported.
    later = (
        '1,f,"Acme RCE",2020-01-02,Some Person,remote,linux,,2020-01-03,,1,'
        '"CVE-2026-1111;OSVDB-1",,,,,\n'
        '2,f,"Old thing",2019-05-05,X,local,linux,,2026-09-01,,0,"CVE-2026-1111",,,,,\n'
    )
    respx.get(exploitdb.raw_url("cut")).mock(
        return_value=httpx.Response(200, text=EDB_HEADER + old_exploit)
    )
    respx.get(exploitdb.raw_url("snap")).mock(
        return_value=httpx.Response(200, text=EDB_HEADER + later)
    )
    source = exploitdb.ExploitDBSource(settings)
    source.fetch(ctx)
    records = list(source.parse(snapshot))
    signals = [r for r in records if isinstance(r, CveSignal)]
    docs = [r for r in records if isinstance(r, Document)]
    # At the cutoff nothing linked the exploit to the CVE: no cutoff signal at all.
    assert [(s.as_of, s.values["exploit_count"]) for s in signals] == [("snapshot", 2)]
    assert {d.source_id for d in docs} == {"1", "2"}  # documents come from the snapshot copy
    assert all("Some Person" not in d.model_dump_json() for d in docs)


@respx.mock
def test_attack_skips_revoked_and_deprecated(ctx, settings, snapshot):
    def obj(i, **kw):
        return {
            "type": "attack-pattern",
            "id": f"attack-pattern--{i}",
            "name": f"Tech {i}",
            "description": "d",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": f"T{i}",
                    "url": f"https://attack.mitre.org/techniques/T{i}",
                }
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
            ],
            **kw,
        }

    bundle = {
        "objects": [
            obj(1190),
            obj(1, revoked=True),
            obj(2, x_mitre_deprecated=True),
            {"type": "relationship", "id": "r"},
        ]
    }
    source = attack.AttackSource(settings)
    respx.get(source.url()).mock(return_value=httpx.Response(200, json=bundle))
    source.fetch(ctx)
    [doc] = source.parse(snapshot)
    assert doc.id == "attack:T1190"
    assert doc.metadata["tactics"] == ["initial-access"]


CWE_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7"><Weaknesses>
<Weakness ID="79" Name="XSS" Abstraction="Base" Status="Stable">
<Description>Bad.</Description></Weakness>
<Weakness ID="1" Name="Old" Abstraction="Base" Status="Deprecated">
<Description>x</Description></Weakness>
</Weaknesses></Weakness_Catalog>"""


@respx.mock
def test_cwe(ctx, settings, snapshot):
    source = cwe.CWESource(settings)
    respx.get(source.url()).mock(
        return_value=httpx.Response(200, content=zip_bytes({"cwec_v4.20.xml": CWE_XML}))
    )
    source.fetch(ctx)
    [doc] = source.parse(snapshot)
    assert (doc.id, doc.title, doc.text) == ("cwe:CWE-79", "XSS", "Bad.")


def test_cwe_rejects_entity_expansion():
    bomb = b"""<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7">&a;</Weakness_Catalog>"""
    import io

    from defusedxml import EntitiesForbidden

    with pytest.raises(EntitiesForbidden):
        list(cwe.CWESource._weaknesses(io.BytesIO(bomb)))


def vulnrichment_record(cve, exploitation):
    return json.dumps(
        {
            "cveMetadata": {"cveId": cve},
            "containers": {
                "adp": [
                    {
                        "providerMetadata": {"shortName": "CISA-ADP"},
                        "metrics": [
                            {
                                "other": {
                                    "type": "ssvc",
                                    "content": {
                                        "id": cve,
                                        "timestamp": "2026-01-01T00:00:00Z",
                                        "options": [
                                            {"Exploitation": exploitation},
                                            {"Automatable": "yes"},
                                            {"Technical Impact": "total"},
                                        ],
                                    },
                                }
                            },
                            {"other": {"type": "kev", "content": {"dateAdded": "2026-05-01"}}},
                        ],
                    }
                ]
            },
        }
    ).encode()


@respx.mock
def test_vulnrichment_point_in_time_without_kev(ctx, settings, snapshot, monkeypatch):
    pin_github(monkeypatch, "cisagov/vulnrichment", "develop", {"cutoff": "aaa", "snapshot": "bbb"})
    for sha, exploitation in (("aaa", "none"), ("bbb", "active")):
        archive = tar_gz(
            {
                f"vulnrichment-{sha}/2026/1xxx/CVE-2026-1111.json": vulnrichment_record(
                    "CVE-2026-1111", exploitation
                ),
                f"vulnrichment-{sha}/README.md": b"readme",
            }
        )
        respx.get(f"https://codeload.github.com/cisagov/vulnrichment/tar.gz/{sha}").mock(
            return_value=httpx.Response(200, content=archive)
        )
    source = VulnrichmentSource(settings)
    source.fetch(ctx)
    signals = {s.as_of: s for s in source.parse(snapshot)}
    assert signals["cutoff"].values["exploitation"] == "none"
    assert signals["snapshot"].values["exploitation"] == "active"
    assert signals["cutoff"].values["commit"] == "aaa"
    assert "dateAdded" not in json.dumps(signals["snapshot"].values)


@respx.mock
def test_metasploit_aggregates_per_cve(ctx, settings, snapshot, monkeypatch):
    pin_github(
        monkeypatch, "rapid7/metasploit-framework", "master", {"cutoff": "c1", "snapshot": "s1"}
    )
    modules = {
        "a": {
            "fullname": "exploit/x",
            "type": "exploit",
            "rank": 600,
            "references": ["CVE-2026-1111", "URL-https://x"],
        },
        "b": {
            "fullname": "auxiliary/y",
            "type": "auxiliary",
            "rank": 300,
            "references": ["CVE-2026-1111"],
        },
    }
    for sha in ("c1", "s1"):
        respx.get(
            f"https://raw.githubusercontent.com/rapid7/metasploit-framework/{sha}/"
            "db/modules_metadata_base.json"
        ).mock(return_value=httpx.Response(200, json=modules if sha == "s1" else {}))
    source = MetasploitSource(settings)
    source.fetch(ctx)
    [signal] = source.parse(snapshot)  # nothing existed at the cutoff
    assert signal.as_of == "snapshot"
    assert signal.values["module_count"] == 2
    assert signal.values["exploit_modules"] == 1
    assert signal.values["best_rank"] == 600


@respx.mock
def test_nuclei(ctx, settings, snapshot, monkeypatch):
    pin_github(
        monkeypatch, "projectdiscovery/nuclei-templates", "main", {"cutoff": "c", "snapshot": "s"}
    )
    row = {"ID": "CVE-2026-1111", "Info": {"Severity": "critical"}, "file_path": "http/cves/x.yaml"}
    for sha in ("c", "s"):
        respx.get(
            f"https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/{sha}/cves.json"
        ).mock(return_value=httpx.Response(200, content=jsonl([row]) + b"\n"))
    source = NucleiSource(settings)
    source.fetch(ctx)
    signals = list(source.parse(snapshot))
    assert {s.as_of for s in signals} == {"cutoff", "snapshot"}
    assert all(isinstance(s, CveSignal) and s.values["severity"] == "critical" for s in signals)


THREATFOX_CSV = (
    "################################################################\n"
    "# ThreatFox IOCs: full data dump (CSV)                          #\n"
    "################################################################\n"
    '# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware",'
    '"malware_alias","malware_printable","last_seen_utc","confidence_level","reference",'
    '"tags","anonymous","reporter"\n'
    '"2026-10-01 10:00:00", "101", "203.0.113.7:443", "ip:port", "botnet_cc", "win.qakbot",'
    ' "", "QakBot", "", "100", "", "qakbot,c2", "0", "someone"\n'
    '"2026-10-02 10:00:00", "102", "http://evil.example.com/a", "url", "payload_delivery",'
    ' "unknown", "", "Unknown malware", "", "75", "", "", "0", "someone"\n'
)

URLHAUS_CSV = (
    "################################################################\n"
    "# abuse.ch URLhaus Database Dump (CSV - recent URLs)            #\n"
    "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
    '"9","2026-10-20 08:00:00","https://bad.example.net/x.exe","online","2026-10-20 08:00:00",'
    '"malware_download","exe","https://urlhaus.abuse.ch/url/9/","someone"\n'
)


@respx.mock
def test_threatfox_defangs_and_redacts_key(ctx, settings, snapshot):
    source = abusech.ThreatFoxSource(settings)
    assert KEY in source.url()
    respx.get(source.url()).mock(
        return_value=httpx.Response(200, content=zip_bytes({"full.csv": THREATFOX_CSV}))
    )
    source.fetch(ctx)
    [entry] = snapshot.entries("threatfox")
    assert KEY not in entry.url and "<redacted>" in entry.url
    assert KEY not in json.dumps(snapshot.manifest.model_dump(mode="json"))
    docs = list(source.parse(snapshot))
    assert [d.metadata["ioc"] for d in docs] == [
        "203.0.113[.]7:443",
        "hxxp://evil[.]example[.]com/a",
    ]
    assert docs[0].metadata["tags"] == ["qakbot", "c2"]
    assert all("someone" not in d.model_dump_json() for d in docs)  # reporter dropped


@respx.mock
def test_urlhaus(ctx, settings, snapshot):
    source = abusech.URLhausSource(settings)
    respx.get(source.url()).mock(return_value=httpx.Response(200, text=URLHAUS_CSV))
    source.fetch(ctx)
    [doc] = source.parse(snapshot)
    assert isinstance(doc, Document)
    assert doc.metadata["ioc"] == "hxxps://bad[.]example[.]net/x.exe"
    assert doc.metadata["status"] == "online"


def test_abusech_requires_key():
    from cti.config import ConfigError, Settings

    with pytest.raises(ConfigError):
        abusech.ThreatFoxSource(Settings(_env_file=None)).url()


def test_csv_without_header_rejected():
    with pytest.raises(ValueError):
        list(abusech.read_commented_csv("1,2,3\n"))


def test_abusech_csv_ignores_footer_and_keeps_odd_characters():
    text = (
        "# id,dateadded,url\n"
        '"1","2026-10-20","http://c\x85d.example/x"\n'
        "# Number of entries: 1,234\n"
    )
    [row] = abusech.read_commented_csv(text)
    assert row == {"id": "1", "dateadded": "2026-10-20", "url": "http://c\x85d.example/x"}


@respx.mock
def test_epss_cutoff_falls_back_to_previous_day(ctx, settings, snapshot):
    body = gzip_bytes(b"#model_version:v1,score_date:x\ncve,epss,percentile\n")
    respx.get(epss.url_for(date(2026, 4, 28))).mock(return_value=httpx.Response(404))
    earlier = respx.get(epss.url_for(date(2026, 4, 27))).mock(
        return_value=httpx.Response(200, content=body)
    )
    respx.get(epss.url_for(date(2026, 10, 25))).mock(return_value=httpx.Response(200, content=body))
    epss.EPSSSource(settings).fetch(ctx)
    assert earlier.called  # only earlier days, never later ones (no leakage)


@respx.mock
def test_key_redacted_from_http_errors(ctx):
    """httpx error messages carry the percent-encoded URL; both forms are redacted."""
    ctx.secrets.append("K+EY/=")
    respx.get(url__regex=r".*").mock(return_value=httpx.Response(404))
    url = "https://threatfox-api.abuse.ch/v2/files/exports/K%2BEY%2F%3D/full.csv.zip"
    with pytest.raises(httpx.HTTPStatusError) as exc:
        ctx.download(url)
    message = ctx.redact(str(exc.value))
    assert "K%2BEY" not in message and "<redacted>" in message
