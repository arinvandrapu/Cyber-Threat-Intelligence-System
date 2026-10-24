import gzip
import json

import httpx
import pytest

from cti import cli
from cti.ingest import ingest, refetch
from cti.models import Document
from cti.snapshot import Snapshot, SnapshotExistsError
from cti.sources.base import Source

from .conftest import KEY, SNAPSHOT_DAY


class FakeSource(Source):
    name = "fake"
    fail_times = 0
    payload = b"v1"

    def probe_url(self):
        return "https://example.com"

    def fetch(self, ctx):
        ctx.write(self.name, "part1", b"p1", "https://example.com/p1")
        if self.fail_times:
            self.fail_times -= 1
            raise RuntimeError(f"boom at https://host/{KEY}/file")
        ctx.write(self.name, "part2", self.payload, "https://example.com/p2")

    def parse(self, snapshot):
        for entry in snapshot.entries(self.name):
            yield Document(
                id=f"fake:{entry.name}",
                source="fake",
                source_id=entry.name,
                title=snapshot.read_raw(entry).decode(),
            )


class OtherSource(FakeSource):
    name = "other"


@pytest.fixture
def client():
    with httpx.Client() as c:
        yield c


def run(storage, settings, sources, client, **kw):
    return ingest(storage, settings, SNAPSHOT_DAY, sources, client, **kw)


def test_ingest_runs_once(storage, settings, client):
    result = run(storage, settings, [FakeSource(settings)], client)
    assert result.ok and result.completed == ["fake"]
    with pytest.raises(SnapshotExistsError):
        run(storage, settings, [FakeSource(settings)], client)


def test_failure_is_isolated_redacted_and_resumable(storage, settings, client):
    flaky = FakeSource(settings)
    flaky.fail_times = 1
    other = OtherSource(settings)
    first = run(storage, settings, [flaky, other], client)
    assert first.completed == ["other"]
    assert "fake" in first.failed
    assert KEY not in first.failed["fake"]  # secrets redacted from errors (ctx.secrets)

    second = run(storage, settings, [flaky, other], client, resume=True)
    assert second.ok
    assert second.completed == ["fake"] and second.skipped == ["other"]
    snap = Snapshot.open(storage, SNAPSHOT_DAY.isoformat())
    assert [e.name for e in snap.entries("fake")] == ["part1", "part2"]
    assert snap.manifest.refetches[0].reason.startswith("resume")
    # the partial first attempt is kept, not overwritten
    assert storage.exists(f"{snap.id}/raw/fake/1/part1")


def test_refetch_requires_completed_data_and_logs_reason(storage, settings, client):
    run(storage, settings, [FakeSource(settings)], client)
    updated = FakeSource(settings)
    updated.payload = b"v2"
    result = refetch(storage, settings, SNAPSHOT_DAY.isoformat(), updated, "bad parse", client)
    assert result.ok
    snap = Snapshot.open(storage, SNAPSHOT_DAY.isoformat())
    assert [d.title for d in updated.parse(snap)] == ["p1", "v2"]
    assert snap.manifest.refetches[-1].reason == "bad parse"


def test_cli_status_and_parse(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CTI_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CTI_CONTACT", "t@example.com")
    monkeypatch.setattr(cli, "select", lambda settings, names: [FakeSource(settings)])
    from cti.config import Settings
    from cti.storage import LocalStorage

    settings = Settings(_env_file=None)
    with httpx.Client() as c:
        ingest(
            LocalStorage(tmp_path / "snapshots"), settings, SNAPSHOT_DAY, [FakeSource(settings)], c
        )
    day = SNAPSHOT_DAY.isoformat()
    assert cli.main(["status", "--date", day]) == 0
    assert "fake" in capsys.readouterr().out
    assert cli.main(["parse", "--date", day]) == 0
    out = tmp_path / "processed" / day / "fake.jsonl.gz"
    with gzip.open(out, "rt") as fh:
        rows = [json.loads(line) for line in fh]
    assert [r["title"] for r in rows] == ["p1", "v1"]


def test_cli_refuses_missing_key(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CTI_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CTI_CONTACT", "t@example.com")
    monkeypatch.delenv("CTI_ABUSECH_AUTH_KEY", raising=False)
    monkeypatch.chdir(tmp_path)  # no .env here
    code = cli.main(["ingest", "--date", "2026-10-25", "--only", "threatfox"])
    assert code == 2
    assert "CTI_ABUSECH_AUTH_KEY" in capsys.readouterr().err
    assert not (tmp_path / "snapshots").exists()  # failed before creating a snapshot


class CrashAfterWrite(FakeSource):
    """Simulates a crash after data reached storage but before the manifest was saved."""

    name = "crashy"
    crash = True

    def fetch(self, ctx):
        if self.crash:
            self.crash = False
            # data lands in storage; the process "dies" before the manifest records it
            ctx.snapshot.storage.put_bytes(f"{ctx.snapshot.id}/raw/crashy/1/part1", b"old")
            raise RuntimeError("killed")
        ctx.write(self.name, "part1", b"new upstream bytes", "https://example.com/p1")


def test_resume_after_crash_before_manifest_save(storage, settings, client):
    source = CrashAfterWrite(settings)
    first = run(storage, settings, [source], client)
    assert "crashy" in first.failed
    second = run(storage, settings, [source], client, resume=True)
    assert second.ok  # new attempt instead of FileExistsError on the orphaned key
    snap = Snapshot.open(storage, SNAPSHOT_DAY.isoformat())
    [entry] = snap.entries("crashy")
    assert entry.attempt == 2
    assert snap.read_raw(entry) == b"new upstream bytes"
