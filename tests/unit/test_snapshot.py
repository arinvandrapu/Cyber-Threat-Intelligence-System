import pytest

from cti.snapshot import Snapshot, SnapshotExistsError
from cti.storage import LocalStorage

SID = "2026-10-25"


@pytest.fixture
def storage(tmp_path):
    return LocalStorage(tmp_path)


def test_create_write_and_reopen(storage):
    snap = Snapshot.create(storage, SID)
    entry = snap.write_raw("kev", "kev.json", b'{"v": 1}', url="https://x", source_version="v1")
    assert entry.key == f"{SID}/raw/kev/1/kev.json"
    assert entry.bytes == 8
    reopened = Snapshot.open(storage, SID)
    [loaded] = reopened.entries("kev")
    assert reopened.read_raw(loaded) == b'{"v": 1}'
    assert loaded.source_version == "v1"


def test_ingest_runs_once(storage):
    Snapshot.create(storage, SID)
    with pytest.raises(SnapshotExistsError):
        Snapshot.create(storage, SID)


def test_cannot_overwrite_raw_data(storage):
    snap = Snapshot.create(storage, SID)
    snap.write_raw("kev", "kev.json", b"1")
    with pytest.raises(FileExistsError):
        snap.write_raw("kev", "kev.json", b"2")


def test_refetch_is_logged_and_keeps_old_data(storage):
    snap = Snapshot.create(storage, SID)
    snap.write_raw("kev", "kev.json", b"old")
    with pytest.raises(ValueError):
        snap.begin_refetch("kev", "  ")
    attempt = snap.begin_refetch("kev", "parser found truncated download")
    assert attempt == 2
    snap.write_raw("kev", "kev.json", b"new")
    reopened = Snapshot.open(storage, SID)
    [current] = reopened.entries("kev")
    assert reopened.read_raw(current) == b"new"
    assert storage.get_bytes(f"{SID}/raw/kev/1/kev.json") == b"old"
    assert reopened.manifest.refetches[0].reason == "parser found truncated download"


def test_refetch_unknown_source_rejected(storage):
    snap = Snapshot.create(storage, SID)
    with pytest.raises(ValueError):
        snap.begin_refetch("nvd", "why not")


def test_checksum_verified_on_read(storage, tmp_path):
    snap = Snapshot.create(storage, SID)
    entry = snap.write_raw("kev", "kev.json", b"good")
    (tmp_path / entry.key).write_bytes(b"tampered")  # simulate on-disk corruption
    with pytest.raises(ValueError, match="checksum"):
        snap.read_raw(entry)


@pytest.mark.parametrize("bad", ["2026-1-1", "latest", "../x", "2026-10-25\n", "2026-99-99"])
def test_bad_snapshot_id(storage, bad):
    with pytest.raises(ValueError):
        Snapshot.create(storage, bad)


@pytest.mark.parametrize("name", ["../evil", "a/b", "", "kev.json\n"])
def test_bad_names(storage, name):
    snap = Snapshot.create(storage, SID)
    with pytest.raises(ValueError):
        snap.write_raw("kev", name, b"x")


def test_newline_id_cannot_duplicate_existing_snapshot(storage):
    Snapshot.create(storage, SID)
    with pytest.raises(ValueError):
        Snapshot.create(storage, SID + "\n")


def test_write_raw_retry_after_manifest_failure_is_safe(storage, monkeypatch):
    snap = Snapshot.create(storage, SID)

    def boom(**_):
        raise OSError("disk full")

    monkeypatch.setattr(snap, "save", boom)
    with pytest.raises(OSError):
        snap.write_raw("kev", "kev.json", b"data")
    monkeypatch.undo()
    entry = snap.write_raw("kev", "kev.json", b"data")  # same bytes: retry succeeds
    assert len(snap.entries("kev")) == 1
    assert Snapshot.open(storage, SID).entries("kev") == [entry]
    with pytest.raises(FileExistsError):
        snap.write_raw("kev", "kev.json", b"different")
