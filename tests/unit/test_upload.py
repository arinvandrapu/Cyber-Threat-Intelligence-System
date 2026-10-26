import hashlib

import boto3
import pytest
from moto import mock_aws

from cti import cli
from cti.cli import main
from cti.snapshot import Snapshot
from cti.storage import LocalStorage, S3Storage
from cti.upload import GOLD_KEY, RemoteConflictError, upload_gold, upload_snapshot

BUCKET = "test-bucket"
SID = "2026-10-25"


@pytest.fixture
def local(tmp_path):
    return LocalStorage(tmp_path / "snapshots")


@pytest.fixture
def client():
    with mock_aws():
        c = boto3.client("s3", region_name="us-east-1")
        c.create_bucket(Bucket=BUCKET)
        yield c


@pytest.fixture
def remote(client):
    return S3Storage(BUCKET, "snapshots", client=client)


@pytest.fixture
def snap(local):
    snap = Snapshot.create(local, SID)
    snap.write_raw("kev", "kev.json", b'{"v": 1}')
    snap.write_raw("epss", "epss.csv.gz", b"cve,epss\n")
    snap.mark_complete("kev")
    snap.mark_complete("epss")
    return snap


def test_uploads_raw_files_and_manifest(local, remote, snap):
    result = upload_snapshot(local, remote, SID)
    assert result.ok and result.uploaded == 2 and result.manifest_updated
    assert remote.list_keys(f"{SID}/") == sorted(
        [f"{SID}/manifest.json", f"{SID}/raw/epss/1/epss.csv.gz", f"{SID}/raw/kev/1/kev.json"]
    )
    assert remote.get_bytes(f"{SID}/raw/kev/1/kev.json") == b'{"v": 1}'


def test_rerun_is_a_no_op(local, remote, snap):
    upload_snapshot(local, remote, SID)
    again = upload_snapshot(local, remote, SID)
    assert again.ok and again.uploaded == 0 and again.already_present == 2
    assert not again.manifest_updated


def test_refetch_uploads_new_attempt_and_replaces_manifest(local, remote, snap):
    upload_snapshot(local, remote, SID)
    snap.begin_refetch("kev", "feed was truncated")
    snap.write_raw("kev", "kev.json", b'{"v": 2}')
    snap.mark_complete("kev")
    result = upload_snapshot(local, remote, SID)
    assert result.ok and result.uploaded == 1 and result.manifest_updated
    assert remote.get_bytes(f"{SID}/raw/kev/1/kev.json") == b'{"v": 1}'  # history kept
    assert remote.get_bytes(f"{SID}/raw/kev/2/kev.json") == b'{"v": 2}'
    assert remote.get_bytes(f"{SID}/manifest.json") == local.get_bytes(f"{SID}/manifest.json")


def test_refuses_incomplete_snapshot(local, remote):
    snap = Snapshot.create(local, SID)
    snap.write_raw("kev", "kev.json", b"{}")
    with pytest.raises(ValueError, match="incomplete"):
        upload_snapshot(local, remote, SID)
    assert remote.list_keys() == []


def test_refuses_locally_corrupted_file(local, remote, snap, tmp_path):
    (tmp_path / "snapshots" / SID / "raw" / "kev" / "1" / "kev.json").write_bytes(b"tampered")
    with pytest.raises(ValueError, match="checksum mismatch"):
        upload_snapshot(local, remote, SID)
    assert f"{SID}/manifest.json" not in remote.list_keys()


def test_refuses_different_remote_bytes(local, remote, snap):
    remote.put_bytes(f"{SID}/raw/kev/1/kev.json", b"other")
    with pytest.raises(RemoteConflictError, match="differs"):
        upload_snapshot(local, remote, SID)


class Flaky:
    """Wraps a storage; fails the Nth put, counts downloads, can drop a key silently."""

    def __init__(self, inner, fail_on_put=None, drop=None):
        self.inner, self.fail_on_put, self.drop = inner, fail_on_put, drop
        self.puts = self.gets = 0

    def put_bytes(self, key, data, *, overwrite=False):
        self.puts += 1
        if self.puts == self.fail_on_put:
            raise ConnectionError("network down")
        if key != self.drop:
            self.inner.put_bytes(key, data, overwrite=overwrite)

    def get_bytes(self, key):
        self.gets += 1
        return self.inner.get_bytes(key)

    def __getattr__(self, name):
        return getattr(self.inner, name)


def test_resume_after_failure_skips_uploaded_files_without_downloading(local, remote, snap):
    with pytest.raises(ConnectionError):
        upload_snapshot(local, Flaky(remote, fail_on_put=2), SID)
    assert f"{SID}/manifest.json" not in remote.list_keys()  # never published half-done
    spy = Flaky(remote)
    result = upload_snapshot(local, spy, SID)
    assert result.ok and result.uploaded == 1 and result.already_present == 1
    assert spy.gets == 0


def test_reports_keys_missing_after_upload(local, remote, snap):
    result = upload_snapshot(local, Flaky(remote, drop=f"{SID}/raw/kev/1/kev.json"), SID)
    assert not result.ok and result.missing == [f"{SID}/raw/kev/1/kev.json"]


def test_refuses_to_replace_newer_remote_manifest(local, remote, snap):
    snap.begin_refetch("kev", "feed was truncated")
    snap.write_raw("kev", "kev.json", b'{"v": 2}')
    snap.mark_complete("kev")
    upload_snapshot(local, remote, SID)
    # simulate a stale local copy: the remote has a refetch the local manifest lacks
    stale = Snapshot.open(local, SID)
    stale.manifest.refetches.clear()
    stale.manifest.entries = [e for e in stale.manifest.entries if e.attempt == 1]
    stale.save()
    with pytest.raises(RemoteConflictError, match="refusing to overwrite"):
        upload_snapshot(local, remote, SID)


def test_gold_upload_verifies_checksum(tmp_path, client):
    remote = S3Storage(BUCKET, "gold", client=client)
    path = tmp_path / "gold.jsonl.gz"
    path.write_bytes(b"fixture")
    sha = hashlib.sha256(b"fixture").hexdigest()
    with pytest.raises(ValueError, match="checksum mismatch"):
        upload_gold(path, remote, "0" * 64)
    assert upload_gold(path, remote, sha) is True
    assert upload_gold(path, remote, sha) is False
    assert remote.get_bytes(GOLD_KEY) == b"fixture"


def test_cli_upload_needs_a_target_and_a_bucket(monkeypatch, capsys):
    monkeypatch.delenv("CTI_S3_BUCKET", raising=False)
    monkeypatch.chdir("/")  # no .env picked up
    assert main(["upload"]) == 2
    assert "--date, --gold" in capsys.readouterr().err
    assert main(["upload", "--date", SID]) == 2
    assert "CTI_S3_BUCKET" in capsys.readouterr().err


def test_cli_uploads_gold_and_snapshot(tmp_path, monkeypatch, capsys, client, snap):
    gold_path = tmp_path / "gold" / "gold.jsonl.gz"
    gold_path.parent.mkdir()
    gold_path.write_bytes(b"fixture")
    monkeypatch.setenv("CTI_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CTI_S3_BUCKET", BUCKET)
    monkeypatch.setattr(
        cli,
        "upload_gold",
        lambda path, remote: upload_gold(path, remote, hashlib.sha256(b"fixture").hexdigest()),
    )
    monkeypatch.setattr(
        cli, "_s3", lambda settings, prefix: S3Storage(BUCKET, prefix, client=client)
    )
    assert main(["upload", "--date", SID, "--gold"]) == 0
    out = capsys.readouterr().out
    assert "gold     uploaded" in out and "2 uploaded" in out
    assert S3Storage(BUCKET, "gold", client=client).get_bytes(GOLD_KEY) == b"fixture"
