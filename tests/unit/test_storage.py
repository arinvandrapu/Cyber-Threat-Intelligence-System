import boto3
import pytest
from moto import mock_aws

from cti.storage import LocalStorage, MirroredStorage, S3Storage, StorageKeyError

BUCKET = "test-bucket"


@pytest.fixture
def local(tmp_path):
    return LocalStorage(tmp_path / "store")


@pytest.fixture
def s3():
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket=BUCKET)
        yield S3Storage(BUCKET, "snapshots", client=client)


@pytest.fixture(params=["local", "s3"])
def storage(request, local):
    if request.param == "local":
        return local
    return request.getfixturevalue("s3")


def test_roundtrip_and_list(storage):
    storage.put_bytes("2026-10-25/raw/kev/1/kev.json", b"{}")
    storage.put_bytes("2026-10-25/manifest.json", b"m")
    assert storage.get_bytes("2026-10-25/raw/kev/1/kev.json") == b"{}"
    assert storage.exists("2026-10-25/manifest.json")
    assert not storage.exists("2026-10-25/missing")
    assert storage.list_keys("2026-10-25/raw/") == ["2026-10-25/raw/kev/1/kev.json"]


def test_no_overwrite_by_default(storage):
    storage.put_bytes("a/b", b"1")
    with pytest.raises(FileExistsError):
        storage.put_bytes("a/b", b"2")
    storage.put_bytes("a/b", b"3", overwrite=True)
    assert storage.get_bytes("a/b") == b"3"


def test_missing_key_raises(storage):
    with pytest.raises(FileNotFoundError):
        storage.get_bytes("nope")


@pytest.mark.parametrize("key", ["", "/abs", "a/../b", "a//b", "./a", "a\\b"])
def test_rejects_bad_keys(storage, key):
    with pytest.raises(StorageKeyError):
        storage.put_bytes(key, b"x")


def test_has_no_delete_method(storage):
    assert not any("delete" in name or "remove" in name for name in dir(storage))


class FlakyStorage:
    """Wraps a store and fails the first put."""

    def __init__(self, inner):
        self.inner = inner
        self.fail_next = True

    def put_bytes(self, key, data, *, overwrite=False):
        if self.fail_next:
            self.fail_next = False
            raise ConnectionError("network blip")
        self.inner.put_bytes(key, data, overwrite=overwrite)

    def __getattr__(self, name):
        return getattr(self.inner, name)


def test_mirrored_retry_completes_replica(local, s3):
    mirrored = MirroredStorage(local, FlakyStorage(s3))
    with pytest.raises(ConnectionError):
        mirrored.put_bytes("k/v", b"data")
    assert local.exists("k/v") and not s3.exists("k/v")
    mirrored.put_bytes("k/v", b"data")  # retry: local already has it, replica completes
    assert s3.get_bytes("k/v") == b"data"
    with pytest.raises(FileExistsError):
        mirrored.put_bytes("k/v", b"data")  # both already have it
    with pytest.raises(FileExistsError):
        mirrored.put_bytes("k/v", b"other")


def test_local_rejects_symlink_escape(tmp_path):
    root = tmp_path / "store"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "link").symlink_to(outside)
    with pytest.raises(PermissionError):
        LocalStorage(root).put_bytes("link/x", b"x")


def test_local_leaves_no_temp_files(local):
    local.put_bytes("a/b", b"1")
    with pytest.raises(FileExistsError):
        local.put_bytes("a/b", b"2")
    assert [p.name for p in (local.root / "a").iterdir()] == ["b"]


def test_mirrored_writes_both(local, s3):
    mirrored = MirroredStorage(local, s3)
    mirrored.put_bytes("k/v", b"data")
    assert local.get_bytes("k/v") == b"data"
    assert s3.get_bytes("k/v") == b"data"
