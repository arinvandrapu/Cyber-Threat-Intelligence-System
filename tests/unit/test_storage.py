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


def test_mirrored_writes_both(local, s3):
    mirrored = MirroredStorage(local, s3)
    mirrored.put_bytes("k/v", b"data")
    assert local.get_bytes("k/v") == b"data"
    assert s3.get_bytes("k/v") == b"data"
