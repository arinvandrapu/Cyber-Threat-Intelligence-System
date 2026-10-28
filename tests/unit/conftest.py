import gzip
import hashlib
import io
import json
import tarfile
import zipfile
from datetime import date

import httpx
import pytest

from cti.config import Settings
from cti.snapshot import Snapshot
from cti.sources.base import FetchContext
from cti.storage import LocalStorage

SNAPSHOT_DAY = date(2026, 10, 25)  # cutoff = 2026-04-28 with the default 180 days
KEY = "TESTKEY123"


@pytest.fixture
def settings():
    return Settings(
        _env_file=None, contact="test@example.com", abusech_auth_key=KEY, extra_cutoffs=0
    )


@pytest.fixture
def storage(tmp_path):
    return LocalStorage(tmp_path / "snapshots")


@pytest.fixture
def snapshot(storage):
    return Snapshot.create(storage, SNAPSHOT_DAY.isoformat())


@pytest.fixture
def ctx(snapshot, settings):
    with httpx.Client() as client:
        yield FetchContext(
            snapshot=snapshot,
            client=client,
            settings=settings,
            snapshot_date=SNAPSHOT_DAY,
            secrets=[KEY],
        )


def gzip_bytes(data: bytes) -> bytes:
    return gzip.compress(data, mtime=0)


def tar_gz(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def zip_bytes(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def nvd_meta(payload: bytes) -> bytes:
    sha = hashlib.sha256(payload).hexdigest().upper()
    return (
        f"lastModifiedDate:2026-10-25T03:00:00-04:00\nsize:{len(payload)}\nsha256:{sha}\n".encode()
    )


CUTOFF_DAY = date(2026, 4, 28)


def pin_github(monkeypatch, repo, branch, shas):
    """Replace git pinning: the cutoff date maps to shas['cutoff'], the snapshot date to
    shas['snapshot']. Asserts the right repo, branch, and dates are requested."""
    from cti.sources import github

    def fake_head_at(url, br, on):
        assert url == github.repo_url(repo)
        assert br == branch
        assert on in (CUTOFF_DAY, SNAPSHOT_DAY)
        return shas["cutoff" if on == CUTOFF_DAY else "snapshot"], on.isoformat()

    monkeypatch.setattr(github, "head_at", fake_head_at)


def jsonl(rows) -> bytes:
    return "\n".join(json.dumps(r) for r in rows).encode()
