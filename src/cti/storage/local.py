"""Local filesystem storage."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from cti.storage.base import validate_key


class LocalStorage:
    def __init__(self, root: Path | str) -> None:
        self.root = Path(root).resolve()

    def _path(self, key: str) -> Path:
        path = self.root / validate_key(key)
        # Refuse keys that escape the root through a symlinked directory.
        if not path.parent.resolve().is_relative_to(self.root):
            raise PermissionError(f"key escapes storage root: {key!r}")
        return path

    def put_bytes(self, key: str, data: bytes, *, overwrite: bool = False) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            if overwrite:
                os.replace(tmp, path)
            else:
                os.link(tmp, path)  # atomic create; fails if the key already exists
        finally:
            tmp.unlink(missing_ok=True)

    def get_bytes(self, key: str) -> bytes:
        return self._path(key).read_bytes()

    def exists(self, key: str) -> bool:
        return self._path(key).is_file()

    def list_keys(self, prefix: str = "") -> list[str]:
        if not self.root.exists():
            return []
        keys = (
            p.relative_to(self.root).as_posix()
            for p in self.root.rglob("*")
            if p.is_file() and not p.name.startswith(".")
        )
        return sorted(k for k in keys if k.startswith(prefix))
