"""Local filesystem storage."""

from __future__ import annotations

import os
from pathlib import Path

from cti.storage.base import validate_key


class LocalStorage:
    def __init__(self, root: Path | str) -> None:
        self.root = Path(root).resolve()

    def _path(self, key: str) -> Path:
        return self.root / validate_key(key)

    def put_bytes(self, key: str, data: bytes, *, overwrite: bool = False) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        if not overwrite and path.exists():
            raise FileExistsError(key)
        tmp = path.with_name(f".{path.name}.tmp")
        tmp.write_bytes(data)
        os.replace(tmp, path)

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
