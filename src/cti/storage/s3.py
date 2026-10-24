"""S3 storage. Uses the boto3 default credential chain (e.g. a named profile)."""

from __future__ import annotations

from typing import Any

import boto3
from botocore.exceptions import ClientError

from cti.storage.base import validate_key


class S3Storage:
    def __init__(
        self,
        bucket: str,
        prefix: str = "",
        *,
        profile: str | None = None,
        client: Any | None = None,
    ) -> None:
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self._s3 = client or boto3.Session(profile_name=profile).client("s3")

    def _key(self, key: str) -> str:
        validate_key(key)
        return f"{self.prefix}/{key}" if self.prefix else key

    def put_bytes(self, key: str, data: bytes, *, overwrite: bool = False) -> None:
        extra: dict[str, str] = {} if overwrite else {"IfNoneMatch": "*"}
        try:
            self._s3.put_object(
                Bucket=self.bucket,
                Key=self._key(key),
                Body=data,
                ChecksumAlgorithm="SHA256",
                **extra,
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in {"PreconditionFailed", "ConditionalRequestConflict"}:
                raise FileExistsError(key) from exc
            raise

    def get_bytes(self, key: str) -> bytes:
        try:
            obj = self._s3.get_object(Bucket=self.bucket, Key=self._key(key))
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in {"NoSuchKey", "404"}:
                raise FileNotFoundError(key) from exc
            raise
        return obj["Body"].read()

    def exists(self, key: str) -> bool:
        try:
            self._s3.head_object(Bucket=self.bucket, Key=self._key(key))
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in {"404", "NoSuchKey", "NotFound"}:
                return False
            raise
        return True

    def list_keys(self, prefix: str = "") -> list[str]:
        full = f"{self.prefix}/{prefix}" if self.prefix else prefix
        strip = len(self.prefix) + 1 if self.prefix else 0
        keys: list[str] = []
        for page in self._s3.get_paginator("list_objects_v2").paginate(
            Bucket=self.bucket, Prefix=full
        ):
            keys.extend(obj["Key"][strip:] for obj in page.get("Contents", []))
        return sorted(keys)
