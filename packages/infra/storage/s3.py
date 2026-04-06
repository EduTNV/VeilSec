from __future__ import annotations

import json
from uuid import UUID

import aioboto3

from packages.shared.logging import get_logger
from packages.shared.settings import get_settings

settings = get_settings()
log = get_logger(__name__)


class S3StorageAdapter:
    def __init__(self) -> None:
        self._session = aioboto3.Session()
        self._bucket = settings.aws_s3_bucket
        self._endpoint = settings.aws_endpoint_url

    def _client_kwargs(self) -> dict:
        kwargs: dict = {"service_name": "s3", "region_name": settings.aws_region}
        if self._endpoint:
            kwargs["endpoint_url"] = self._endpoint
        return kwargs

    async def upload_text(self, key: str, content: str) -> str:
        async with self._session.client(**self._client_kwargs()) as s3:
            await s3.put_object(
                Bucket=self._bucket,
                Key=key,
                Body=content.encode("utf-8"),
                ServerSideEncryption="AES256",
            )
        return key

    async def upload_json(self, key: str, data: dict) -> str:
        return await self.upload_text(key, json.dumps(data, ensure_ascii=True))

    async def download_text(self, key: str) -> str:
        async with self._session.client(**self._client_kwargs()) as s3:
            response = await s3.get_object(Bucket=self._bucket, Key=key)
            body = await response["Body"].read()
        return body.decode("utf-8")

    async def download_json(self, key: str) -> dict:
        return json.loads(await self.download_text(key))

    async def delete(self, key: str) -> None:
        if key == "DELETED":
            return
        async with self._session.client(**self._client_kwargs()) as s3:
            await s3.delete_object(Bucket=self._bucket, Key=key)
        log.info("storage.deleted", key=key)

    async def delete_all_for_client(self, client_id: UUID) -> None:
        prefix = f"clients/{client_id}/"
        async with self._session.client(**self._client_kwargs()) as s3:
            paginator = s3.get_paginator("list_objects_v2")
            async for page in paginator.paginate(Bucket=self._bucket, Prefix=prefix):
                objects = page.get("Contents", [])
                if objects:
                    await s3.delete_objects(
                        Bucket=self._bucket,
                        Delete={"Objects": [{"Key": o["Key"]} for o in objects]},
                    )
        log.info("storage.client_data_deleted", client_id=str(client_id))

    @staticmethod
    def build_sast_input_key(client_id: UUID, scan_id: UUID) -> str:
        return f"clients/{client_id}/scans/{scan_id}/input.txt"

    @staticmethod
    def build_sast_report_key(client_id: UUID, scan_id: UUID) -> str:
        return f"clients/{client_id}/scans/{scan_id}/report.json"

    @staticmethod
    def build_dast_evidence_key(client_id: UUID, scan_id: UUID, finding_id: UUID) -> str:
        return f"clients/{client_id}/scans/{scan_id}/evidence/{finding_id}.json"
