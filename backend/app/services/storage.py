"""SeaweedFS S3 Ciphertext Storage Client with Local Fallback."""

import os
from typing import Optional
import httpx

from ..core.config import settings


class StorageService:
    """Manages ciphertext object persistence in SeaweedFS S3 or local directory."""

    def __init__(
        self,
        endpoint_url: str = settings.s3_endpoint_url,
        bucket_name: str = settings.s3_bucket_name,
        local_dir: str = settings.local_storage_dir,
    ):
        self.endpoint_url = endpoint_url
        self.bucket_name = bucket_name
        self.local_dir = local_dir
        os.makedirs(self.local_dir, exist_ok=True)

    async def put_ciphertext(self, object_key: str, data: bytes) -> str:
        """Stores ciphertext bytes under object_key.

        Returns:
            object_key
        """
        # 1. Attempt SeaweedFS HTTP PUT
        try:
            url = f"{self.endpoint_url}/{self.bucket_name}/{object_key}"
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.put(url, content=data)
                if resp.status_code in [200, 201]:
                    return object_key
        except Exception:
            pass

        # 2. Local directory fallback
        full_path = os.path.join(self.local_dir, object_key.replace("/", "_"))
        with open(full_path, "wb") as f:
            f.write(data)
        return object_key

    async def get_ciphertext(self, object_key: str) -> Optional[bytes]:
        """Retrieves ciphertext bytes for object_key."""
        # 1. Attempt SeaweedFS HTTP GET
        try:
            url = f"{self.endpoint_url}/{self.bucket_name}/{object_key}"
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    return resp.content
        except Exception:
            pass

        # 2. Local directory fallback
        full_path = os.path.join(self.local_dir, object_key.replace("/", "_"))
        if os.path.exists(full_path):
            with open(full_path, "rb") as f:
                return f.read()

        return None

    async def delete_ciphertext(self, object_key: str) -> bool:
        """Deletes object_key."""
        full_path = os.path.join(self.local_dir, object_key.replace("/", "_"))
        if os.path.exists(full_path):
            os.remove(full_path)
            return True
        return False


storage_service = StorageService()
