"""
Client for DetectionHub REST API.
Authenticates via `access_token` header (JWT token from DetectionHub session).
"""
import httpx
import logging
from typing import Optional
from app.config import settings

logger = logging.getLogger(__name__)

TIMEOUT = 30.0


class DetectionHubClient:
    def __init__(self, base_url: Optional[str] = None, api_key: Optional[str] = None):
        self.base_url = (base_url or settings.detectionhub_base_url).rstrip("/")
        self.api_key = api_key or settings.detectionhub_api_key
        if not self.api_key:
            raise ValueError("DetectionHub API key not configured")

    def _headers(self) -> dict:
        return {
            "Cookie": f"access_token={self.api_key}",
            "Accept": "application/json",
        }

    async def test_connection(self) -> bool:
        """Verify access_token is valid by calling a lightweight endpoint."""
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                r = await client.get(
                    f"{self.base_url}/api/rules/public",
                    headers=self._headers(),
                    params={"page": 1, "page_size": 1},
                )
                return r.status_code == 200
        except Exception as e:
            logger.error(f"DetectionHub connection failed: {e}")
            return False

    async def get_rules(
        self,
        page: int = 1,
        page_size: int = 50,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ) -> dict:
        """
        Fetch paginated rules from DetectionHub.
        start_date / end_date format: YYYY-MM-DD (e.g. "2026-03-16")
        Returns the raw API response dict.
        """
        params: dict = {"page": page, "page_size": page_size}
        if start_date:
            params["start_date"] = start_date
        if end_date:
            params["end_date"] = end_date

        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            r = await client.get(
                f"{self.base_url}/api/rules/public",
                headers=self._headers(),
                params=params,
            )
            r.raise_for_status()
            return r.json()

    async def get_all_rules(
        self,
        page_size: int = 100,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ) -> list[dict]:
        """Fetch all rules (paginated). Optionally filter by date range."""
        all_rules = []
        page = 1
        while True:
            response = await self.get_rules(
                page=page,
                page_size=page_size,
                start_date=start_date,
                end_date=end_date,
            )
            data = response.get("data", {})
            items = data.get("items", []) if isinstance(data, dict) else []
            all_rules.extend(items)
            total = data.get("total", 0) if isinstance(data, dict) else len(items)
            if len(all_rules) >= total or not items:
                break
            page += 1
        logger.info(f"Fetched {len(all_rules)} rules from DetectionHub")
        return all_rules

    async def get_rule(self, rule_id: str) -> Optional[dict]:
        """Fetch a single rule by ID."""
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            r = await client.get(
                f"{self.base_url}/api/rules/public/{rule_id}",
                headers=self._headers(),
            )
            if r.status_code == 404:
                return None
            r.raise_for_status()
            return r.json().get("data")

    async def get_newsfeed(self, page: int = 1, page_size: int = 50) -> dict:
        """Fetch threat intelligence news feed."""
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            r = await client.get(
                f"{self.base_url}/api/newsfeed/active",
                headers=self._headers(),
                params={"page": page, "page_size": page_size},
            )
            r.raise_for_status()
            return r.json()
