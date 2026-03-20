"""
Client for DetectionHub REST API.
Authenticates via email/password: POST /api/auth/signin, then GET /api/auth/me to retrieve token.
"""
import httpx
import logging
from typing import Optional
from app.config import settings

logger = logging.getLogger(__name__)

TIMEOUT = 30.0


class DetectionHubClient:
    def __init__(
        self,
        base_url: Optional[str] = None,
        email: Optional[str] = None,
        password: Optional[str] = None,
    ):
        self.base_url = (base_url or settings.detectionhub_base_url).rstrip("/")
        self.email = email or settings.detectionhub_email
        self.password = password or settings.detectionhub_password
        if not self.email or not self.password:
            raise ValueError("DetectionHub email and password not configured")

    async def _get_token(self, client: httpx.AsyncClient) -> str:
        """Sign in and return the bearer token from /api/auth/me."""
        signin_r = await client.post(
            f"{self.base_url}/api/auth/signin",
            json={"email": self.email, "password": self.password},
            headers={"Accept": "application/json"},
        )
        signin_r.raise_for_status()

        me_r = await client.get(
            f"{self.base_url}/api/auth/me",
            headers={"Accept": "application/json"},
        )
        me_r.raise_for_status()
        token = me_r.json().get("token")
        if not token:
            raise ValueError("No token returned from /api/auth/me")
        return token

    def _auth_headers(self, token: str) -> dict:
        return {
            "Cookie": f"access_token={token}",
            "Accept": "application/json",
        }

    async def test_connection(self) -> bool:
        """Verify credentials are valid by signing in and calling a lightweight endpoint."""
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                token = await self._get_token(client)
                r = await client.get(
                    f"{self.base_url}/api/rules/public",
                    headers=self._auth_headers(token),
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
            token = await self._get_token(client)
            r = await client.get(
                f"{self.base_url}/api/rules/public",
                headers=self._auth_headers(token),
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
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            token = await self._get_token(client)
            while True:
                params: dict = {"page": page, "page_size": page_size}
                if start_date:
                    params["start_date"] = start_date
                if end_date:
                    params["end_date"] = end_date

                r = await client.get(
                    f"{self.base_url}/api/rules/public",
                    headers=self._auth_headers(token),
                    params=params,
                )
                r.raise_for_status()
                response = r.json()
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
            token = await self._get_token(client)
            r = await client.get(
                f"{self.base_url}/api/rules/public/{rule_id}",
                headers=self._auth_headers(token),
            )
            if r.status_code == 404:
                return None
            r.raise_for_status()
            return r.json().get("data")

    async def get_newsfeed(self, page: int = 1, page_size: int = 50) -> dict:
        """Fetch threat intelligence news feed."""
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            token = await self._get_token(client)
            r = await client.get(
                f"{self.base_url}/api/newsfeed/active",
                headers=self._auth_headers(token),
                params={"page": page, "page_size": page_size},
            )
            r.raise_for_status()
            return r.json()
