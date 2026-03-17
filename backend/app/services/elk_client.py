"""
Elasticsearch client for rule deployment and unit test execution.
"""
import logging
import asyncio
from typing import Optional
from app.config import settings

logger = logging.getLogger(__name__)


class ELKClient:
    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        api_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        use_ssl: bool = False,
    ):
        self.host = host or settings.elk_host
        self.port = port or settings.elk_port
        self.api_key = api_key or settings.elk_api_key
        self.username = username or settings.elk_username
        self.password = password or settings.elk_password
        self.use_ssl = use_ssl or settings.elk_use_ssl
        self._client = None

    def _get_client(self):
        from elasticsearch import AsyncElasticsearch

        scheme = "https" if self.use_ssl else "http"
        hosts = [{"host": self.host, "port": self.port, "scheme": scheme}]

        kwargs = {
            "verify_certs": False,  # allow self-signed certs (on-prem ELK)
            "ssl_show_warn": False,
        }
        if self.api_key:
            kwargs["api_key"] = self.api_key
        elif self.username and self.password:
            kwargs["basic_auth"] = (self.username, self.password)

        return AsyncElasticsearch(hosts, **kwargs)

    async def test_connection(self) -> dict:
        """Test ELK connectivity and return cluster info."""
        client = self._get_client()
        try:
            info = await client.info()
            health = await client.cluster.health()
            return {
                "connected": True,
                "cluster_name": info["cluster_name"],
                "version": info["version"]["number"],
                "status": health["status"],
            }
        except Exception as e:
            logger.error(f"ELK connection failed: {e}")
            return {"connected": False, "error": str(e)}
        finally:
            await client.close()

    async def deploy_rule(self, rule_json: dict, rule_id: str) -> dict:
        """
        Deploy a detection rule to Elasticsearch as a SIEM detection alert.
        Uses the Kibana Detection Engine API if available, otherwise stores as a watcher.
        """
        client = self._get_client()
        try:
            # Try Kibana Detection Engine API (ELK 7.9+)
            import httpx
            scheme = "https" if self.use_ssl else "http"
            kibana_url = f"{scheme}://{self.host}:5601"

            headers = {"Content-Type": "application/json", "kbn-xsrf": "true"}
            if self.api_key:
                headers["Authorization"] = f"ApiKey {self.api_key}"
            elif self.username and self.password:
                import base64
                creds = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
                headers["Authorization"] = f"Basic {creds}"

            async with httpx.AsyncClient(verify=False, timeout=30) as http:
                r = await http.post(
                    f"{kibana_url}/api/detection_engine/rules",
                    json=rule_json,
                    headers=headers,
                )
                if r.status_code in (200, 201):
                    resp_data = r.json()
                    return {
                        "deployed": True,
                        "rule_id_elk": resp_data.get("id"),
                        "method": "kibana_detection_engine",
                    }

            # Fallback: store as Elasticsearch document
            doc = {**rule_json, "detectioncore_rule_id": rule_id, "type": "detection_rule"}
            resp = await client.index(
                index=f"{settings.elk_index_prefix}-rules",
                id=rule_id,
                document=doc,
            )
            return {
                "deployed": True,
                "rule_id_elk": resp["_id"],
                "method": "elasticsearch_index",
            }
        except Exception as e:
            logger.error(f"Rule deployment failed: {e}")
            return {"deployed": False, "error": str(e)}
        finally:
            await client.close()

    async def search(self, index: str, query: str, size: int = 10) -> dict:
        """
        Execute a Lucene query against an ELK index.
        Used for unit test verification.
        """
        client = self._get_client()
        try:
            resp = await client.search(
                index=index,
                body={"query": {"query_string": {"query": query}}, "size": size},
            )
            return {
                "hits": resp["hits"]["total"]["value"],
                "results": resp["hits"]["hits"],
            }
        except Exception as e:
            logger.error(f"ELK search failed: {e}")
            return {"hits": 0, "error": str(e)}
        finally:
            await client.close()

    async def list_indices(self) -> list[dict]:
        """List available ELK indices with document counts."""
        client = self._get_client()
        try:
            resp = await client.cat.indices(format="json", h="index,docs.count,store.size,health")
            return [
                {
                    "index": i.get("index"),
                    "docs_count": int(i.get("docs.count", 0) or 0),
                    "size": i.get("store.size"),
                    "health": i.get("health"),
                }
                for i in resp
                if not str(i.get("index", "")).startswith(".")
            ]
        except Exception as e:
            logger.error(f"Failed to list indices: {e}")
            return []
        finally:
            await client.close()
