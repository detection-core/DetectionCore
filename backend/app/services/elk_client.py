"""
Elasticsearch client for rule deployment and unit test execution.
"""
import logging
from typing import Optional
from app.config import settings

logger = logging.getLogger(__name__)


def _flatten_properties(properties: dict, prefix: str, out: list) -> None:
    """Recursively flatten Elasticsearch mapping properties to dot-notation field list."""
    for name, field_def in properties.items():
        if name.startswith("_"):
            continue
        full_name = f"{prefix}{name}" if not prefix else f"{prefix}.{name}"
        field_type = field_def.get("type", "object")
        out.append({"name": full_name, "type": field_type})
        nested = field_def.get("properties") or field_def.get("fields") or {}
        if nested:
            _flatten_properties(nested, full_name, out)


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

    async def deploy_rule(self, rule_json: dict) -> dict:
        """
        Deploy a detection rule to Elasticsearch as a SIEM detection alert.
        Uses the Kibana Detection Engine API if available, otherwise stores as a watcher.
        """
        client = self._get_client()
        try:
            # Try Kibana Detection Engine API (ELK 7.9+)
            import httpx
            from app.config import settings
            kibana_url = (settings.kibana_url or f"http://{self.host}:5601").rstrip("/")

            headers = {"Content-Type": "application/json", "kbn-xsrf": "true"}
            if self.api_key:
                headers["Authorization"] = f"ApiKey {self.api_key}"
            elif self.username and self.password:
                import base64
                creds = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
                headers["Authorization"] = f"Basic {creds}"

            # Normalize rule_json to satisfy Kibana validation
            payload = dict(rule_json)
            author = payload.get("author", "DetectionCore")
            payload["author"] = author if isinstance(author, list) else [author]
            fixed_threat = []
            for entry in payload.get("threat", []):
                if "tactic" not in entry:
                    techniques = entry.get("technique", [])
                    tid = techniques[0]["id"] if techniques else "T0000"
                    entry = {**entry, "tactic": {"id": "unknown", "name": "Unknown", "reference": f"https://attack.mitre.org/techniques/{tid}/"}}
                fixed_threat.append(entry)
            payload["threat"] = fixed_threat

            async with httpx.AsyncClient(verify=False, timeout=30) as http:
                # Ensure detection engine index is initialized
                init_r = await http.post(
                    f"{kibana_url}/api/detection_engine/index",
                    headers=headers,
                )
                if init_r.status_code not in (200, 201):
                    logger.warning(f"Kibana detection engine init: {init_r.status_code} {init_r.text[:200]}")

                r = await http.post(
                    f"{kibana_url}/api/detection_engine/rules",
                    json=payload,
                    headers=headers,
                )
                if r.status_code in (200, 201):
                    resp_data = r.json()
                    return {
                        "deployed": True,
                        "rule_id_elk": resp_data.get("id"),
                        "method": "kibana_detection_engine",
                    }
                logger.error(f"Kibana detection engine API returned {r.status_code}: {r.text[:500]}")

            # Fallback: Kibana unavailable — do not report as deployed
            return {
                "deployed": False,
                "error": "Kibana Detection Engine API rejected the rule — check server logs for details",
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

    async def get_field_names(self, index_pattern: str) -> list[dict]:
        """
        Return all field names and types from an Elasticsearch index pattern.
        Recursively flattens nested 'properties' to dot-notation.
        Returns [] (not an error) when the pattern matches no indices.
        Raises an exception on connection failure.
        """
        client = self._get_client()
        try:
            response = await client.indices.get_mapping(index=index_pattern)
            fields = []
            for _, index_data in response.items():
                mappings = index_data.get("mappings", {})
                _flatten_properties(mappings.get("properties", {}), prefix="", out=fields)
            # Deduplicate by name (multiple backing indices may share the same fields)
            seen = set()
            unique_fields = []
            for f in fields:
                if f["name"] not in seen:
                    seen.add(f["name"])
                    unique_fields.append(f)
            return sorted(unique_fields, key=lambda x: x["name"])
        finally:
            await client.close()

    async def list_indices(self) -> list[dict]:
        """List data streams and regular indices with document counts.

        Data streams are preferred — each groups all its backing indices
        (e.g. .ds-winlogbeat-9.3.1-2026.03.20-000001) under one logical name.
        Regular indices that are NOT backing a data stream are included separately.
        Hidden/system indices (starting with '.') are excluded.
        """
        client = self._get_client()
        try:
            results = []
            backing_index_names = set()

            # 1. Fetch data streams
            try:
                ds_resp = await client.indices.get_data_stream(name="*")
                for ds in ds_resp.get("data_streams", []):
                    name = ds.get("name", "")
                    indices = ds.get("indices", [])
                    # Track backing index names so we can exclude them below
                    for idx in indices:
                        backing_index_names.add(idx.get("index_name", ""))
                    # Get doc count from the write index via cat
                    write_index = indices[-1].get("index_name", "") if indices else ""
                    doc_count = 0
                    size = None
                    if write_index:
                        try:
                            cat = await client.cat.indices(
                                index=write_index, format="json", h="docs.count,store.size"
                            )
                            if cat:
                                doc_count = int(cat[0].get("docs.count", 0) or 0)
                                size = cat[0].get("store.size")
                        except Exception:
                            pass
                    results.append({
                        "index": name,
                        "type": "data_stream",
                        "docs_count": doc_count,
                        "size": size,
                        "health": ds.get("status", "unknown").lower(),
                        "backing_indices": len(indices),
                    })
            except Exception as e:
                logger.warning(f"Could not fetch data streams: {e}")

            # 2. Fetch regular indices, skip system and backing indices
            cat_resp = await client.cat.indices(format="json", h="index,docs.count,store.size,health")
            for i in cat_resp:
                name = str(i.get("index", ""))
                if name.startswith(".") or name in backing_index_names:
                    continue
                results.append({
                    "index": name,
                    "type": "index",
                    "docs_count": int(i.get("docs.count", 0) or 0),
                    "size": i.get("store.size"),
                    "health": i.get("health"),
                    "backing_indices": None,
                })

            return sorted(results, key=lambda x: x["index"])
        except Exception as e:
            logger.error(f"Failed to list indices: {e}")
            return []
        finally:
            await client.close()
