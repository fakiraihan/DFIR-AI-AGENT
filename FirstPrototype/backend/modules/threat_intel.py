"""
Threat Intelligence Tool Wrappers
Integrations for 6 threat intel APIs
"""
import requests
import json
from collections import OrderedDict
from typing import Dict, List, Optional, Any
from datetime import datetime
import time
import threading
from urllib.parse import quote


class ThreatIntelToolkit:
    """Collection of threat intelligence API wrappers"""
    
    def __init__(self, api_keys: Dict[str, str]):
        """
        Initialize toolkit with API keys
        
        Args:
            api_keys: Dictionary with keys for each service
        """
        self.api_keys = api_keys
        self.max_cache_entries = 512
        self.session_cache = OrderedDict()  # Bounded cache results per session
        self._cache_lock = threading.RLock()
    
    def _cache_key(self, tool_name: str, ioc: str) -> str:
        """Generate cache key"""
        return f"{tool_name}:{ioc}"
    
    def _get_cached(self, tool_name: str, ioc: str) -> Optional[Dict]:
        """Get cached result if available"""
        key = self._cache_key(tool_name, ioc)
        with self._cache_lock:
            cached = self.session_cache.get(key)
            if cached is not None:
                self.session_cache.move_to_end(key)
            return cached
    
    def _set_cache(self, tool_name: str, ioc: str, result: Dict):
        """Cache result"""
        key = self._cache_key(tool_name, ioc)
        with self._cache_lock:
            self.session_cache[key] = result
            self.session_cache.move_to_end(key)
            while len(self.session_cache) > self.max_cache_entries:
                self.session_cache.popitem(last=False)

    def _error_result(
        self,
        tool: str,
        error: Exception | str,
        *,
        ioc: Optional[str] = None,
        ioc_type: Optional[str] = None,
        data: Any = None,
        **extra: Any,
    ) -> Dict[str, Any]:
        """Build a consistent error payload with explicit HTTP details when available."""
        result: Dict[str, Any] = {
            "tool": tool,
            "timestamp": datetime.now().isoformat(),
            "status": "error",
            "error": str(error),
            "data": [] if data is None else data,
        }
        if ioc is not None:
            result["ioc"] = ioc
        if ioc_type is not None:
            result["ioc_type"] = ioc_type

        response = getattr(error, "response", None)
        status_code = getattr(response, "status_code", None)
        if status_code is not None:
            result["http_status"] = status_code
            result["http_error"] = f"HTTP {status_code}"
        result.update(extra)
        return result
    
    # ===== ThreatFox =====
    def threatfox_lookup(self, ioc: str, ioc_type: str = "ip") -> Dict[str, Any]:
        """
        Query ThreatFox API for IOC intel
        Documentation: https://threatfox.abuse.ch/api/
        
        Args:
            ioc: IP, domain, URL, or hash
            ioc_type: Type of IOC (ip, domain, url, md5_hash, sha256_hash)
            
        Returns:
            Threat intelligence data
        """
        print("\n  -> ThreatFox API Call")
        print(f"    IOC: {ioc} (type: {ioc_type})")
        
        # Check cache
        cached = self._get_cached("threatfox", ioc)
        if cached:
            print("    Cache hit")
            return cached
        
        url = "https://threatfox-api.abuse.ch/api/v1/"
        
        payload = {
            "query": "search_ioc",
            "search_term": ioc
        }
        
        headers = {}
        # abuse.ch requires Auth-Key for authenticated API access.
        api_key = self.api_keys.get("abusech_api_key")
        if api_key:
            headers["Auth-Key"] = api_key
            print("    Auth: Using configured API key")
        else:
            print(f"    Auth: No API key configured (abuse.ch APIs require Auth-Key; get a free key at https://auth.abuse.ch/)")
        
        try:
            print(f"    Sending POST to {url}")
            response = requests.post(url, json=payload, headers=headers, timeout=10)
            print(f"    Response: HTTP {response.status_code}")
            
            response.raise_for_status()
            raw_data = response.json()
            data = raw_data if isinstance(raw_data, dict) else {}
            query_status = data.get("query_status") if isinstance(data.get("query_status"), str) else "unknown"

            response_items = data.get("data", [])
            if isinstance(response_items, dict):
                response_items = [response_items]
            elif not isinstance(response_items, list):
                response_items = []

            response_items = [item for item in response_items if isinstance(item, dict)]
            exact_response_items = self._filter_exact_ioc_matches(response_items, ioc)
            if response_items and not exact_response_items:
                print(f"    Exact IOC matches: 0 (ignored {len(response_items)} related/non-exact items)")
                query_status = "no_exact_match"
                response_items = []
            elif exact_response_items:
                response_items = exact_response_items

            print(f"    Query status: {query_status}")
            print(f"    Results: {len(response_items)} items")
            
            result = {
                "tool": "threatfox",
                "ioc": ioc,
                "ioc_type": ioc_type,
                "timestamp": datetime.now().isoformat(),
                "status": query_status,
                "data": response_items,
                "malware_family": None,
                "confidence_level": None,
                "threat_type": None
            }
            
            # Extract key info
            if response_items:
                first_entry = response_items[0]
                result["malware_family"] = first_entry.get("malware")
                result["confidence_level"] = first_entry.get("confidence_level")
                result["threat_type"] = first_entry.get("threat_type")
                print(f"    Malware: {result['malware_family']}")
                print(f"    Threat: {result['threat_type']}")
            
            # Cache result
            self._set_cache("threatfox", ioc, result)
            
            return result
            
        except requests.exceptions.RequestException as e:
            print(f"    Request failed: {e}")
            return self._error_result("threatfox", e, ioc=ioc, ioc_type=ioc_type)
        except Exception as e:
            print(f"    Exception: {e}")
            return self._error_result("threatfox", e, ioc=ioc, ioc_type=ioc_type)

    def _filter_exact_ioc_matches(self, items: List[Dict[str, Any]], requested_ioc: str) -> List[Dict[str, Any]]:
        """Keep ThreatFox rows that match the exact IOC requested."""
        requested = requested_ioc.strip().lower().rstrip("/")
        exact_matches = []
        for item in items:
            returned_ioc = str(item.get("ioc", "")).strip().lower().rstrip("/")
            if returned_ioc == requested:
                exact_matches.append(item)
        return exact_matches
    
    # ===== MalwareBazaar =====
    def malwarebazaar_lookup(self, file_hash: str) -> Dict[str, Any]:
        """
        Query MalwareBazaar for file hash intel
        Documentation: https://bazaar.abuse.ch/api/
        
        Args:
            file_hash: MD5 or SHA256 hash
            
        Returns:
            Malware intelligence data
        """
        cached = self._get_cached("malwarebazaar", file_hash)
        if cached:
            return cached
        
        url = "https://mb-api.abuse.ch/api/v1/"
        
        payload = {
            "query": "get_info",
            "hash": file_hash
        }
        
        headers = {}
        # abuse.ch requires Auth-Key for authenticated API access.
        api_key = self.api_keys.get("abusech_api_key")
        if api_key:
            headers["Auth-Key"] = api_key
        
        try:
            response = requests.post(url, data=payload, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            result = {
                "tool": "malwarebazaar",
                "ioc": file_hash,
                "ioc_type": "hash",
                "hash": file_hash,
                "timestamp": datetime.now().isoformat(),
                "status": data.get("query_status"),
                "data": data.get("data", []),
                "file_name": None,
                "file_type": None,
                "signature": None,
                "tags": []
            }
            
            # Extract key info
            if data.get("data"):
                entry = data["data"][0] if isinstance(data["data"], list) else data["data"]
                result["file_name"] = entry.get("file_name")
                result["file_type"] = entry.get("file_type")
                result["signature"] = entry.get("signature")
                result["tags"] = entry.get("tags", [])
            
            self._set_cache("malwarebazaar", file_hash, result)
            return result
            
        except Exception as e:
            return self._error_result("malwarebazaar", e, ioc=file_hash, hash=file_hash)
    
    # ===== URLHaus =====
    def urlhaus_lookup(self, url: str) -> Dict[str, Any]:
        """
        Query URLHaus for URL intel
        Documentation: https://urlhaus.abuse.ch/api/
        
        Args:
            url: URL to check
            
        Returns:
            URL threat intelligence
        """
        cached = self._get_cached("urlhaus", url)
        if cached:
            return cached
        
        api_url = "https://urlhaus-api.abuse.ch/v1/url/"
        
        payload = {
            "url": url
        }
        
        headers = {}
        # abuse.ch requires Auth-Key for authenticated API access.
        api_key = self.api_keys.get("abusech_api_key")
        if api_key:
            headers["Auth-Key"] = api_key
        
        try:
            response = requests.post(api_url, data=payload, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            result = {
                "tool": "urlhaus",
                "ioc": url,
                "ioc_type": "url",
                "url": url,
                "timestamp": datetime.now().isoformat(),
                "status": data.get("query_status"),
                "data": data,
                "url_status": data.get("url_status"),
                "threat": data.get("threat"),
                "tags": data.get("tags", []),
                "payloads": data.get("payloads", [])
            }
            
            self._set_cache("urlhaus", url, result)
            return result
            
        except Exception as e:
            return self._error_result("urlhaus", e, ioc=url, ioc_type="url", url=url)
    
    # ===== AlienVault OTX =====
    def alienvault_otx_lookup(self, ioc: str, ioc_type: str = "IPv4") -> Dict[str, Any]:
        """
        Query AlienVault OTX for IOC intel
        Documentation: https://otx.alienvault.com/api
        
        Args:
            ioc: IOC value
            ioc_type: IPv4, domain, hostname, URL, url, md5, sha1, sha256,
                file, FileHash-MD5, FileHash-SHA1, or FileHash-SHA256
            
        Returns:
            OTX threat intelligence
        """
        cached = self._get_cached("otx", ioc)
        if cached:
            return cached
        
        api_key = self.api_keys.get("alienvault_otx_api_key")
        if not api_key:
            return self._error_result(
                "alienvault_otx",
                "API key required (get free at otx.alienvault.com)",
                ioc=ioc,
                ioc_type=ioc_type,
            )
        
        otx_ioc_type = self._normalize_otx_ioc_type(ioc_type)
        encoded_ioc = quote(ioc, safe="")
        base_url = f"https://otx.alienvault.com/api/v1/indicators/{otx_ioc_type}/{encoded_ioc}/general"
        headers = {"X-OTX-API-KEY": api_key}
        
        try:
            response = requests.get(base_url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            result = {
                "tool": "alienvault_otx",
                "ioc": ioc,
                "ioc_type": otx_ioc_type,
                "timestamp": datetime.now().isoformat(),
                "status": "ok",
                "data": data,
                "pulse_count": data.get("pulse_info", {}).get("count", 0),
                "pulses": data.get("pulse_info", {}).get("pulses", [])[:3],  # Top 3 pulses
                "reputation": data.get("reputation"),
                "country": data.get("country_name")
            }
            
            self._set_cache("otx", ioc, result)
            return result
            
        except Exception as e:
            return self._error_result("alienvault_otx", e, ioc=ioc, ioc_type=otx_ioc_type)

    def _normalize_otx_ioc_type(self, ioc_type: str) -> str:
        """Map local IOC labels to AlienVault OTX indicator API types."""
        normalized = (ioc_type or "").strip()
        normalized_lower = normalized.lower()

        if normalized in {"IPv4", "IPv6"}:
            return normalized
        if normalized in {"URL", "url"}:
            return "url"
        if normalized in {"FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256"}:
            return "file"

        if normalized_lower in {"ip", "ipv4"}:
            return "IPv4"
        if normalized_lower == "ipv6":
            return "IPv6"
        if normalized_lower in {"domain", "hostname"}:
            return normalized_lower
        if normalized_lower == "url":
            return "url"
        if normalized_lower in {"md5", "sha1", "sha256"}:
            return "file"
        if normalized_lower in {"file", "hash", "filehash"}:
            return "file"

        return normalized or "IPv4"
    
    # ===== GreyNoise =====
    def greynoise_lookup(self, ip: str) -> Dict[str, Any]:
        """
        Query GreyNoise for IP classification
        Documentation: https://docs.greynoise.io/docs/using-the-greynoise-api
        
        Args:
            ip: IP address
            
        Returns:
            GreyNoise classification
        """
        cached = self._get_cached("greynoise", ip)
        if cached:
            return cached
        
        api_key = self.api_keys.get("greynoise_api_key")
        if not api_key:
            # Use community API (no key required, limited data)
            url = f"https://api.greynoise.io/v3/community/{ip}"
            headers = {}
        else:
            # Full API with key - use Bearer token authentication
            url = f"https://api.greynoise.io/v2/noise/context/{ip}"
            headers = {"Authorization": f"Bearer {api_key}"}
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            result = {
                "tool": "greynoise",
                "ioc": ip,
                "ioc_type": "ip",
                "ip": ip,
                "timestamp": datetime.now().isoformat(),
                "status": "ok",
                "data": data,
                "classification": data.get("classification"),
                "noise": data.get("noise", False),
                "riot": data.get("riot", False),
                "message": data.get("message"),
                "tags": data.get("tags", [])
            }
            
            self._set_cache("greynoise", ip, result)
            return result
            
        except Exception as e:
            return self._error_result("greynoise", e, ioc=ip, ioc_type="ip", ip=ip)
    
    # ===== VirusTotal =====
    def virustotal_lookup(self, ioc: str, ioc_type: str = "ip") -> Dict[str, Any]:
        """
        Query VirusTotal for IOC reputation
        Documentation: https://developers.virustotal.com/reference/overview
        
        Args:
            ioc: IP, domain, URL, or file hash
            ioc_type: Type of indicator (ip, domain, url, file)
            
        Returns:
            VirusTotal reputation data
        """
        cached = self._get_cached("virustotal", ioc)
        if cached:
            return cached
        
        api_key = self.api_keys.get("virustotal_api_key")
        if not api_key:
            return self._error_result(
                "virustotal",
                "API key required (get free at virustotal.com)",
                ioc=ioc,
                ioc_type=ioc_type,
            )
        
        # Determine endpoint
        if ioc_type == "ip":
            endpoint = f"ip_addresses/{ioc}"
        elif ioc_type == "domain":
            endpoint = f"domains/{ioc}"
        elif ioc_type == "url":
            import base64
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            endpoint = f"urls/{url_id}"
        elif ioc_type == "file":
            endpoint = f"files/{ioc}"
        else:
            endpoint = f"ip_addresses/{ioc}"
        
        url = f"https://www.virustotal.com/api/v3/{endpoint}"
        headers = {"x-apikey": api_key}
        
        try:
            response = None
            for attempt in range(3):
                response = requests.get(url, headers=headers, timeout=20)
                if response.status_code != 429:
                    break

                wait_seconds = min(30 * (2 ** attempt), 60)
                print(
                    "    VirusTotal rate limited "
                    f"(HTTP 429), retrying in {wait_seconds}s "
                    f"(attempt {attempt + 1}/3)"
                )
                time.sleep(wait_seconds)

            if response is None:
                raise RuntimeError("VirusTotal request was not executed")

            response.raise_for_status()
            data = response.json()
            
            attributes = data.get("data", {}).get("attributes", {})
            last_analysis_stats = attributes.get("last_analysis_stats", {})
            
            result = {
                "tool": "virustotal",
                "ioc": ioc,
                "ioc_type": ioc_type,
                "timestamp": datetime.now().isoformat(),
                "status": "ok",
                "data": data.get("data", {}),
                "malicious": last_analysis_stats.get("malicious", 0),
                "suspicious": last_analysis_stats.get("suspicious", 0),
                "harmless": last_analysis_stats.get("harmless", 0),
                "undetected": last_analysis_stats.get("undetected", 0),
                "total_votes": attributes.get("total_votes", {}),
                "reputation": attributes.get("reputation", 0)
            }
            
            self._set_cache("virustotal", ioc, result)
            return result
            
        except Exception as e:
            return self._error_result("virustotal", e, ioc=ioc, ioc_type=ioc_type)
    
    def get_all_tools(self) -> List[str]:
        """Get list of available tools"""
        return [
            "threatfox_lookup",
            "malwarebazaar_lookup",
            "urlhaus_lookup",
            "alienvault_otx_lookup",
            "greynoise_lookup",
            "virustotal_lookup"
        ]


if __name__ == "__main__":
    # Test threat intel tools
    toolkit = ThreatIntelToolkit(api_keys={})
    
    # Test ThreatFox (no key required)
    print("=== ThreatFox Test ===")
    result = toolkit.threatfox_lookup("8.8.8.8", "ip")
    print(json.dumps(result, indent=2))
