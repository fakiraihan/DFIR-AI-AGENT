"""
Threat Intelligence Tool Wrappers
Integrations for 6 threat intel APIs
"""
import requests
import aiohttp
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
import time


class ThreatIntelToolkit:
    """Collection of threat intelligence API wrappers"""
    
    def __init__(self, api_keys: Dict[str, str]):
        """
        Initialize toolkit with API keys
        
        Args:
            api_keys: Dictionary with keys for each service
        """
        self.api_keys = api_keys
        self.session_cache = {}  # Cache results per session
    
    def _cache_key(self, tool_name: str, ioc: str) -> str:
        """Generate cache key"""
        return f"{tool_name}:{ioc}"
    
    def _get_cached(self, tool_name: str, ioc: str) -> Optional[Dict]:
        """Get cached result if available"""
        key = self._cache_key(tool_name, ioc)
        return self.session_cache.get(key)
    
    def _set_cache(self, tool_name: str, ioc: str, result: Dict):
        """Cache result"""
        key = self._cache_key(tool_name, ioc)
        self.session_cache[key] = result
    
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
        print(f"\n  → ThreatFox API Call")
        print(f"    IOC: {ioc} (type: {ioc_type})")
        
        # Check cache
        cached = self._get_cached("threatfox", ioc)
        if cached:
            print(f"    ✓ Cache hit")
            return cached
        
        url = "https://threatfox-api.abuse.ch/api/v1/"
        
        payload = {
            "query": "search_ioc",
            "search_term": ioc
        }
        
        headers = {}
        # Add API key if available (optional but increases rate limits)
        api_key = self.api_keys.get("abusech_api_key")
        if api_key:
            headers["Auth-Key"] = api_key
            print(f"    Auth: Using API key (first 8 chars: {api_key[:8]}...)")
        else:
            print(f"    Auth: No API key (Get free key at https://auth.abuse.ch/)")
        
        try:
            print(f"    Sending POST to {url}")
            response = requests.post(url, json=payload, headers=headers, timeout=10)
            print(f"    Response: HTTP {response.status_code}")
            
            response.raise_for_status()
            data = response.json()
            
            print(f"    Query status: {data.get('query_status')}")
            print(f"    Results: {len(data.get('data', []))} items")
            
            result = {
                "tool": "threatfox",
                "ioc": ioc,
                "ioc_type": ioc_type,
                "timestamp": datetime.now().isoformat(),
                "status": data.get("query_status"),
                "data": data.get("data", []),
                "malware_family": None,
                "confidence_level": None,
                "threat_type": None
            }
            
            # Extract key info
            if data.get("data"):
                first_entry = data["data"][0]
                result["malware_family"] = first_entry.get("malware")
                result["confidence_level"] = first_entry.get("confidence_level")
                result["threat_type"] = first_entry.get("threat_type")
                print(f"    Malware: {result['malware_family']}")
                print(f"    Threat: {result['threat_type']}")
            
            # Cache result
            self._set_cache("threatfox", ioc, result)
            
            return result
            
        except requests.exceptions.RequestException as e:
            print(f"    ✗ Request failed: {e}")
            return {
                "tool": "threatfox",
                "ioc": ioc,
                "error": str(e),
                "status": "error"
            }
        except Exception as e:
            print(f"    ✗ Exception: {e}")
            return {
                "tool": "threatfox",
                "ioc": ioc,
                "error": str(e),
                "status": "error"
            }
    
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
        # Add API key if available (optional but increases rate limits)
        api_key = self.api_keys.get("abusech_api_key")
        if api_key:
            headers["Auth-Key"] = api_key
        
        try:
            response = requests.post(url, data=payload, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            result = {
                "tool": "malwarebazaar",
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
            return {
                "tool": "malwarebazaar",
                "hash": file_hash,
                "error": str(e),
                "status": "error"
            }
    
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
        # Add API key if available (optional but increases rate limits)
        api_key = self.api_keys.get("abusech_api_key")
        if api_key:
            headers["Auth-Key"] = api_key
        
        try:
            response = requests.post(api_url, data=payload, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            result = {
                "tool": "urlhaus",
                "url": url,
                "timestamp": datetime.now().isoformat(),
                "status": data.get("query_status"),
                "url_status": data.get("url_status"),
                "threat": data.get("threat"),
                "tags": data.get("tags", []),
                "payloads": data.get("payloads", [])
            }
            
            self._set_cache("urlhaus", url, result)
            return result
            
        except Exception as e:
            return {
                "tool": "urlhaus",
                "url": url,
                "error": str(e),
                "status": "error"
            }
    
    # ===== AlienVault OTX =====
    def alienvault_otx_lookup(self, ioc: str, ioc_type: str = "IPv4") -> Dict[str, Any]:
        """
        Query AlienVault OTX for IOC intel
        Documentation: https://otx.alienvault.com/api
        
        Args:
            ioc: IOC value
            ioc_type: IPv4, domain, hostname, url, md5, sha256
            
        Returns:
            OTX threat intelligence
        """
        cached = self._get_cached("otx", ioc)
        if cached:
            return cached
        
        api_key = self.api_keys.get("alienvault_otx_api_key")
        if not api_key:
            return {"tool": "otx", "ioc": ioc, "error": "API key required (get free at otx.alienvault.com)", "status": "error"}
        
        base_url = f"https://otx.alienvault.com/api/v1/indicators/{ioc_type}/{ioc}/general"
        headers = {"X-OTX-API-KEY": api_key}
        
        try:
            response = requests.get(base_url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            result = {
                "tool": "alienvault_otx",
                "ioc": ioc,
                "ioc_type": ioc_type,
                "timestamp": datetime.now().isoformat(),
                "pulse_count": data.get("pulse_info", {}).get("count", 0),
                "pulses": data.get("pulse_info", {}).get("pulses", [])[:3],  # Top 3 pulses
                "reputation": data.get("reputation"),
                "country": data.get("country_name")
            }
            
            self._set_cache("otx", ioc, result)
            return result
            
        except Exception as e:
            return {
                "tool": "alienvault_otx",
                "ioc": ioc,
                "error": str(e),
                "status": "error"
            }
    
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
                "ip": ip,
                "timestamp": datetime.now().isoformat(),
                "classification": data.get("classification"),
                "noise": data.get("noise", False),
                "riot": data.get("riot", False),
                "message": data.get("message"),
                "tags": data.get("tags", [])
            }
            
            self._set_cache("greynoise", ip, result)
            return result
            
        except Exception as e:
            return {
                "tool": "greynoise",
                "ip": ip,
                "error": str(e),
                "status": "error"
            }
    
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
            return {"tool": "virustotal", "ioc": ioc, "error": "API key required (get free at virustotal.com)", "status": "error"}
        
        # Determine endpoint
        if ioc_type == "ip":
            endpoint = f"ip-addresses/{ioc}"
        elif ioc_type == "domain":
            endpoint = f"domains/{ioc}"
        elif ioc_type == "url":
            import base64
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            endpoint = f"urls/{url_id}"
        elif ioc_type == "file":
            endpoint = f"files/{ioc}"
        else:
            endpoint = f"ip-addresses/{ioc}"
        
        url = f"https://www.virustotal.com/api/v3/{endpoint}"
        headers = {"x-apikey": api_key}
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            attributes = data.get("data", {}).get("attributes", {})
            last_analysis_stats = attributes.get("last_analysis_stats", {})
            
            result = {
                "tool": "virustotal",
                "ioc": ioc,
                "ioc_type": ioc_type,
                "timestamp": datetime.now().isoformat(),
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
            return {
                "tool": "virustotal",
                "ioc": ioc,
                "error": str(e),
                "status": "error"
            }
    
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
