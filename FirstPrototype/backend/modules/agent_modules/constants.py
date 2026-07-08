"""Constants used by the DFIR agent orchestration layer."""

IOC_TYPES = {"ip", "domain", "url", "md5", "sha256"}

EXECUTABLE_FILE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".tmp",
    ".sys",
    ".dat",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".jar",
    ".msi",
    ".lnk",
}

TOOL_TO_IOC_TYPES = {
    "threatfox_lookup": {"ip", "domain", "url", "md5", "sha256"},
    "malwarebazaar_lookup": {"md5", "sha256"},
    "urlhaus_lookup": {"url"},
    "alienvault_otx_lookup": {"ip", "domain", "url", "md5", "sha256"},
    "shodan_internetdb_lookup": {"ip"},
    "abuseipdb_lookup": {"ip"},
    "virustotal_lookup": {"ip", "domain", "url", "md5", "sha256"},
}

TOOL_RESULT_ALIASES = {
    "threatfox": "threatfox_lookup",
    "malwarebazaar": "malwarebazaar_lookup",
    "urlhaus": "urlhaus_lookup",
    "otx": "alienvault_otx_lookup",
    "alienvault_otx": "alienvault_otx_lookup",
    "shodan": "shodan_internetdb_lookup",
    "shodan_internetdb": "shodan_internetdb_lookup",
    "abuseipdb": "abuseipdb_lookup",
    "virustotal": "virustotal_lookup",
}

MEMORY_TOOL_TO_AGENT_TOOL = {
    "threatfox": "threatfox_lookup",
    "malwarebazaar": "malwarebazaar_lookup",
    "urlhaus": "urlhaus_lookup",
    "alienvault_otx": "alienvault_otx_lookup",
    "shodan_internetdb": "shodan_internetdb_lookup",
    "abuseipdb": "abuseipdb_lookup",
    "virustotal": "virustotal_lookup",
}

AGENT_TOOL_TO_MEMORY_TOOL = {
    "threatfox_lookup": "threatfox",
    "malwarebazaar_lookup": "malwarebazaar",
    "urlhaus_lookup": "urlhaus",
    "alienvault_otx_lookup": "alienvault_otx",
    "shodan_internetdb_lookup": "shodan_internetdb",
    "abuseipdb_lookup": "abuseipdb",
    "virustotal_lookup": "virustotal",
}

IOC_TYPE_TO_MEMORY_STRATEGY = {
    "ip": "ip_address",
    "md5": "file_hash",
    "sha256": "file_hash",
    "domain": "domain",
    "url": "url",
}

STATIC_FALLBACK_TOOLS = {
    "ip": [
        "abuseipdb_lookup",
        "threatfox_lookup",
        "virustotal_lookup",
    ],
    "domain": [
        "threatfox_lookup",
        "alienvault_otx_lookup",
        "virustotal_lookup",
    ],
    "url": ["urlhaus_lookup", "alienvault_otx_lookup", "threatfox_lookup", "virustotal_lookup"],
    "md5": ["malwarebazaar_lookup", "alienvault_otx_lookup", "virustotal_lookup", "threatfox_lookup"],
    "sha256": ["malwarebazaar_lookup", "alienvault_otx_lookup", "virustotal_lookup", "threatfox_lookup"],
}

DEFAULT_MAX_TOOL_EXECUTION_ROUNDS = 2
DEFAULT_MAX_REFLECTION_ROUNDS = 1
