# DFIR AI Agent - Threat Intelligence API Summary
Generated: 2026-03-02 15:12:09

## MalwareBazaar (malwarebazaar)
- **Provider**: abuse.ch
- **Endpoint**: https://mb-api.abuse.ch/api/v1/
- **Auth**: header via `Auth-Key`
- **Rate Limit**: none_specified
- **Cost**: free
- **Best For**: file_hash, malware_sample_metadata
- **Reliability Score**: 90.00%
- **Avg Response Time**: 1.2s
- **Learned Success Rate**: 82.50%
- **Typical Response Time**: 2.03s

## ThreatFox (threatfox)
- **Provider**: abuse.ch
- **Endpoint**: https://threatfox-api.abuse.ch/api/v1/
- **Auth**: header via `Auth-Key`
- **Rate Limit**: unlimited
- **Cost**: free
- **Best For**: ip_address, domain, url, file_hash, network_iocs
- **Reliability Score**: 85.00%
- **Avg Response Time**: 1.5s
- **Learned Success Rate**: 78.40%
- **Typical Response Time**: 2.59s

## URLhaus (urlhaus)
- **Provider**: abuse.ch
- **Endpoint**: https://urlhaus-api.abuse.ch/
- **Auth**: uri_parameter via `auth-key`
- **Rate Limit**: 5_minutes
- **Cost**: free
- **Best For**: url_reputation, domain_reputation, malware_distribution
- **Reliability Score**: 88.00%
- **Avg Response Time**: 2.0s
- **Learned Success Rate**: 70.00%
- **Typical Response Time**: 2.5s

## AlienVault OTX (alienvault_otx)
- **Provider**: LevelBlue (formerly AlienVault)
- **Endpoint**: https://otx.alienvault.com/api/v1/
- **Auth**: header via `X-OTX-API-KEY`
- **Rate Limit**: not_specified
- **Cost**: free_with_tiers
- **Best For**: multi_source_intel, community_reputation, pulse_associations
- **Reliability Score**: 82.00%
- **Avg Response Time**: 2.2s
- **Learned Success Rate**: 68.00%
- **Typical Response Time**: 3.0s

## GreyNoise (greynoise)
- **Provider**: GreyNoise Intelligence
- **Endpoint**: https://api.greynoise.io
- **Auth**: header via `key`
- **Rate Limit**: subscription_dependent
- **Cost**: paid
- **Best For**: ip_classification, benign_scanner_detection, noise_filtering
- **Reliability Score**: 92.00%
- **Avg Response Time**: 0.8s
- **Learned Success Rate**: 91.00%
- **Typical Response Time**: 1.21s

## VirusTotal (virustotal)
- **Provider**: Google (Chronicle Security)
- **Endpoint**: https://www.virustotal.com/api/v3/
- **Auth**: header via `x-apikey`
- **Rate Limit**: 4_per_minute
- **Cost**: freemium
- **Best For**: multi_av_scan, file_reputation, url_scan, comprehensive_analysis
- **Reliability Score**: 95.00%
- **Avg Response Time**: 2.5s
- **Learned Success Rate**: 88.00%
- **Typical Response Time**: 3.0s

