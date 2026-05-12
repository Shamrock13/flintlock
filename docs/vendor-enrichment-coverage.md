# Vendor Enrichment Coverage

This inventory tracks how current vendor audit findings align with Cashel's finding model. The goal is for supported vendors to produce evidence-backed findings with stable IDs, parser context, and remediation fields while continuing to support legacy finding consumers.

Status terms:

- Fully enriched: current checks use normalized finding dictionaries with stable IDs, vendor, severity, category, title, message, remediation, evidence, affected object or rule name, confidence, verification, and parser context metadata where applicable.
- Partially enriched: current checks use normalized finding dictionaries, but one or more check families still lack parser context, rollback guidance, or complete metadata.
- Legacy dict only: findings are dictionaries with severity, category, message, and remediation, but do not use stable IDs or normalized evidence fields.
- Mixed: the vendor path emits both enriched and legacy dictionary findings.

## Coverage Matrix

| Vendor | Check family | Enrichment status | Missing fields | Recommended next work | Priority |
|---|---|---|---|---|---|
| ASA | Any/any ACL permits, missing logging, duplicate ACL entries, Telnet management/ACL exposure, unrestricted ICMP, ASA shadow checks | Fully enriched | Missing explicit deny-all is intentionally global and has no rule-level evidence; shadow checks do not include rollback guidance. | Keep as current reference pattern; add rollback to ASA shadow findings when touching rule quality again. | Low |
| FTD | Access control policy, threat detection, IPS, SSL inspection, ASA-compatible ACL exposure/logging/duplicates/Telnet/ICMP, FTD shadow checks | Partially enriched | Device posture checks have simple config-presence evidence and limited metadata; FTD shadow checks do not include rollback guidance. | Add richer device posture metadata and rollback text for shadow findings after Fortinet/Palo Alto depth work. | Medium |
| Fortinet | Any/all source-destination permits, missing logging, missing explicit deny-all, duplicate policies, disabled policies, all-service/insecure-service policies, unnamed policies, missing UTM, shadowed policies | Fully enriched | Missing explicit deny-all is global and has no per-policy parser metadata; otherwise current policy-backed findings include stable IDs, evidence, metadata, verification, and rollback. | Continue hardening address/service expansion semantics and add management-plane parsing if FortiGate management checks are introduced. | Low |
| Palo Alto | Any/any rules, missing logging, missing explicit deny-all, duplicate rules, any application, any service, missing security profile, missing description | Fully enriched | Palo Alto shadow checks are enriched but use lighter shadow metadata and no rollback guidance. | Use Palo Alto's own expanded rule context in shadow findings and add rollback guidance. | Medium |
| Juniper SRX | Any/any policies, missing policy logging, insecure applications, missing deny-all, Telnet/SSH/NTP/syslog/SNMP/root-login/screen system checks, Juniper shadow checks | Partially enriched | Policy and system checks are enriched; shadow checks have lighter metadata and no rollback guidance. Some system checks naturally lack rule-level metadata. | Enrich shadow metadata with full zone pair/policy context; keep system checks separate from policy-rule coverage. | Medium |
| pfSense | Any/any rules, missing logging, missing deny-all, duplicate rules, missing description, WAN any-source exposure, pfSense shadow checks | Partially enriched | Core pfSense checks are enriched with UI-oriented remediation guidance; shadow checks have lighter metadata and no rollback guidance. | Add full rule context and rollback guidance to shadow findings; keep procedural remediation style instead of fake CLI commands. | Medium |
| iptables | Default ACCEPT policy, any/any INPUT accepts, internet-exposed sensitive ports, unrestricted FORWARD, missing INPUT logging, unrestricted ICMP | Fully enriched | Current checks include stable IDs, vendor, evidence, affected object/rule name, confidence, verification, rollback, and chain/rule metadata. | Use as the host-firewall reference pattern when converting nftables. | Low |
| nftables | Default accept policy, any/any accepts, internet-exposed sensitive ports, missing logging before accept, unrestricted ICMP | Fully enriched | Current checks include stable IDs, vendor, evidence, affected object/rule name, confidence, verification, rollback, and table/chain/rule metadata. | Use as the nft host-firewall reference pattern when converting remaining cloud firewall checks. | Low |
| AWS Security Groups | Wide-open ingress, unrestricted egress, missing descriptions, default security group ingress, large port ranges | Fully enriched | Current checks include stable IDs, vendor, evidence, affected object/rule name where applicable, confidence, verification, rollback, and security group/rule metadata. | Keep enrichment aligned if new AWS check families are added. | Low |
| Azure NSG | Inbound any-source exposure, missing flow log confirmation, high-priority allow-all, broad port ranges | Mixed | Base Azure checks are legacy dict only; Azure NSG shadow checks are enriched but have lighter metadata and no rollback guidance. | Normalize base Azure checks first, then enrich shadow metadata with priority/direction/source/destination/service context and rollback guidance. | High |
| GCP VPC Firewall | Internet ingress, unrestricted egress, default network rules, missing descriptions, disabled rules, broad target scope, unrestricted ICMP | Legacy dict only | Missing stable ID, vendor, title, evidence, affected object/rule name, confidence, verification, rollback, and metadata. | Convert GCP checks to normalized findings with firewall rule name, network, direction, priority, target tags/service accounts, protocols, ports, ranges, and disabled state metadata. | High |

## Summary

The strongest evidence-backed coverage is currently ASA/FTD, Fortinet, Palo Alto, Juniper SRX, and pfSense. These vendors already emit normalized dictionaries through `make_finding(...)`, though shadow-rule findings still need richer metadata and rollback guidance on several platforms.

The main remaining normalization gap is the cloud group:

- Azure NSG base checks
- GCP VPC Firewall

Those paths still produce legacy dictionaries with the old severity/category/message/remediation shape. They should be converted one vendor at a time, with focused tests that preserve current counts/severities and verify stable IDs, evidence, metadata, legacy string conversion, remediation, JSON/CSV/SARIF exports, and safe samples.
