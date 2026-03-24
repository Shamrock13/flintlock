# Cashel — Vendor-Specific Checks (Free)

The following checks are included in the free open-source tier. Each finding includes a plain-English remediation recommendation.

| Check | Severity | Vendors |
|---|---|---|
| Any/any permit rules | HIGH | All |
| Missing deny-all rule | HIGH | Cisco (ASA/FTD), Juniper, Palo Alto, pfSense |
| Open ingress to 0.0.0.0/0 | HIGH | AWS, GCP |
| Internet-facing policy missing UTM | HIGH | Fortinet |
| WAN-facing any-source pass rule | HIGH | pfSense |
| Any-application rules | HIGH | Palo Alto |
| Inbound Any rules | HIGH | Azure |
| Default ACCEPT chain policy | HIGH | iptables, nftables |
| Any-any accept rule | HIGH | iptables, nftables |
| Permissive FORWARD chain | HIGH | iptables |
| All-service rules | MEDIUM | Fortinet |
| Default SG with active rules | MEDIUM | AWS |
| Default network in use | MEDIUM | GCP |
| Disabled policies | MEDIUM | Fortinet |
| Insecure services (Telnet/HTTP/FTP) | MEDIUM | Fortinet, Juniper |
| Internet ingress on sensitive ports | MEDIUM | GCP, iptables, nftables |
| Missing description | MEDIUM | GCP, Palo Alto, pfSense |
| Missing logging | MEDIUM | Cisco (ASA/FTD), iptables, Juniper, nftables, Palo Alto |
| No deny-all across zone pairs | MEDIUM | Juniper |
| Overly permissive NSG rules | MEDIUM | Azure |
| Shadowed/duplicate rules | MEDIUM | Cisco (ASA/FTD), Fortinet, Juniper, Palo Alto |
| Telnet management enabled | MEDIUM | Cisco (ASA/FTD), Juniper |
| SNMP community strings | MEDIUM | Juniper |
| Unnamed policies | MEDIUM | Fortinet |
| Unrestricted ICMP permit | MEDIUM | Cisco (ASA/FTD), GCP, iptables, nftables |
| Unrestricted egress | MEDIUM | GCP |
| Wide port range (>100 ports) | MEDIUM | AWS, Azure |
