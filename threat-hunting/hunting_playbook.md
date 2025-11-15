# Threat Hunting Playbook

Comprehensive guide for proactive threat hunting using the Network IDS stack.

---

## 🎯 Hunting Methodology

### **1. Hypothesis-Driven Hunting**

```
Hypothesis → Data Collection → Analysis → Detection/Response
```

### **2. Intel-Driven Hunting**

Based on threat intelligence feeds and IOCs.

### **3. Baseline Anomaly Detection**

Identify deviations from normal network behavior.

---

## 📊 Use Cases

### **UC-001: DNS C2 Communication Detection**

**MITRE ATT&CK:** T1071.004 (Application Layer Protocol: DNS)

**Hypothesis:** Attackers are using DNS for command and control communication.

**Data Sources:**
- Zeek DNS logs (`zeek.dns`)
- Suricata DNS events

**KQL Hunting Query:**
```kql
event.dataset:zeek.dns AND zeek.dns.qtype_name:TXT
AND zeek.dns.query:(*[0-9]{10,}* OR *==* OR *[A-Za-z0-9+/]{20,}*)
| stats count() by source.ip, zeek.dns.query
| where count() > 5
```

**Indicators:**
- TXT record queries with base64/hex patterns
- Long query strings (>50 characters)
- High entropy subdomains
- Unusual query frequency

**Validation:**
```bash
# Check specific source IP
curl -u elastic:changeme "http://localhost:9200/zeek-*/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "query": {
    "bool": {
      "must": [
        {"term": {"source.ip": "10.0.0.50"}},
        {"term": {"zeek.dns.qtype_name": "TXT"}}
      ]
    }
  },
  "size": 100
}'
```

**Response Actions:**
1. Isolate affected host
2. Capture PCAP for IOC extraction
3. Block malicious domain
4. Hunt for other infected hosts

---

### **UC-002: SMB Lateral Movement**

**MITRE ATT&CK:** T1021.002 (SMB/Windows Admin Shares)

**Hypothesis:** Attacker has gained initial access and is moving laterally via SMB.

**Data Sources:**
- Zeek SMB logs (`zeek.smb`)
- Suricata SMB events
- Custom lateral movement alerts

**KQL Hunting Query:**
```kql
event.dataset:zeek.smb AND zeek.smb.action:("open" OR "tree_connect")
AND zeek.smb.path:(*ADMIN$* OR *C$* OR *IPC$*)
| stats dc(destination.ip) by source.ip, user.name
| where dc(destination.ip) > 3
```

**Indicators:**
- Single source accessing multiple destinations
- Administrative share access (ADMIN$, C$, IPC$)
- PSExec-like activity
- Off-hours activity

**Timeline Analysis:**
```kql
event.dataset:zeek.smb AND source.ip:"10.0.0.100"
| sort @timestamp
| table @timestamp, source.ip, destination.ip, zeek.smb.action, zeek.smb.path
```

**Pivot Points:**
1. Check RDP connections from same source
2. Review authentication logs
3. Analyze process execution (if host telemetry available)

---

### **UC-003: Port Scanning Reconnaissance**

**MITRE ATT&CK:** T1046 (Network Service Scanning)

**Hypothesis:** Attacker is performing network reconnaissance before exploitation.

**Data Sources:**
- Zeek connection logs (`zeek.conn`)
- Suricata port scan alerts
- Custom port scan detection

**KQL Hunting Query:**
```kql
event.dataset:zeek.conn AND zeek.conn.state:("S0" OR "REJ" OR "RSTO")
| stats dc(destination.port) by source.ip
| where dc(destination.port) > 20
```

**Horizontal Scan Detection:**
```kql
event.dataset:zeek.conn
| stats dc(destination.ip) by source.ip, destination.port
| where dc(destination.ip) > 10
```

**Indicators:**
- Many failed connections (S0, REJ)
- Sequential port access
- Uncommon source ports
- Short connection duration

**Correlation:**
```kql
# Check if scan led to exploitation
event.dataset:suricata AND alert.signature:*exploit*
AND source.ip IN (
  /* IPs that performed scanning */
)
```

---

### **UC-004: TLS Certificate Anomalies**

**MITRE ATT&CK:** T1573.002 (Encrypted Channel: Asymmetric Cryptography)

**Hypothesis:** Malware is using suspicious TLS certificates for C2 communication.

**Data Sources:**
- Zeek SSL/TLS logs (`zeek.ssl`)
- Custom TLS anomaly detection

**KQL Hunting Query:**
```kql
event.dataset:zeek.ssl
AND (zeek.ssl.validation_status:(* AND NOT "ok")
     OR zeek.ssl.subject:zeek.ssl.issuer)
| table source.ip, destination.ip, zeek.ssl.subject, zeek.ssl.issuer, zeek.ssl.validation_status
```

**Self-Signed Certificate Hunt:**
```kql
event.dataset:zeek.ssl
AND zeek.ssl.subject:*
| where zeek.ssl.subject == zeek.ssl.issuer
| stats count() by destination.ip, zeek.ssl.subject
```

**Short-Lived Certificates:**
```kql
event.dataset:zeek.ssl
| where zeek.ssl.certificate.not_valid_after - zeek.ssl.certificate.not_valid_before < 604800
| table destination.ip, zeek.ssl.subject
```

---

### **UC-005: Beaconing Pattern Detection**

**MITRE ATT&CK:** T1071 (Application Layer Protocol)

**Hypothesis:** Compromised host is beaconing to C2 server at regular intervals.

**Data Sources:**
- Zeek connection logs
- Custom C2 beaconing detection
- Flow data

**KQL Hunting Query:**
```kql
event.dataset:zeek.conn
| stats count() by source.ip, destination.ip, destination.port
| where count() > 10
```

**Statistical Analysis:**
```python
# Analyze connection intervals (requires exported data)
import pandas as pd
import numpy as np

# Load connections from Elasticsearch
df = load_connections(source_ip="10.0.0.50")

# Calculate intervals
df['interval'] = df['timestamp'].diff()

# Check for low variance (beaconing indicator)
cv = df['interval'].std() / df['interval'].mean()

if cv < 0.3:  # Coefficient of variation < 30%
    print(f"Potential beaconing detected! CV: {cv}")
```

**Kibana Visualization:**
```
Visualization Type: Line Chart
X-Axis: @timestamp (histogram)
Y-Axis: Count of connections
Split Series: destination.ip
```

---

## 🔍 Advanced Hunting Techniques

### **Stacking / Frequency Analysis**

Find rare occurrences:

```kql
# Rare user agents
event.dataset:http
| stats count() by user_agent.original
| sort count()
| head 20
```

```kql
# Rare destination ports
event.dataset:zeek.conn
| stats count() by destination.port
| where count() < 5 AND destination.port > 1024
```

### **Time-Based Anomalies**

```kql
# After-hours activity
event.dataset:zeek.conn AND @timestamp:[00:00 TO 06:00]
AND destination.port:(445 OR 3389)
| stats count() by source.ip
```

### **Geo-IP Anomalies**

```kql
# Connections to high-risk countries
event.dataset:zeek.conn
AND destination.geo.country_iso_code:(RU OR CN OR KP OR IR)
| table source.ip, destination.ip, destination.geo.country_name
```

---

## 📝 Hunting Workflow

### **Phase 1: Preparation** (15 min)

1. Define hypothesis
2. Identify required data sources
3. Build initial queries
4. Set up Kibana dashboards

### **Phase 2: Hunting** (2-4 hours)

1. Execute queries
2. Analyze results
3. Pivot to related data
4. Document findings

### **Phase 3: Validation** (30 min)

1. Confirm true positives
2. Eliminate false positives
3. Extract IOCs

### **Phase 4: Response** (Varies)

1. Containment
2. Eradication
3. Recovery
4. Lessons learned

---

## 🎨 Kibana Dashboard Setup

### **Create Hunting Dashboard**

1. Navigate to Kibana > Dashboard
2. Create New Dashboard
3. Add visualizations:

**Visualization 1: Top Talkers**
```
Type: Data Table
Index: zeek-*
Metrics: Count
Buckets: Terms aggregation on source.ip
```

**Visualization 2: Protocol Distribution**
```
Type: Pie Chart
Index: zeek-*
Metrics: Count
Buckets: Terms aggregation on network.protocol
```

**Visualization 3: Alert Timeline**
```
Type: Area Chart
Index: suricata-*
Metrics: Count
Buckets: Date Histogram on @timestamp
Split Series: alert.signature
```

---

## 📚 IOC Management

### **Extract IOCs from Findings**

```bash
# Export malicious IPs
curl -u elastic:changeme "http://localhost:9200/zeek-*/_search" -H 'Content-Type: application/json' -d'
{
  "query": {"match": {"notice.note": "DNS_Tunneling_Detected"}},
  "_source": ["source.ip"],
  "size": 1000
}' | jq -r '.hits.hits[]._source.source.ip' | sort -u > malicious_ips.txt

# Export malicious domains
curl -u elastic:changeme "http://localhost:9200/zeek-*/_search" -H 'Content-Type: application/json' -d'
{
  "query": {"match": {"notice.note": "DNS_Tunneling_Detected"}},
  "_source": ["zeek.dns.query"],
  "size": 1000
}' | jq -r '.hits.hits[]._source.zeek.dns.query' | sort -u > malicious_domains.txt
```

### **Feed IOCs Back to Detection**

Update Zeek intel framework:
```bash
# Format: indicator<TAB>indicator_type<TAB>meta.source
cat malicious_ips.txt | awk '{print $1 "\tIntel::ADDR\tThreat Hunt 2024-11"}' > intel/hunting_iocs.txt
```

---

## ✅ Hunting Checklist

- [ ] Define clear hypothesis
- [ ] Identify MITRE ATT&CK techniques
- [ ] Build 3-5 KQL queries
- [ ] Execute queries in Kibana
- [ ] Document at least 5 findings
- [ ] Validate findings (eliminate FPs)
- [ ] Extract IOCs
- [ ] Create detection rules for recurring patterns
- [ ] Update intel feeds
- [ ] Report findings to team

---

## 📊 Reporting Template

```markdown
# Threat Hunt Report: [Name]

**Date:** YYYY-MM-DD
**Hunter:** [Name]
**Duration:** X hours

## Hypothesis
[Describe what you were looking for]

## Methodology
[KQL queries, tools used]

## Findings
- True Positives: X
- False Positives: X
- IOCs Extracted: X

## Key Discoveries
1. [Finding 1]
2. [Finding 2]

## Recommendations
1. [Recommendation 1]
2. [Recommendation 2]

## IOCs
- IPs: [list]
- Domains: [list]
- File Hashes: [list]
```

---

**Next Steps:** See individual use case files:
- [use_case_1_smb_recon.md](use_case_1_smb_recon.md)
- [use_case_2_dns_c2.md](use_case_2_dns_c2.md)
- [use_case_3_port_scanning.md](use_case_3_port_scanning.md)
- [use_case_4_tls_anomalies.md](use_case_4_tls_anomalies.md)
- [use_case_5_lateral_movement.md](use_case_5_lateral_movement.md)
