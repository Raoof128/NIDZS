# Threat Hunting Resources

Comprehensive threat hunting playbooks, KQL queries, and methodologies for proactive threat detection using the Network IDS.

---

## 📚 Available Resources

| Resource | Description | Difficulty |
|----------|-------------|------------|
| [Hunting Playbook](hunting_playbook.md) | 5 documented hunting use cases | ⭐⭐ Intermediate |
| [KQL Query Library](kql_queries.md) | 50+ pre-built KQL queries | ⭐⭐ Intermediate |

---

## 🎯 Hunting Methodology

### **Intelligence-Driven Hunting**

**Process:**
1. **Hypothesis Formation** → Define what you're looking for
2. **Data Collection** → Query relevant data sources
3. **Analysis** → Identify patterns and anomalies
4. **Validation** → Confirm findings (reduce false positives)
5. **Documentation** → Record findings and IOCs
6. **Response** → Escalate or remediate

### **The Hunting Loop**

```
┌─────────────────────────────────────┐
│   1. Develop Hypothesis             │
│   "Are there DNS C2 channels?"      │
└───────────┬─────────────────────────┘
            │
┌───────────▼─────────────────────────┐
│   2. Collect Data (KQL Queries)     │
│   event.dataset:zeek.dns AND ...    │
└───────────┬─────────────────────────┘
            │
┌───────────▼─────────────────────────┐
│   3. Analyze Results                │
│   High entropy? TXT records?        │
└───────────┬─────────────────────────┘
            │
┌───────────▼─────────────────────────┐
│   4. Validate Findings              │
│   Context check, false positive?    │
└───────────┬─────────────────────────┘
            │
┌───────────▼─────────────────────────┐
│   5. Create Detection Rules         │
│   Automate future detection         │
└─────────────────────────────────────┘
```

---

## 🔍 Use Cases Overview

### **UC-001: DNS C2 Communication Detection**
**MITRE ATT&CK:** T1071.004 (Application Layer Protocol: DNS)

**Hypothesis:** Attackers are using DNS for C2 communication or data exfiltration

**Indicators:**
- Long DNS query names (>50 characters)
- High entropy subdomain patterns
- Unusual TXT record queries
- High volume of queries to single domain
- Base64/hex encoding patterns in queries

**KQL Query:**
```kql
event.dataset:zeek.dns AND zeek.dns.qtype_name:TXT
AND zeek.dns.query:(*[0-9]{10,}* OR *==* OR *[A-Za-z0-9+/]{20,}*)
| stats count() by source.ip, zeek.dns.query
| where count() > 5
```

**📖 Full Playbook:** [hunting_playbook.md](hunting_playbook.md#uc-001-dns-c2-communication-detection)

---

### **UC-002: Lateral Movement Detection**
**MITRE ATT&CK:** T1021.001 (RDP), T1021.002 (SMB)

**Hypothesis:** Attackers are moving laterally across internal systems

**Indicators:**
- Multiple RDP/SMB connections from single source
- Connections to multiple destinations in short timeframe
- Unusual credential usage patterns
- Admin share access (\\C$, \\ADMIN$)
- Failed authentication attempts followed by success

**KQL Query:**
```kql
event.dataset:(zeek.rdp OR zeek.smb)
| stats dc(destination.ip) by source.ip, user.name
| where dc(destination.ip) > 5
```

**📖 Full Playbook:** [hunting_playbook.md](hunting_playbook.md#uc-002-lateral-movement-detection)

---

### **UC-003: Port Scanning Detection**
**MITRE ATT&CK:** T1046 (Network Service Scanning)

**Hypothesis:** Reconnaissance activity is occurring on the network

**Indicators:**
- High number of unique ports accessed by single source
- Short-lived connections (connection attempts without data transfer)
- Sequential or random port access patterns
- Connections to common vulnerability scanning ports

**KQL Query:**
```kql
event.dataset:zeek.conn
| stats dc(destination.port) as unique_ports by source.ip
| where unique_ports > 50
```

**📖 Full Playbook:** [hunting_playbook.md](hunting_playbook.md#uc-003-port-scanning-detection)

---

### **UC-004: TLS/SSL Anomalies**
**MITRE ATT&CK:** T1573.002 (Encrypted Channel)

**Hypothesis:** Malicious encrypted communications are present

**Indicators:**
- Self-signed certificates
- Expired certificates
- Certificate validation failures
- Weak/deprecated cipher suites
- JA3 hash mismatches

**KQL Query:**
```kql
event.dataset:zeek.ssl
AND zeek.ssl.validation_status:("self signed certificate" OR "unable to verify")
| stats count() by destination.ip, zeek.ssl.server_name
```

**📖 Full Playbook:** [hunting_playbook.md](hunting_playbook.md#uc-004-tls-ssl-anomaly-detection)

---

### **UC-005: C2 Beaconing Detection**
**MITRE ATT&CK:** T1071 (Application Layer Protocol)

**Hypothesis:** Compromised systems are beaconing to C2 infrastructure

**Indicators:**
- Periodic connections with consistent intervals
- Similar payload sizes across connections
- Connections to unusual external IPs
- Low jitter in connection timing

**KQL Query:**
```kql
event.dataset:zeek.conn
AND NOT destination.ip:(10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16)
| stats count() by source.ip, destination.ip, destination.port
| where count() > 20
```

**📖 Full Playbook:** [hunting_playbook.md](hunting_playbook.md#uc-005-c2-beaconing-detection)

---

## 🎓 Hunting Techniques

### **Hypothesis-Driven Hunting**

Start with a specific threat hypothesis based on intelligence or threat modeling.

**Example:**
- **Hypothesis:** "Attackers are using DNS tunneling for data exfiltration"
- **Data Source:** Zeek DNS logs
- **Query:** Search for long queries, high entropy, unusual patterns
- **Validation:** Check baseline, context, user behavior
- **Outcome:** Confirm/deny hypothesis, create detection rule

### **Baseline Anomaly Hunting**

Compare current behavior against established baselines.

**Steps:**
1. **Establish Baseline** (7-30 days of normal traffic)
2. **Define Normal Ranges** (statistical analysis)
3. **Hunt for Deviations** (outliers, anomalies)
4. **Investigate Outliers** (true positive vs false positive)

**Example Baseline:**
```kql
# Establish baseline: Average DNS queries per host
event.dataset:zeek.dns
| stats count() by source.ip
| stats avg(count()) as baseline_avg, stdev(count()) as baseline_stdev

# Hunt for anomalies: Hosts exceeding 3 standard deviations
| where count() > baseline_avg + (3 * baseline_stdev)
```

### **IOC-Based Hunting**

Search for known Indicators of Compromise from threat intelligence.

**IOC Types:**
- IP addresses (C2 servers, malicious hosts)
- Domain names (phishing, malware distribution)
- File hashes (malware samples)
- User-agent strings (malware variants)
- JA3 fingerprints (TLS patterns)

**Example:**
```kql
# Hunt for known malicious IPs
event.dataset:zeek.conn
AND destination.ip:("203.0.113.5" OR "198.51.100.42" OR "192.0.2.100")
```

### **Clustering and Grouping**

Group similar events to identify patterns.

**Techniques:**
- **Group by source IP:** Identify compromised hosts
- **Group by destination:** Identify common targets
- **Group by time:** Identify campaign windows
- **Group by behavior:** Identify attack patterns

**Example:**
```kql
event.dataset:zeek.conn
| stats count(), dc(destination.ip) as unique_dests, dc(destination.port) as unique_ports
    by source.ip
| where unique_dests > 10 AND unique_ports > 20
```

---

## 📊 Hunting Metrics

### **Effectiveness Metrics**

| Metric | Calculation | Target |
|--------|-------------|--------|
| **True Positive Rate** | True Positives / (TP + False Negatives) | >90% |
| **False Positive Rate** | False Positives / (FP + True Negatives) | <10% |
| **Hunt Success Rate** | Hunts with Findings / Total Hunts | >40% |
| **Time to Detection** | Detection Time - Attack Start | <24 hours |
| **Coverage** | Hunted Techniques / Total Techniques | >80% |

### **Operational Metrics**

- **Hunts per Week:** Target 5-10 hunts
- **Average Hunt Duration:** 30-60 minutes per hunt
- **Documentation Rate:** 100% of findings documented
- **Automation Rate:** 50%+ of successful hunts converted to detections

---

## 🛠️ Tools and Techniques

### **Kibana Discover**

Primary interface for threat hunting in this IDS.

**Best Practices:**
- Use time range filters to scope searches
- Save useful queries for reuse
- Create visualizations for pattern analysis
- Export findings to CSV for reporting

**Useful Filters:**
```kql
# Filter by event type
event.dataset:(zeek.conn OR zeek.dns OR zeek.http)

# Filter by severity
event.severity:(high OR critical)

# Filter by external traffic only
NOT destination.ip:(10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16)

# Time-based filters
@timestamp:[now-24h TO now]
```

### **Aggregations and Statistics**

Use Kibana aggregations for pattern detection.

**Examples:**
```kql
# Count events by source IP
| stats count() by source.ip

# Multiple aggregations
| stats count(), avg(bytes), sum(packets) by source.ip, destination.ip

# Rare item analysis
| rare source.ip by destination.ip

# Distinct count
| stats dc(destination.port) by source.ip
```

### **Correlation Across Data Sources**

Combine multiple event types for comprehensive analysis.

**Example: Multi-Stage Attack Detection**
```kql
# Stage 1: Port scan
event.dataset:zeek.notice AND zeek.notice.note:"Scan::Port_Scan"
| fields source.ip

# Stage 2: Follow-up connections from scanners
event.dataset:zeek.conn
AND source.ip:(RESULTS_FROM_STAGE_1)
AND @timestamp > [port_scan_timestamp]
```

---

## 📋 Hunting Workflow

### **Daily Hunting Routine** (30 minutes)

1. **Review New Alerts** (10 min)
   - Check Threat Detection Dashboard
   - Triage high-severity alerts
   - Note patterns or trends

2. **Quick Hunt** (15 min)
   - Run 2-3 quick KQL queries from library
   - Check for known IOCs
   - Review anomalies in baselines

3. **Documentation** (5 min)
   - Log findings (even if negative)
   - Update hunt journal
   - Share notable findings with team

### **Weekly Deep Dive** (2-4 hours)

1. **Threat Intel Review** (30 min)
   - Review latest threat reports
   - Update IOC lists
   - Identify new hunting hypotheses

2. **Focused Hunt** (60-90 min)
   - Execute full hunting use case
   - Investigate findings thoroughly
   - Validate and document

3. **Rule Development** (30-60 min)
   - Create detection rules from findings
   - Test rules for false positives
   - Deploy and monitor

4. **Reporting** (30 min)
   - Summarize week's hunts
   - Share findings and metrics
   - Plan next week's focus

---

## 📝 Documentation Templates

### **Hunt Log Template**

```markdown
# Hunt: [Hunt Name]
**Date:** 2024-11-15
**Hunter:** [Your Name]
**Duration:** 45 minutes

## Hypothesis
[What you're looking for]

## Data Sources
- event.dataset:zeek.dns
- event.dataset:zeek.conn

## Queries Executed
```kql
[Your KQL queries]
```

## Findings
- **True Positives:** 2
- **False Positives:** 5
- **Suspicious Events:** 3

## Notable Observations
[Interesting patterns, anomalies, or concerns]

## Actions Taken
- [ ] Created ticket: SECURITY-1234
- [ ] Updated detection rule
- [ ] Added to IOC list
- [ ] Escalated to IR team

## Lessons Learned
[What worked well, what to improve]
```

---

## 🎯 Best Practices

### Do's ✅

- **Document everything** - Even negative results are valuable
- **Start with hypothesis** - Focused hunting is more effective
- **Validate findings** - Always check context and baselines
- **Automate successful hunts** - Convert to detection rules
- **Share findings** - Collaborate with team
- **Use time ranges** - Scope your searches appropriately
- **Iterate and refine** - Improve queries based on results

### Don'ts ❌

- **Don't hunt without direction** - Random searching wastes time
- **Don't ignore false positives** - Tune them out or update rules
- **Don't hunt alone** - Collaborate for better coverage
- **Don't skip documentation** - Future you will thank you
- **Don't over-complicate queries** - Simple often works best
- **Don't forget the baseline** - Know your normal to find abnormal

---

## 📚 Additional Resources

### Documentation
- [Hunting Playbook](hunting_playbook.md) - Detailed use cases with step-by-step instructions
- [KQL Query Library](kql_queries.md) - 50+ pre-built queries organized by category
- [MITRE ATT&CK Framework](https://attack.mitre.org/) - Adversary tactics and techniques
- [Kibana Query Language Guide](https://www.elastic.co/guide/en/kibana/current/kuery-query.html)

### Tools
- [CyberChef](https://gchq.github.io/CyberChef/) - Data transformation and analysis
- [VirusTotal](https://www.virustotal.com/) - IOC enrichment
- [Hybrid Analysis](https://www.hybrid-analysis.com/) - Malware analysis
- [Shodan](https://www.shodan.io/) - Internet-connected device search

### Training
- [SANS FOR508](https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting-training/) - Advanced Threat Hunting
- [Active Countermeasures](https://www.activecountermeasures.com/hunt-training/) - Free threat hunting training
- [Splunk Boss of the SOC](https://www.splunk.com/en_us/blog/conf-splunklive/boss-of-the-soc-scoring-server-questions-and-answers-and-dataset-open-sourced-and-ready-for-download.html) - Practice dataset

---

**Last Updated:** 2024-11-15
**Version:** 1.2.0
**Use Cases:** 5 documented hunting playbooks
**Queries:** 50+ KQL queries available
