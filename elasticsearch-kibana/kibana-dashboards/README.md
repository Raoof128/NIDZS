# Kibana Dashboards

Pre-built dashboards for the Network IDS project providing comprehensive visibility into network security events, detections, and threat hunting.

---

## 📊 Available Dashboards

### 1. **Network Overview Dashboard**
**File:** `network_overview.ndjson`

**Purpose:** High-level network traffic statistics and health monitoring

**Visualizations:**
- Total connections over time
- Top talkers (source/destination IPs)
- Protocol distribution (DNS, HTTP, TLS, SMB, RDP)
- Bandwidth usage trends
- Connection state distribution
- Geographic heat map (if GeoIP enabled)

**Use Case:** Daily SOC operations, baseline understanding, capacity planning

---

### 2. **Threat Detection Dashboard**
**File:** `threat_detection.ndjson`

**Purpose:** Centralized view of all security alerts and detections

**Visualizations:**
- Alert timeline (last 24h, 7d, 30d)
- Alert severity distribution
- Top alerting signatures
- MITRE ATT&CK technique coverage
- Alert source breakdown (Zeek vs Suricata)
- False positive rate tracking
- Detection confidence scores

**Use Case:** Incident response, alert triage, detection tuning

---

### 3. **DNS Analysis Dashboard**
**File:** `dns_analysis.ndjson`

**Purpose:** DNS traffic analysis and tunneling detection

**Visualizations:**
- DNS query volume timeline
- Query type distribution (A, AAAA, TXT, MX, CNAME)
- High entropy domain queries (DNS tunneling indicators)
- Long query name alerts
- Suspicious TXT record queries
- Top queried domains
- DNS query flood detection
- Response code distribution (NXDOMAIN, SERVFAIL, etc.)

**Use Case:** DNS tunneling detection, data exfiltration hunting, C2 detection

**MITRE Coverage:** T1071.004 (Application Layer Protocol: DNS)

---

### 4. **C2 Beaconing Dashboard**
**File:** `c2_beaconing.ndjson`

**Purpose:** Command and Control beaconing pattern detection

**Visualizations:**
- Periodic connection patterns (interval analysis)
- Connection interval histogram
- Top beaconing candidates
- Jitter analysis (standard deviation of intervals)
- Payload size consistency analysis
- External connection timeline
- Coefficient of variation distribution

**Use Case:** C2 detection, APT hunting, long-term compromise identification

**MITRE Coverage:** T1071 (Application Layer Protocol), T1573 (Encrypted Channel)

---

### 5. **Lateral Movement Dashboard**
**File:** `lateral_movement.ndjson`

**Purpose:** Detect and visualize lateral movement activities

**Visualizations:**
- RDP connection attempts timeline
- SMB lateral movement patterns
- Internal scanning activity
- Admin share access (\\\\C$, \\\\ADMIN$)
- Failed authentication attempts
- Privilege escalation indicators
- Kerberos anomalies
- Internal network graph (source → destination)

**Use Case:** Insider threat detection, ransomware containment, APT lateral movement

**MITRE Coverage:** T1021.001 (RDP), T1021.002 (SMB/Windows Admin Shares)

---

### 6. **Port Scanning Dashboard**
**File:** `port_scanning.ndjson`

**Purpose:** Network reconnaissance and scanning detection

**Visualizations:**
- Port scan events timeline
- Top scanners (source IPs)
- Top scanned targets
- Port distribution scanned
- Scan technique detection (SYN, FIN, NULL, Xmas)
- Vertical vs horizontal scanning
- Scan velocity metrics

**Use Case:** Reconnaissance detection, attacker profiling, network mapping detection

**MITRE Coverage:** T1046 (Network Service Scanning)

---

### 7. **TLS/SSL Anomaly Dashboard**
**File:** `tls_anomalies.ndjson`

**Purpose:** Detect TLS/SSL certificate and handshake anomalies

**Visualizations:**
- Self-signed certificate detections
- Expired certificate alerts
- Certificate validation failures
- TLS version distribution (deprecated versions)
- Weak cipher suite usage
- Certificate mismatch alerts
- JA3 fingerprint analysis

**Use Case:** Man-in-the-middle detection, malware C2 detection, compliance monitoring

**MITRE Coverage:** T1573.002 (Encrypted Channel: Asymmetric Cryptography)

---

## 🚀 Quick Import

### Method 1: Kibana UI (Recommended)

1. **Access Kibana:**
   ```
   http://localhost:5601
   ```

2. **Navigate to Import:**
   - Click **☰ Menu** → **Stack Management** → **Saved Objects**
   - Click **Import** button (top right)

3. **Import Dashboard:**
   - Drag and drop `.ndjson` file OR click to browse
   - Select the dashboard file (e.g., `threat_detection.ndjson`)
   - Click **Import**
   - If prompted about conflicts, choose **Overwrite** or **Skip**

4. **View Dashboard:**
   - Click **☰ Menu** → **Dashboard**
   - Select your imported dashboard

### Method 2: Automated Script

```bash
# Import all dashboards at once
./import-dashboards.sh

# Import specific dashboard
./import-dashboards.sh network_overview.ndjson
```

### Method 3: cURL API

```bash
# Import single dashboard
curl -X POST "http://localhost:5601/api/saved_objects/_import" \
  -u elastic:changeme \
  -H "kbn-xsrf: true" \
  --form file=@network_overview.ndjson

# Import all dashboards
for dashboard in *.ndjson; do
  curl -X POST "http://localhost:5601/api/saved_objects/_import" \
    -u elastic:changeme \
    -H "kbn-xsrf: true" \
    --form file=@"$dashboard"
  echo "Imported $dashboard"
done
```

---

## 📝 Configuration Notes

### Index Patterns Required

Before importing dashboards, ensure these index patterns exist in Kibana:

1. **`zeek-*`** - For Zeek logs
2. **`suricata-*`** - For Suricata alerts
3. **`filebeat-*`** - For general log shipping

**Create Index Patterns:**
1. **☰ Menu** → **Stack Management** → **Index Patterns**
2. Click **Create index pattern**
3. Enter pattern name (e.g., `zeek-*`)
4. Select timestamp field: `@timestamp`
5. Click **Create index pattern**
6. Repeat for `suricata-*` and `filebeat-*`

### Time Range Settings

All dashboards default to **Last 24 hours**. Adjust as needed:
- Click **🕐 calendar icon** (top right)
- Select: Last 15 minutes, Last 7 days, Last 30 days, etc.
- Or set **Absolute** time range

### Refresh Interval

Enable auto-refresh for real-time monitoring:
- Click **🕐 calendar icon** → **Refresh every**
- Select: 10 seconds, 30 seconds, 1 minute, 5 minutes

---

## 🎨 Customization

### Modify Visualizations

1. Open dashboard
2. Click **Edit** (top right)
3. Click visualization to edit
4. Modify query, aggregations, or appearance
5. **Save** changes

### Add New Visualizations

1. Click **☰ Menu** → **Visualize Library**
2. Click **Create visualization**
3. Select visualization type (Bar, Line, Pie, etc.)
4. Configure data source and aggregations
5. **Save** and add to dashboard

### Clone and Customize

1. Open dashboard
2. Click **•••** → **Clone**
3. Rename (e.g., "Custom Threat Detection")
4. Make modifications
5. **Save**

---

## 🔍 Sample KQL Queries

### High-Severity Alerts Only
```kql
event.severity:high OR event.severity:critical
```

### DNS Tunneling Candidates
```kql
event.dataset:zeek.dns AND
zeek.dns.query_length > 50 AND
zeek.dns.entropy > 3.5
```

### Lateral Movement (RDP)
```kql
event.dataset:zeek.rdp OR
(zeek.service:rdp AND destination.port:3389)
```

### Suspicious TLS Certificates
```kql
zeek.ssl.validation_status:self signed certificate OR
zeek.ssl.validation_status:certificate has expired
```

### Port Scanning Events
```kql
event.module:zeek AND zeek.notice.note:"Scan::Port_Scan"
```

---

## 📈 Performance Optimization

### For Large Datasets (>100GB)

1. **Reduce Time Range:**
   - Use 1-7 day ranges instead of 30+ days
   - Leverage rollup indices for historical analysis

2. **Limit Visualization Count:**
   - Keep 8-10 visualizations per dashboard max
   - Split complex dashboards into multiple focused dashboards

3. **Use Filters:**
   - Filter by specific subnets, IPs, or event types
   - Save filtered views as separate dashboards

4. **Enable Caching:**
   - Elasticsearch query cache helps with repeated queries
   - Dashboard loading times improve significantly

---

## 🐛 Troubleshooting

### Dashboard Import Fails

**Error:** "Index pattern not found"
**Solution:** Create required index patterns first (see Configuration Notes)

**Error:** "Conflict detected"
**Solution:** Choose **Overwrite** to replace existing dashboard

### No Data Showing

**Issue:** Dashboard loads but shows "No results found"

**Solutions:**
1. **Check time range** - Extend to last 7 days
2. **Verify data ingestion:**
   ```bash
   # Check if indices exist
   curl -u elastic:changeme "http://localhost:9200/_cat/indices?v" | grep -E "zeek|suricata"

   # Count documents
   curl -u elastic:changeme "http://localhost:9200/zeek-*/_count"
   ```
3. **Generate test traffic:**
   ```bash
   # Create DNS queries
   dig google.com
   nslookup amazon.com

   # Wait 30-60 seconds for ingestion
   ```

### Slow Dashboard Loading

**Solutions:**
1. Reduce time range (e.g., last 1 hour instead of 7 days)
2. Add filters to limit data scope
3. Increase Elasticsearch heap size in docker-compose.yml:
   ```yaml
   environment:
     - "ES_JAVA_OPTS=-Xms4g -Xmx4g"
   ```

---

## 📚 Additional Resources

- [Kibana Dashboard Documentation](https://www.elastic.co/guide/en/kibana/current/dashboard.html)
- [KQL Query Syntax](https://www.elastic.co/guide/en/kibana/current/kuery-query.html)
- [Visualization Types](https://www.elastic.co/guide/en/kibana/current/dashboard.html#create-panels-with-lens)
- [Threat Hunting Playbook](../../threat-hunting/hunting_playbook.md)
- [KQL Query Library](../../threat-hunting/kql_queries.md)

---

## 🎯 Best Practices

1. **Start Simple:** Import Network Overview dashboard first to verify data flow
2. **Customize for Your Environment:** Adjust thresholds, filters based on your network
3. **Create Baselines:** Use dashboards to understand normal behavior before hunting threats
4. **Regular Reviews:** Check dashboards daily for SOC operations
5. **Alert Integration:** Create alerts from dashboard queries using Kibana alerting
6. **Version Control:** Export modified dashboards and commit to git
7. **Documentation:** Document custom modifications in dashboard descriptions

---

## 🆘 Support

**Issues with dashboards?**
- Check [SETUP.md](../../SETUP.md) for general troubleshooting
- Review [threat-hunting/README.md](../../threat-hunting/README.md) for query examples
- Open GitHub issue: https://github.com/Raoof128/NIDZS/issues

---

**Last Updated:** 2024-11-15
**Version:** 1.1.0
**Dashboards:** 7 pre-built dashboards included
