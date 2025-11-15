# Performance Baseline Metrics

Expected performance characteristics for different deployment sizes and workload profiles.

---

## 📊 Deployment Size Profiles

### Small Deployment (Development/Lab)

**Target Environment:**
- Small office (<50 devices)
- Lab/testing environment
- Development workstation
- Low traffic volume (<10 Mbps)

**Hardware Requirements:**
- **CPU:** 4 cores (2.0 GHz+)
- **RAM:** 8GB minimum, 12GB recommended
- **Storage:** 50GB SSD
- **Network:** 1 Gbps NIC

**Expected Performance:**

| Metric | Baseline | Peak |
|--------|----------|------|
| Packet Rate | 5,000-15,000 pps | 25,000 pps |
| Network Throughput | 5-10 Mbps | 50 Mbps |
| Connections/Second | 50-100 | 500 |
| Alerts/Hour | 10-50 | 200 |
| CPU Usage | 20-35% | 60% |
| Memory Usage | 6-8GB | 10GB |
| Disk I/O | 10-20 MB/s | 50 MB/s |
| Log Volume | 1-5 GB/day | 10 GB/day |

**Detection Capabilities:**
- ✅ All Zeek scripts enabled
- ✅ Full Suricata rule sets (190+ rules)
- ✅ Real-time alerting
- ⚠️ Limited packet replay at full speed
- ⚠️ Historical analysis limited by storage

---

### Medium Deployment (SMB/Branch Office)

**Target Environment:**
- Medium business (50-250 devices)
- Branch office
- SOC monitoring station
- Medium traffic volume (10-100 Mbps)

**Hardware Requirements:**
- **CPU:** 8 cores (2.5 GHz+)
- **RAM:** 16GB minimum, 32GB recommended
- **Storage:** 200GB SSD
- **Network:** 1 Gbps NIC

**Expected Performance:**

| Metric | Baseline | Peak |
|--------|----------|------|
| Packet Rate | 15,000-50,000 pps | 100,000 pps |
| Network Throughput | 10-100 Mbps | 500 Mbps |
| Connections/Second | 100-500 | 2,000 |
| Alerts/Hour | 50-200 | 1,000 |
| CPU Usage | 35-55% | 75% |
| Memory Usage | 12-16GB | 24GB |
| Disk I/O | 20-50 MB/s | 150 MB/s |
| Log Volume | 5-20 GB/day | 50 GB/day |

**Detection Capabilities:**
- ✅ All Zeek scripts enabled
- ✅ Full Suricata rule sets
- ✅ Real-time alerting
- ✅ Packet replay at moderate speeds
- ✅ 30-day log retention
- ✅ Threat hunting capabilities

**Recommended Optimizations:**
- Enable Zeek clustering (if >50 Mbps sustained)
- Tune Suricata for multi-core
- Implement log rotation
- Configure ES index lifecycle management

---

### Large Deployment (Enterprise/ISP)

**Target Environment:**
- Enterprise (250+ devices)
- ISP/Cloud provider
- High traffic volume (>100 Mbps)
- 24/7 SOC operations

**Hardware Requirements:**
- **CPU:** 16+ cores (3.0 GHz+)
- **RAM:** 64GB minimum, 128GB recommended
- **Storage:** 1TB+ NVMe SSD
- **Network:** 10 Gbps NIC
- **Clustering:** Multi-node Zeek cluster recommended

**Expected Performance:**

| Metric | Baseline | Peak |
|--------|----------|------|
| Packet Rate | 50,000-200,000 pps | 500,000+ pps |
| Network Throughput | 100-1,000 Mbps | 5 Gbps |
| Connections/Second | 500-2,000 | 10,000 |
| Alerts/Hour | 200-1,000 | 5,000 |
| CPU Usage | 45-65% | 85% |
| Memory Usage | 32-64GB | 96GB |
| Disk I/O | 50-200 MB/s | 500 MB/s |
| Log Volume | 20-100 GB/day | 500 GB/day |

**Detection Capabilities:**
- ✅ All detection capabilities
- ✅ Distributed Zeek cluster
- ✅ Suricata AF_PACKET load balancing
- ✅ Real-time alerting with <5s latency
- ✅ Full packet capture (PCAP on demand)
- ✅ 90+ day log retention
- ✅ Advanced threat hunting
- ✅ Machine learning anomaly detection

**Recommended Architecture:**
```
┌─────────────────┐
│  Load Balancer  │
└────────┬────────┘
         │
    ┌────┴────┬────────┬────────┐
    ▼         ▼        ▼        ▼
┌──────┐  ┌──────┐ ┌──────┐ ┌──────┐
│ Zeek │  │ Zeek │ │ Zeek │ │ Zeek │
│Worker│  │Worker│ │Worker│ │Worker│
└───┬──┘  └───┬──┘ └───┬──┘ └───┬──┘
    │         │        │        │
    └────┬────┴────────┴────────┘
         ▼
  ┌──────────────┐
  │ Elasticsearch│
  │   Cluster    │
  │  (3+ nodes)  │
  └──────────────┘
```

---

## 🔬 Workload Profiles

### Profile 1: Normal Business Traffic

**Characteristics:**
- HTTP/HTTPS web browsing (60%)
- Email (SMTP/IMAP) (15%)
- DNS queries (10%)
- Cloud services (O365, AWS) (10%)
- Internal file shares (SMB) (5%)

**Expected Detection Volume:**
- **False Positive Rate:** 3-5% (tunable to <2%)
- **Alerts per Day:** 50-200
- **Critical Alerts:** 1-5 per day
- **DNS Tunneling Alerts:** <5 per day (mostly FP)
- **Port Scan Alerts:** 5-20 per day
- **TLS Anomalies:** 10-30 per day (self-signed certs)

**Tuning Recommendations:**
- Whitelist internal services
- Tune DNS entropy thresholds
- Suppress known TLS warnings for internal apps
- Adjust port scan sensitivity

---

### Profile 2: Development Environment

**Characteristics:**
- GitHub/GitLab traffic (30%)
- Cloud API calls (AWS, Azure, GCP) (25%)
- Container registry pulls (20%)
- Database connections (PostgreSQL, MySQL) (15%)
- SSH connections (10%)

**Expected Detection Volume:**
- **False Positive Rate:** 8-12% (high FP due to dev tools)
- **Alerts per Day:** 100-500
- **Critical Alerts:** 2-10 per day
- **DNS Tunneling Alerts:** 20-50 per day (ngrok, tunneling tools)
- **Lateral Movement Alerts:** 10-30 per day (internal SSH)
- **Port Scan Alerts:** 50-100 per day (vulnerability scanners)

**Tuning Recommendations:**
- Whitelist CI/CD IPs
- Exclude development subnets from certain rules
- Adjust lateral movement thresholds
- Suppress alerts for known security tools

---

### Profile 3: High-Threat Environment

**Characteristics:**
- Frequent external attacks
- Active threat hunting
- Penetration testing
- Red team exercises

**Expected Detection Volume:**
- **False Positive Rate:** 2-3% (highly tuned)
- **Alerts per Day:** 500-2,000
- **Critical Alerts:** 10-50 per day
- **Malware Detections:** 5-20 per day
- **C2 Beaconing:** 3-10 per day
- **Lateral Movement:** 5-15 per day

**Tuning Recommendations:**
- Enable all detection scripts
- Use strict thresholds
- Enable advanced correlation
- Implement threat intel feeds

---

## 📈 Performance Benchmarks by Traffic Type

### DNS Traffic

| Metric | Light (<1,000 qps) | Medium (1,000-10,000 qps) | Heavy (>10,000 qps) |
|--------|-------------------|---------------------------|---------------------|
| CPU Impact | <5% | 10-20% | 30-50% |
| Memory Impact | 500MB | 1-2GB | 3-5GB |
| Tunneling Alerts | 0-5/day | 5-20/day | 20-100/day |
| Processing Latency | <1ms | 1-5ms | 5-15ms |

**Optimization:**
- Light: All scripts enabled
- Medium: Tune entropy threshold (3.5 → 4.0)
- Heavy: Consider external DNS analytics tool

---

### HTTP/HTTPS Traffic

| Metric | Light (<100 req/s) | Medium (100-1,000 req/s) | Heavy (>1,000 req/s) |
|--------|-------------------|--------------------------|----------------------|
| CPU Impact | <10% | 20-35% | 45-65% |
| Memory Impact | 1GB | 2-4GB | 5-8GB |
| TLS Alerts | 5-20/day | 20-100/day | 100-500/day |
| Processing Latency | <5ms | 5-20ms | 20-50ms |

**Optimization:**
- Light: Full TLS inspection
- Medium: Reduce cipher suite checks
- Heavy: Sample traffic (1:10 ratio)

---

### Port Scanning Traffic

| Scan Type | Detection Rate | False Positive Rate | Avg Detection Time |
|-----------|----------------|---------------------|-------------------|
| **TCP SYN Scan** | >99% | <1% | <10 seconds |
| **TCP Connect** | >99% | <1% | <10 seconds |
| **UDP Scan** | >95% | <5% | <30 seconds |
| **FIN/NULL/Xmas** | >98% | <2% | <15 seconds |
| **Slow Scan** (>5 min) | 85-90% | <3% | Delayed (>5 min) |

**Tuning by Environment:**
- **DMZ:** Aggressive (threshold: 10 ports/60s)
- **Internal:** Moderate (threshold: 25 ports/60s)
- **Development:** Relaxed (threshold: 50 ports/120s)

---

## 🎯 Baseline Collection Methodology

### Data Collection Period

**Minimum Duration:** 72 hours (3 days)
**Recommended Duration:** 7-14 days
**Ideal Duration:** 30 days (captures monthly patterns)

**Include in Baseline:**
- ✅ Full business week (Mon-Fri)
- ✅ Weekend traffic patterns
- ✅ Peak usage hours
- ✅ Maintenance windows
- ❌ Exclude: Unusual events, outages, tests

### Metrics to Capture

**System Metrics (every 5 minutes):**
```bash
# CPU usage per container
docker stats --no-stream --format "{{.Name}},{{.CPUPerc}},{{.MemUsage}}"

# Disk I/O
iostat -x 300

# Network throughput
iftop -t -s 300
```

**Detection Metrics (every hour):**
```bash
# Alert volume
curl -u elastic:changeme "http://localhost:9200/suricata-*/_count"

# Detection types
curl -u elastic:changeme "http://localhost:9200/suricata-*/_search" \
  -d '{"size":0,"aggs":{"categories":{"terms":{"field":"alert.category.keyword"}}}}'

# False positive tracking
# (Manual review + tagging required)
```

**Traffic Metrics (continuous):**
```bash
# Zeek connection stats
docker-compose exec zeek zeekctl netstats

# Suricata packet stats
docker-compose exec suricata tail -f /var/log/suricata/stats.log
```

---

## 📊 Baseline Analysis

### Statistical Summary

**Calculate for each metric:**
- **Mean:** Average value
- **Median:** 50th percentile
- **P95:** 95th percentile (peak loads)
- **P99:** 99th percentile (extreme peaks)
- **Min/Max:** Range
- **Standard Deviation:** Variability

**Example Analysis:**
```
CPU Usage (Zeek container):
  Mean: 45%
  Median: 42%
  P95: 68%
  P99: 75%
  StdDev: 12%

Interpretation:
  - Normal load: 40-50%
  - Peak load: 65-70%
  - Alert threshold: >80% for 5+ minutes
```

### Anomaly Detection Thresholds

**Set based on baseline:**
```
Alert Threshold = Median + (3 × StdDev)

Example:
  Median CPU = 42%
  StdDev = 12%
  Alert Threshold = 42 + (3 × 12) = 78%
```

**Progressive Alerting:**
- **Warning:** P95 exceeded
- **Critical:** P99 exceeded
- **Emergency:** Sustained >P99 for 10+ minutes

---

## 🔍 Baseline Validation

### Validation Checklist

- [ ] **Traffic Diversity:** Captured all major protocols
- [ ] **Time Coverage:** Full business cycle included
- [ ] **Load Variation:** Peak and off-peak hours represented
- [ ] **Anomaly Exclusion:** Removed unusual events
- [ ] **Statistical Validity:** Sufficient sample size (>1000 data points)
- [ ] **Documentation:** Baseline conditions documented
- [ ] **Reproducibility:** Baseline can be recreated

### Red Flags (Invalid Baseline)

⚠️ **Discard baseline if:**
- Collected during system changes/migrations
- Major outage occurred during collection
- Security incident in progress
- Insufficient data points (<24 hours)
- Extreme variance (CV >50%)
- Known anomalous conditions

---

## 📅 Baseline Maintenance

### Update Schedule

- **Minor Update:** Quarterly (every 3 months)
- **Major Update:** Annually or after significant changes
- **Emergency Update:** After infrastructure changes

**Triggers for Emergency Update:**
- Network architecture changes
- Significant user count changes (+/- 20%)
- New major applications deployed
- Detection rule changes (>50 rules modified)
- Hardware/resource changes

### Version Control

```bash
# Baseline naming convention
baseline_YYYYMMDD_duration_environment.json

# Examples
baseline_20241115_7d_production.json
baseline_20241115_14d_development.json
baseline_20241115_30d_enterprise.json
```

**Include in baseline file:**
- Collection start/end dates
- Environment details (CPU, RAM, network)
- Software versions (Zeek, Suricata, ES)
- Network topology
- Statistical summary
- Raw metrics data

---

## 🎓 Best Practices

### Do's ✅

- Collect baselines before implementing detections
- Update baselines after tuning rules
- Document baseline collection conditions
- Version control baseline files
- Compare performance against baseline regularly
- Set alerts based on baseline + thresholds

### Don'ts ❌

- Don't use baselines from different environments
- Don't collect baselines during incidents
- Don't ignore baseline drift over time
- Don't set static thresholds without baseline
- Don't skip validation steps

---

**Last Updated:** 2024-11-15
**Version:** 1.1.0
**Baseline Collection:** Recommended before production deployment
