# Suricata Rules Tuning Guide

This guide helps reduce false positives and optimize detection performance.

---

## 📊 False Positive Reduction Strategy

### **Phase 1: Baseline (Week 1-2)**

1. **Enable All Rules**
   ```bash
   docker-compose up -d suricata
   ```

2. **Collect Metrics**
   ```bash
   # Monitor alert rate
   docker-compose exec suricata tail -f /var/log/suricata/fast.log

   # Query Elasticsearch
   curl -u elastic:changeme "http://localhost:9200/suricata-*/_search?size=0" -H 'Content-Type: application/json' -d'
   {
     "aggs": {
       "by_signature": {
         "terms": {
           "field": "alert.signature.keyword",
           "size": 50
         }
       }
     }
   }'
   ```

3. **Identify Noisy Rules**
   - Rules firing >100 times/hour
   - Rules with <5% true positive rate

### **Phase 2: Tuning (Week 3-4)**

#### **Method 1: Threshold Adjustment**

Edit `threshold.config`:

```
# Reduce alert frequency for noisy rule
threshold gen_id 1, sig_id 2300001, type threshold, track by_src, count 10, seconds 300
```

#### **Method 2: Suppression**

Suppress known false positives:

```
# Suppress for specific IP
suppress gen_id 1, sig_id 2300001, track by_src, ip 192.168.1.50

# Suppress for entire subnet
suppress gen_id 1, sig_id 2300001, track by_src, ip 10.0.0.0/8
```

#### **Method 3: Rule Modification**

Adjust rule sensitivity:

```
# Original (too sensitive)
alert http any any -> $HOME_NET any (msg:"TEST"; content:"admin"; http_uri;)

# Tuned (more specific)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"TEST"; content:"/admin/"; http_uri; depth:7; content:"POST"; http_method;)
```

### **Phase 3: Validation (Week 5-6)**

Run test attacks to verify detections still work:

```bash
# SQL Injection test
./scripts/test-detections.sh sql_injection

# Port scan test
./scripts/test-detections.sh port_scan
```

---

## 🎯 Optimization Techniques

### **1. Prioritize Critical Rules**

Set priorities in `classification.config`:

```
config classification: ransomware,Ransomware Activity Detected,1  # Highest
config classification: policy-violation,Policy Violation,3        # Lowest
```

### **2. Use Fast Pattern**

Optimize rule performance:

```
# Before
alert http any any -> any any (msg:"TEST"; content:"malware"; content:"payload";)

# After (faster)
alert http any any -> any any (msg:"TEST"; content:"malware"; fast_pattern; content:"payload";)
```

### **3. Disable Unused Protocols**

Edit `suricata.yaml`:

```yaml
app-layer:
  protocols:
    ftp:
      enabled: no  # If not needed
```

---

## 📈 Performance Monitoring

### **Key Metrics to Track**

```bash
# Check packet capture stats
docker-compose exec suricata grep -A 10 "Capture" /var/log/suricata/stats.log

# Check rule performance
docker-compose exec suricata cat /var/log/suricata/rule_perf.log | head -20
```

**Target Metrics:**
- Packet drop rate: <1%
- CPU usage: <70%
- Alert-to-packet ratio: <0.1%

---

## 🔧 Common Tuning Scenarios

### **Scenario 1: High False Positives on Internal Scanning**

**Problem:** Security scanners trigger port scan alerts

**Solution:**
```
# Add scanner IPs to whitelist in threshold.config
suppress gen_id 1, sig_id 2200001, track by_src, ip 192.168.1.100
suppress gen_id 1, sig_id 2200002, track by_src, ip 192.168.1.100
```

### **Scenario 2: Legitimate File Uploads Flagged as Malicious**

**Problem:** Internal file sharing triggers web attack alerts

**Solution:**
```
# Adjust rule to exclude internal traffic
alert http $EXTERNAL_NET any -> $HOME_NET any (...)  # Changed from 'any any'
```

### **Scenario 3: Cloud Services Trigger Policy Violations**

**Problem:** Legitimate cloud usage flagged

**Solution:**
```
# Suppress for known cloud IPs
suppress gen_id 1, sig_id 2700003, track by_dst, ip 52.0.0.0/8  # AWS
suppress gen_id 1, sig_id 2700003, track by_dst, ip 13.0.0.0/8  # AWS
```

---

## 📋 Tuning Checklist

- [ ] Run baseline for 2 weeks minimum
- [ ] Identify top 10 noisiest rules
- [ ] Document legitimate use cases causing FPs
- [ ] Apply threshold/suppression rules
- [ ] Test critical detections still work
- [ ] Monitor for 1 week post-tuning
- [ ] Document all changes in this file
- [ ] Achieve <5% false positive rate

---

## 🚨 Critical Rules (Never Disable)

These rules should have minimal tuning:

- Ransomware signatures (sid:2400000-2400999)
- Critical exploits (EternalBlue, Log4Shell, etc.)
- C2 beaconing patterns
- Lateral movement detections

---

## 📊 Tuning Template

Use this template for each tuned rule:

```
Rule SID: 2XXXXXX
Original Alert Rate: XXX/hour
False Positive Rate: XX%
Root Cause: [Description]
Tuning Action: [threshold/suppress/modify]
New Alert Rate: XXX/hour
Validation: [Test results]
Date: YYYY-MM-DD
```

---

## 🔄 Continuous Improvement

Review tuning monthly:

```bash
# Generate monthly report
./scripts/generate-report.py --month $(date +%Y-%m) --fp-analysis
```

Adjust as network environment changes.

---

**Questions?** See main [README.md](../README.md) or [SETUP.md](../SETUP.md)
