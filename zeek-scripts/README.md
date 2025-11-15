# Custom Zeek Detection Scripts

This directory contains custom Zeek scripts for advanced network threat detection. Each script implements behavioral detection logic beyond simple signature matching.

---

## 📁 Scripts Overview

| Script | Detection Focus | MITRE ATT&CK Coverage |
|--------|----------------|----------------------|
| `detect_dns_tunneling.zeek` | DNS-based exfiltration & C2 | T1071.004 (DNS), T1048 (Exfiltration) |
| `detect_c2_beaconing.zeek` | Periodic C2 callbacks | T1071 (Application Layer Protocol), T1573 (Encrypted Channel) |
| `detect_lateral_movement.zeek` | RDP/SMB lateral movement | T1021.001 (RDP), T1021.002 (SMB/Windows Admin Shares) |
| `detect_port_scanning.zeek` | Network reconnaissance | T1046 (Network Service Scanning) |
| `detect_tls_anomalies.zeek` | TLS/SSL certificate issues | T1573.002 (Asymmetric Cryptography), T1588.004 (Digital Certificates) |

---

## 🎯 Detection Methods

### **1. DNS Tunneling Detection**

**File:** `detect_dns_tunneling.zeek`

**Detects:**
- Abnormally long DNS queries (>50 characters)
- High entropy subdomains (Shannon entropy >3.5)
- Excessive TXT record queries
- Base64/hex-encoded data in queries
- Query flooding (>100 queries/minute per source)

**Tunable Parameters:**
```zeek
const query_length_threshold = 50;        # Character threshold
const entropy_threshold = 3.5;            # Shannon entropy
const max_queries_per_minute = 100;       # Rate limit
```

**Example Alert:**
```
DNS_Tunneling_Detected: abnormally long query (87 chars)
Query: YWRtaW4xMjNwYXNzd29yZDQ1Ng.malicious.com
Entropy: 4.23
```

---

### **2. C2 Beaconing Detection**

**File:** `detect_c2_beaconing.zeek`

**Detects:**
- Periodic connection patterns (10s - 3600s intervals)
- Consistent connection sizes (low variance)
- Uncommon port usage (4444, 5555, 6666, etc.)
- Regular heartbeat patterns

**Tunable Parameters:**
```zeek
const min_connections = 5;                # Minimum to establish pattern
const max_jitter = 5.0;                   # Timing variance (seconds)
const min_beacon_interval = 10.0;         # Minimum interval
const max_beacon_interval = 3600.0;       # Maximum interval
const max_size_cv = 0.3;                  # Size coefficient of variation
```

**Example Alert:**
```
Beaconing_Detected: 192.168.1.50 -> 203.0.113.45:8443
Connections: 12, Avg Interval: 60.2s, Size CV: 0.15
```

---

### **3. Lateral Movement Detection**

**File:** `detect_lateral_movement.zeek`

**Detects:**
- Multiple RDP connections from single source
- SMB administrative share access (ADMIN$, C$, IPC$)
- PSExec-like activity
- WMI remote execution
- Credential spraying patterns

**Tunable Parameters:**
```zeek
const max_rdp_connections = 5;            # RDP threshold
const max_smb_targets = 10;               # SMB threshold
const observation_window = 5min;          # Tracking window
```

**Example Alert:**
```
Suspicious_RDP_Activity: 192.168.1.100 accessed 7 hosts
Connections: 15 in 5min window
Admin_Share_Access: 192.168.1.100 -> \\SERVER01\ADMIN$
```

---

### **4. Port Scanning Detection**

**File:** `detect_port_scanning.zeek`

**Detects:**
- Horizontal scanning (same port, multiple hosts)
- Vertical scanning (multiple ports, same host)
- SYN floods and stealth scans
- NULL, FIN, XMAS TCP scans
- Failed connection floods

**Tunable Parameters:**
```zeek
const horizontal_scan_threshold = 20;     # Unique hosts
const vertical_scan_threshold = 30;       # Unique ports
const failed_connection_threshold = 15;   # Failed attempts
const scan_window = 1min;                 # Observation window
```

**Example Alert:**
```
Port_Scan_Detected: 10.0.0.50 scanning 45 hosts
Ports: 3, Duration: 12.5s
Stealth_Scan_Detected: NULL/FIN/XMAS probes: 23
```

---

### **5. TLS Anomaly Detection**

**File:** `detect_tls_anomalies.zeek`

**Detects:**
- Self-signed certificates
- Expired certificates
- Certificate validation failures
- Weak cipher suites (RC4, DES, 3DES)
- SSL/TLS version downgrade (SSLv2, SSLv3, TLS <1.2)
- Suspicious JA3 fingerprints (Metasploit, Cobalt Strike)

**Tunable Parameters:**
```zeek
const acceptable_tls_versions = set("TLSv12", "TLSv13");
const min_cert_lifetime = 7;              # Days
const suspicious_ja3_hashes = set(        # Known malware hashes
    "6734f37431670b3ab4292b8f60f29984",   # Metasploit
    "51c64c77e60f3980eea90869b68c58a8",   # Cobalt Strike
);
```

**Example Alert:**
```
Self_Signed_Certificate: 203.0.113.100
Subject: CN=localhost
Weak_Cipher_Suite: TLS_RSA_WITH_RC4_128_SHA
```

---

## 🔧 Installation & Configuration

### **1. Deploy Scripts**

Scripts are automatically loaded via `/opt/zeek/share/zeek/site/local.zeek`:

```zeek
@load custom/detect_dns_tunneling
@load custom/detect_c2_beaconing
@load custom/detect_lateral_movement
@load custom/detect_port_scanning
@load custom/detect_tls_anomalies
```

### **2. Customize Thresholds**

Edit individual `.zeek` files to adjust detection sensitivity:

```bash
# Example: Reduce DNS query length threshold
vim zeek-scripts/detect_dns_tunneling.zeek

# Change line:
const query_length_threshold = 50 &redef;
# To:
const query_length_threshold = 40 &redef;
```

### **3. Reload Zeek**

```bash
docker-compose restart zeek

# Or if using zeekctl directly:
docker-compose exec zeek zeekctl deploy
```

### **4. Verify Scripts Are Running**

```bash
# Check Zeek logs
docker-compose exec zeek tail -f /opt/zeek/logs/current/notice.log

# Look for initialization messages
docker-compose exec zeek zeekctl diag
```

---

## 📊 Testing Detections

### **Test DNS Tunneling**

```bash
# Generate long DNS query
dig $(python3 -c "print('A'*60)").test.com @8.8.8.8

# Generate high TXT queries
for i in {1..50}; do dig TXT randomdata$i.test.com @8.8.8.8; done
```

### **Test C2 Beaconing**

```bash
# Create periodic connections (requires netcat)
while true; do
    echo "beacon" | nc -w 1 example.com 8443
    sleep 60
done
```

### **Test Lateral Movement**

```bash
# Multiple RDP attempts (requires rdesktop or xfreerdp)
for host in 10.0.0.{10..20}; do
    timeout 2 xfreerdp /v:$host /u:admin /p:test
done

# SMB share enumeration
smbclient -L //10.0.0.10 -U guest%
```

### **Test Port Scanning**

```bash
# Horizontal scan
nmap -p 22 10.0.0.0/24

# Vertical scan
nmap -p 1-1000 10.0.0.10

# Stealth scan
nmap -sN 10.0.0.10  # NULL scan
nmap -sF 10.0.0.10  # FIN scan
```

### **Test TLS Anomalies**

```bash
# Connect with weak cipher
openssl s_client -connect example.com:443 -cipher RC4-SHA

# Force TLS 1.0
openssl s_client -connect example.com:443 -tls1
```

---

## 🎨 Customization Guide

### **Add Custom Notice Type**

```zeek
# In your script
export {
    redef enum Notice::Type += {
        My_Custom_Detection,
    };
}

# Generate notice
NOTICE([$note=My_Custom_Detection,
        $conn=c,
        $msg="Custom detection triggered",
        $sub=fmt("Details: %s", info),
        $identifier=cat(c$id$orig_h, "custom")]);
```

### **Add Whitelist**

```zeek
# DNS tunneling whitelist
const whitelist_domains = set(
    "google.com",
    "your-domain.com",
) &redef;

# Check in event handler
if (is_whitelisted(query))
    return;
```

### **Integrate with Intel Framework**

```zeek
# Load intel framework
@load base/frameworks/intel

# Create intel file: /opt/zeek/share/zeek/site/intel/malicious-ips.txt
# Format: indicator<TAB>indicator_type<TAB>meta.source
# Example:
# 203.0.113.45	Intel::ADDR	MalwareC2
# evil.com	Intel::DOMAIN	Phishing

# Configure in local.zeek
redef Intel::read_files += {
    "/opt/zeek/share/zeek/site/intel/malicious-ips.txt",
};
```

---

## 🐛 Troubleshooting

### **Script Not Loading**

```bash
# Check for syntax errors
docker-compose exec zeek zeek -C -r /pcaps/test.pcap custom/detect_dns_tunneling.zeek

# Check loaded scripts
docker-compose exec zeek zeekctl print ScriptDir
```

### **No Alerts Generated**

```bash
# Verify notice.log exists
docker-compose exec zeek ls -l /opt/zeek/logs/current/notice.log

# Check script initialization
docker-compose exec zeek grep "Detection: Monitoring started" /opt/zeek/logs/current/stdout.log

# Manually test with PCAP
docker-compose exec zeek zeek -r /pcaps/malicious.pcap custom/detect_dns_tunneling.zeek
```

### **High False Positive Rate**

```
# Increase thresholds
const query_length_threshold = 70;  # Was 50
const max_queries_per_minute = 150;  # Was 100

# Add more whitelists
const whitelist_domains += { "known-good.com" };

# Restart Zeek
docker-compose restart zeek
```

---

## 📚 Additional Resources

- [Zeek Scripting Documentation](https://docs.zeek.org/en/stable/scripting/index.html)
- [Zeek Notice Framework](https://docs.zeek.org/en/stable/frameworks/notice.html)
- [Zeek SumStats Framework](https://docs.zeek.org/en/stable/frameworks/sumstats.html)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

---

## ✅ Validation Checklist

- [ ] All 5 scripts load without errors
- [ ] Scripts appear in `zeekctl status` output
- [ ] `notice.log` receives alerts
- [ ] Test traffic generates expected alerts
- [ ] False positive rate <5%
- [ ] Thresholds tuned for environment
- [ ] Scripts integrated with Filebeat

---

**Questions or issues?** Check the main [README.md](../README.md) or open an issue on GitHub.
