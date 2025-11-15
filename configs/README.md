# Configuration Files

This directory contains all configuration files for the Network IDS components.

---

## 📁 Directory Structure

```
configs/
├── zeek-config/           # Zeek configuration files
│   ├── Dockerfile         # Zeek container build file
│   ├── local.zeek         # Main Zeek configuration
│   ├── networks.cfg       # Network definitions
│   ├── node.cfg           # Zeek cluster node configuration
│   └── zeekctl.cfg        # Zeek control configuration
│
└── suricata-config/       # Suricata configuration files
    ├── Dockerfile         # Suricata container build file
    ├── suricata.yaml      # Main Suricata configuration
    ├── classification.config  # Alert classification
    ├── reference.config   # External reference systems
    └── threshold.config   # Alert thresholds and suppression
```

---

## 🔧 Zeek Configuration

### **local.zeek**
Main Zeek configuration file that loads all detection scripts and sets global parameters.

**Key Features:**
- Loads custom detection scripts from `zeek-scripts/`
- Configures log formats (JSON for Elasticsearch compatibility)
- Sets network protocols to monitor
- Defines file extraction policies

**Custom Script Loading:**
```zeek
@load custom/detect_dns_tunneling
@load custom/detect_c2_beaconing
@load custom/detect_lateral_movement
@load custom/detect_port_scanning
@load custom/detect_tls_anomalies
```

### **networks.cfg**
Defines internal networks for proper traffic direction analysis.

**Format:**
```
10.0.0.0/8       Private-Network
172.16.0.0/12    Private-Network
192.168.0.0/16   Private-Network
```

**Usage:** Update with your actual internal network ranges for accurate threat detection.

### **node.cfg**
Zeek cluster configuration for distributed packet processing.

**Current Setup:** Standalone mode (single node)
**For Production:** Configure multiple workers for high-traffic environments

### **zeekctl.cfg**
Zeek control daemon configuration.

**Key Settings:**
- Log directory paths
- Email notifications (disabled by default)
- Log rotation settings

---

## 🔧 Suricata Configuration

### **suricata.yaml**
Main Suricata configuration file (7,500+ lines).

**Key Sections:**
```yaml
# Network capture settings
af-packet:
  - interface: any
    cluster-id: 99
    cluster-type: cluster_flow

# Detection engine
detect:
  profile: high
  custom-values:
    toclient-groups: 3
    toserver-groups: 25

# Output modules
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - http
        - dns
        - tls
```

**Performance Tuning:**
- Multi-threading enabled (auto-detect cores)
- AF_PACKET for high-performance packet capture
- Flow-based load balancing

### **classification.config**
Defines alert severity levels and categories.

**Categories:**
- `not-suspicious` - Priority 3
- `unknown` - Priority 3
- `bad-unknown` - Priority 2
- `attempted-recon` - Priority 2
- `successful-recon-limited` - Priority 2
- `attempted-dos` - Priority 2
- `attempted-user` - Priority 1
- `successful-admin` - Priority 1
- `trojan-activity` - Priority 1
- `web-application-attack` - Priority 1

### **threshold.config**
Controls alert volume through suppression and thresholds.

**Strategies:**
- **Limit:** Generate alert only N times per time period
- **Threshold:** Alert only after N occurrences
- **Both:** Combination of limit and threshold
- **Suppress:** Completely suppress specific alerts

**Example:**
```
# Alert only once for port scan per 60 seconds
threshold gen_id 1, sig_id 2010937, type limit, track by_src, count 1, seconds 60
```

### **reference.config**
External reference systems for rule metadata.

**Supported Systems:**
- CVE (Common Vulnerabilities and Exposures)
- BugTraq
- Emerging Threats
- NIST
- OSVDB

---

## 🚀 Configuration Management

### Modifying Configurations

**1. Edit Configuration Files:**
```bash
# Edit Zeek config
nano configs/zeek-config/local.zeek

# Edit Suricata config
nano configs/suricata-config/suricata.yaml
```

**2. Validate Configuration:**
```bash
# Validate Suricata config
docker-compose exec suricata suricata -T -c /etc/suricata/suricata.yaml

# Test Zeek config
docker-compose exec zeek zeek -C configs/local.zeek
```

**3. Apply Changes:**
```bash
# Restart specific service
docker-compose restart zeek
docker-compose restart suricata

# Or restart all services
docker-compose restart
```

### Network Customization

**Update `networks.cfg` for your environment:**
```bash
# Example for corporate network
10.50.0.0/16      Corporate-HQ
10.51.0.0/16      Corporate-DC
192.168.100.0/24  Guest-WiFi
```

**Benefits:**
- Accurate traffic direction (internal vs external)
- Improved lateral movement detection
- Better baseline for anomaly detection

---

## 🔍 Configuration Best Practices

### Security Hardening

1. **Change Default Passwords**
   - Update Elasticsearch password in docker-compose.yml
   - Never commit credentials to version control

2. **Enable TLS/SSL**
   ```yaml
   # In suricata.yaml - Enable TLS logging
   tls:
     enabled: yes
     extended: yes
   ```

3. **Configure Log Retention**
   ```yaml
   # Suricata log rotation
   max-days: 30
   ```

4. **Resource Limits**
   - Set appropriate memory limits in docker-compose.yml
   - Configure Zeek/Suricata workers based on CPU cores

### Performance Tuning

**For Low-Resource Environments (<8GB RAM):**
```yaml
# Reduce Suricata threads
threading:
  set-cpu-affinity: no
  detect-thread-ratio: 1.0
```

**For High-Traffic Environments (>1 Gbps):**
```yaml
# Increase buffer sizes
af-packet:
  - buffer-size: 64535
    ring-size: 20000
```

### Monitoring and Alerting

**Enable Stats Logging:**
```yaml
# In suricata.yaml
stats:
  enabled: yes
  interval: 30
  decoder-events: yes
```

**Configure Zeek Stats:**
```bash
# In zeekctl.cfg
StatsLogEnable = 1
StatsLogExpireInterval = 3600
```

---

## 📚 Additional Resources

- [Zeek Configuration Reference](https://docs.zeek.org/en/master/configuration/index.html)
- [Suricata Configuration Guide](https://suricata.readthedocs.io/en/latest/configuration/index.html)
- [Network IDS Best Practices](../SETUP.md)
- [Performance Tuning Guide](../performance-metrics/README.md)

---

## ⚙️ Troubleshooting

### Zeek Won't Start

**Check logs:**
```bash
docker-compose logs zeek | tail -50
```

**Common issues:**
- Syntax error in local.zeek - Validate with `zeek -C local.zeek`
- Network interface not found - Set to `any` for testing
- Permission issues - Check file ownership

### Suricata Configuration Errors

**Validate configuration:**
```bash
docker-compose exec suricata suricata -T -c /etc/suricata/suricata.yaml
```

**Common issues:**
- YAML syntax errors - Use proper indentation (spaces, not tabs)
- Missing rule files - Ensure rules are mounted correctly
- Interface issues - Check `--af-packet` interface setting

### High Resource Usage

**Check resource consumption:**
```bash
docker stats
```

**Solutions:**
- Reduce number of Suricata workers
- Disable unused Zeek scripts
- Tune rule sets (disable low-value rules)
- Increase Docker resource limits

---

**Last Updated:** 2024-11-15
**Version:** 1.2.0
**Status:** Production-Ready
