# Network IDS - Complete Setup Guide

This guide walks through deploying the complete Network IDS stack from scratch. Follow these steps for a production-grade deployment.

---

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start Deployment](#quick-start-deployment)
3. [Manual Deployment](#manual-deployment)
4. [Verification & Testing](#verification--testing)
5. [Configuration Tuning](#configuration-tuning)
6. [Troubleshooting](#troubleshooting)
7. [Advanced Configuration](#advanced-configuration)

---

## Prerequisites

### **System Requirements**

| Component | Minimum | Recommended | Notes |
|-----------|---------|-------------|-------|
| **CPU** | 4 cores | 8+ cores | M1/M2/M4 or x86_64 |
| **RAM** | 8GB | 16GB+ | Elasticsearch is memory-intensive |
| **Disk** | 50GB | 100GB+ | SSD recommended for I/O |
| **OS** | macOS 12+ / Ubuntu 20.04+ | Latest stable | Tested on macOS M4 Max |
| **Network** | 100 Mbps | 1 Gbps+ | For packet capture |

### **Software Prerequisites**

```bash
# macOS
brew install docker docker-compose git

# Ubuntu/Debian
sudo apt update
sudo apt install docker.io docker-compose git -y
sudo usermod -aG docker $USER  # Add user to docker group
newgrp docker  # Activate group
```

### **Verify Installations**

```bash
docker --version          # Should be 24.0+
docker-compose --version  # Should be 2.20+
git --version            # Should be 2.30+
```

---

## Quick Start Deployment

### **Option 1: Automated Deployment (Recommended)**

```bash
# Clone repository
git clone https://github.com/Raoof128/NIDZS.git
cd NIDZS

# Run automated setup
chmod +x scripts/deploy.sh
./scripts/deploy.sh

# Verify deployment
./scripts/verify-deployment.sh
```

**Deployment completes in 3-5 minutes**. Access Kibana at http://localhost:5601 (elastic/changeme).

### **Option 2: Docker Compose Manual Start**

```bash
# Start all services
docker-compose up -d

# Check service health
docker-compose ps

# View logs
docker-compose logs -f
```

### **Option 3: Step-by-Step Build**

Continue to [Manual Deployment](#manual-deployment) section.

---

## Manual Deployment

### **Step 1: Network Configuration**

Create Docker network for service communication:

```bash
docker network create ids-network
```

### **Step 2: Deploy Elasticsearch**

```bash
# Create data directory
mkdir -p elasticsearch-kibana/data/elasticsearch

# Set permissions (Linux only)
sudo chown -R 1000:1000 elasticsearch-kibana/data/elasticsearch

# Start Elasticsearch
docker-compose up -d elasticsearch

# Wait for startup (60-90 seconds)
sleep 90

# Verify Elasticsearch is healthy
curl -u elastic:changeme http://localhost:9200/_cluster/health?pretty
```

**Expected output:**
```json
{
  "status" : "green",
  "cluster_name" : "network-ids-cluster",
  "number_of_nodes" : 1
}
```

### **Step 3: Deploy Kibana**

```bash
# Start Kibana
docker-compose up -d kibana

# Wait for startup (30-60 seconds)
sleep 60

# Verify Kibana is accessible
curl -I http://localhost:5601/api/status
```

**Access Kibana**: Open http://localhost:5601 in browser, login with `elastic/changeme`.

### **Step 4: Deploy Zeek**

```bash
# Build Zeek container
docker-compose build zeek

# Start Zeek
docker-compose up -d zeek

# Verify Zeek is running
docker-compose exec zeek zeek --version
docker-compose exec zeek zeekctl status
```

**Expected output:**
```
Name         Type       Host          Status    Pid    Started
zeek         standalone localhost     running   123    15 Nov 10:30:00
```

### **Step 5: Deploy Suricata**

```bash
# Build Suricata container
docker-compose build suricata

# Update Suricata rules
docker-compose exec suricata suricata-update

# Start Suricata
docker-compose up -d suricata

# Verify Suricata is running
docker-compose exec suricata suricatasc -c "uptime"
```

### **Step 6: Deploy Filebeat**

```bash
# Start Filebeat
docker-compose up -d filebeat

# Verify Filebeat is shipping logs
docker-compose logs filebeat | grep "Publish event"
```

### **Step 7: Load Kibana Dashboards**

```bash
# Import dashboards
./scripts/load-dashboards.sh

# Or manually via Kibana UI:
# 1. Navigate to Management > Saved Objects
# 2. Import each .ndjson file from elasticsearch-kibana/kibana-dashboards/
```

---

## Verification & Testing

### **Health Check All Services**

```bash
# Check all containers are running
docker-compose ps

# Should show all services as "Up"
```

### **Verify Data Flow**

```bash
# 1. Check Zeek is generating logs
docker-compose exec zeek ls -lh /opt/zeek/logs/current/

# 2. Check Suricata is generating alerts
docker-compose exec suricata tail /var/log/suricata/fast.log

# 3. Query Elasticsearch for Zeek logs
curl -u elastic:changeme "http://localhost:9200/zeek-*/_count?pretty"

# 4. Query Elasticsearch for Suricata alerts
curl -u elastic:changeme "http://localhost:9200/suricata-*/_count?pretty"
```

### **Test Detection with Sample Traffic**

```bash
# Replay malicious PCAP file
./scripts/replay-pcap.sh sample-traffic/malicious.pcap

# Wait 30 seconds for processing
sleep 30

# Check for alerts in Kibana
# Navigate to: Discover > suricata-* index
# Filter: event.kind:alert

# Or query via API
curl -u elastic:changeme "http://localhost:9200/suricata-*/_search?pretty&q=event.kind:alert"
```

### **Performance Benchmarking**

```bash
# Run performance test
./scripts/benchmark.sh

# Results saved to: performance-metrics/latest_benchmark.json
```

**Expected baseline metrics:**
- Packet processing: 50,000+ pps
- Alert latency: <30 seconds
- CPU usage: <70%
- Memory usage: <16GB

---

## Configuration Tuning

### **Zeek Performance Tuning**

Edit `configs/zeek-config/local.zeek`:

```zeek
# Increase worker threads (adjust for CPU count)
@load policy/frameworks/cluster

# Disable verbose logging for performance
redef Log::enable_local_logging = F;

# Tune memory
redef table_expire_interval = 10min;
```

Restart Zeek:
```bash
docker-compose restart zeek
```

### **Suricata Performance Tuning**

Edit `configs/suricata-config/suricata.yaml`:

```yaml
# Adjust thread count (CPU cores - 1)
threading:
  set-cpu-affinity: yes
  cpu-affinity:
    - management-cpu-set:
        cpu: [ 0 ]
    - receive-cpu-set:
        cpu: [ 1,2,3 ]
    - worker-cpu-set:
        cpu: [ 4,5,6,7 ]

# Tune packet buffer
max-pending-packets: 65535
```

Restart Suricata:
```bash
docker-compose restart suricata
```

### **Elasticsearch Performance Tuning**

Edit `elasticsearch-kibana/elasticsearch.yml`:

```yaml
# Increase heap size (50% of available RAM, max 32GB)
ES_JAVA_OPTS: "-Xms8g -Xmx8g"

# Optimize for time-series data
index.refresh_interval: 30s
index.number_of_shards: 1
index.number_of_replicas: 0
```

Restart Elasticsearch:
```bash
docker-compose restart elasticsearch
```

### **False Positive Reduction**

```bash
# Run automated tuning script
python3 scripts/tune-rules.py \
  --threshold 0.05 \
  --days 7 \
  --output suricata-rules/tuned_rules.yaml

# Apply tuned rules
docker-compose restart suricata
```

---

## Troubleshooting

### **Issue: Elasticsearch Won't Start**

**Symptoms:**
```
ERROR: Elasticsearch exited with code 78
```

**Solution:**
```bash
# macOS: Increase Docker memory limit
# Docker Desktop > Preferences > Resources > Memory = 8GB+

# Linux: Increase vm.max_map_count
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf

# Restart Elasticsearch
docker-compose restart elasticsearch
```

### **Issue: Zeek Not Capturing Traffic**

**Symptoms:**
```
No logs in /opt/zeek/logs/current/
```

**Solution:**
```bash
# Check network interface
docker-compose exec zeek ip link show

# Ensure Zeek has CAP_NET_RAW capability
docker-compose exec zeek capsh --print | grep cap_net_raw

# Restart with correct interface
docker-compose restart zeek
```

### **Issue: Filebeat Not Shipping Logs**

**Symptoms:**
```
No data in Elasticsearch indices
```

**Solution:**
```bash
# Check Filebeat logs
docker-compose logs filebeat | grep ERROR

# Test Elasticsearch connectivity
docker-compose exec filebeat curl -u elastic:changeme http://elasticsearch:9200

# Verify log paths exist
docker-compose exec filebeat ls -l /var/log/zeek/
docker-compose exec filebeat ls -l /var/log/suricata/

# Restart Filebeat
docker-compose restart filebeat
```

### **Issue: High CPU Usage**

**Symptoms:**
```
Docker consuming 90%+ CPU
```

**Solution:**
```bash
# Identify resource-heavy container
docker stats

# Reduce Zeek worker threads
# Edit configs/zeek-config/node.cfg
# Set worker count to CPU cores / 2

# Reduce Suricata threads
# Edit configs/suricata-config/suricata.yaml
# Decrease worker-cpu-set count

# Restart services
docker-compose restart zeek suricata
```

### **Issue: Disk Space Filling Up**

**Symptoms:**
```
Elasticsearch index writes failing
```

**Solution:**
```bash
# Check disk usage
du -sh elasticsearch-kibana/data/*

# Delete old indices (>30 days)
curl -u elastic:changeme -X DELETE "http://localhost:9200/zeek-$(date -d '30 days ago' +%Y.%m.%d)"
curl -u elastic:changeme -X DELETE "http://localhost:9200/suricata-$(date -d '30 days ago' +%Y.%m.%d)"

# Configure automated cleanup (Index Lifecycle Management)
# Kibana > Management > Index Lifecycle Policies
# Create policy: Delete after 30 days
```

### **Issue: Can't Access Kibana**

**Symptoms:**
```
Connection refused at localhost:5601
```

**Solution:**
```bash
# Check Kibana container status
docker-compose logs kibana | tail -50

# Wait for full startup (can take 2-3 minutes)
sleep 120

# Verify Elasticsearch is healthy first
curl -u elastic:changeme http://localhost:9200/_cluster/health

# Restart Kibana
docker-compose restart kibana
```

---

## Advanced Configuration

### **Enable IPS Mode (Inline Blocking)**

**Suricata IPS Configuration:**

```yaml
# Edit configs/suricata-config/suricata.yaml
af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes
```

**Enable blocking:**
```bash
# Add iptables rule for packet forwarding
docker-compose exec suricata iptables -I FORWARD -j NFQUEUE --queue-num 0

# Restart Suricata in IPS mode
docker-compose exec suricata suricata -c /etc/suricata/suricata.yaml -q 0 -D
```

### **Custom Zeek Scripts Auto-Load**

Edit `configs/zeek-config/local.zeek`:

```zeek
# Load custom detection scripts
@load ./detect_dns_tunneling
@load ./detect_c2_beaconing
@load ./detect_lateral_movement
@load ./detect_port_scanning
@load ./detect_tls_anomalies

# Load community scripts
@load packages
```

### **Automated Rule Updates**

Create cron job:

```bash
# Add to crontab
crontab -e

# Update Suricata rules daily at 2 AM
0 2 * * * docker-compose exec suricata suricata-update && docker-compose restart suricata
```

### **Enable TLS Encryption**

**Generate certificates:**
```bash
cd elasticsearch-kibana/certs
./generate-certs.sh
```

**Update docker-compose.yml:**
```yaml
elasticsearch:
  environment:
    - xpack.security.enabled=true
    - xpack.security.transport.ssl.enabled=true
    - xpack.security.http.ssl.enabled=true
```

### **Multi-Host Deployment**

For distributed setup across multiple hosts:

```bash
# On sensor nodes (capture traffic)
docker-compose up -d zeek suricata filebeat

# On SIEM node (central logging)
docker-compose up -d elasticsearch kibana

# Update Filebeat to point to remote Elasticsearch
# Edit configs/filebeat-config.yml:
output.elasticsearch:
  hosts: ["https://siem-server:9200"]
```

---

## Next Steps

After successful deployment:

1. **Load Custom Detection Rules**
   - Review `zeek-scripts/README.md`
   - Review `suricata-rules/README.md`
   - Apply custom rules: `docker-compose restart zeek suricata`

2. **Configure Dashboards**
   - Import pre-built dashboards from `elasticsearch-kibana/kibana-dashboards/`
   - Customize for your environment

3. **Run Threat Hunting**
   - Follow playbooks in `threat-hunting/`
   - Execute KQL queries from `threat-hunting/kql_queries.md`

4. **Benchmark Performance**
   - Run `./scripts/benchmark.sh`
   - Document results in `performance-metrics/`

5. **Simulate Attacks**
   - Use sample PCAPs from `sample-traffic/`
   - Or generate live attacks with Kali Linux

---

## Maintenance

### **Daily Tasks**

```bash
# Check service health
docker-compose ps

# Monitor disk usage
df -h | grep docker
```

### **Weekly Tasks**

```bash
# Update Suricata rules
docker-compose exec suricata suricata-update

# Review false positives
python3 scripts/analyze-alerts.py --days 7 --threshold 10
```

### **Monthly Tasks**

```bash
# Backup Elasticsearch indices
./scripts/backup-elasticsearch.sh

# Update Docker images
docker-compose pull
docker-compose up -d

# Review performance metrics
cat performance-metrics/monthly_report.json
```

---

## Support

**Common Resources:**
- [Zeek Documentation](https://docs.zeek.org/)
- [Suricata Docs](https://suricata.readthedocs.io/)
- [Elastic Stack Guide](https://www.elastic.co/guide/)

**Project Issues:**
- GitHub Issues: https://github.com/Raoof128/NIDZS/issues
- Troubleshooting: See above section

---

**Setup complete! Access Kibana at http://localhost:5601 and start hunting.** 🎯
