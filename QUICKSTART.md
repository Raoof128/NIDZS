# Quick Start Guide

Get the Network IDS running in 5 minutes.

---

## ⚡ One-Line Deploy

```bash
git clone https://github.com/Raoof128/NIDZS.git && cd NIDZS && ./scripts/deploy.sh
```

---

## 📋 Prerequisites

Ensure you have:
- **Docker** (24.0+)
- **Docker Compose** (2.20+)
- **8GB RAM minimum** (16GB recommended)
- **50GB free disk space**

### Install Dependencies

**macOS:**
```bash
brew install docker docker-compose
```

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install docker.io docker-compose git -y
sudo usermod -aG docker $USER
newgrp docker
```

---

## 🚀 Step-by-Step Deployment

### Step 1: Clone Repository

```bash
git clone https://github.com/Raoof128/NIDZS.git
cd NIDZS
```

### Step 2: Deploy Stack

```bash
# Automated deployment (recommended)
./scripts/deploy.sh

# Or manually
docker-compose up -d
```

**Wait 2-3 minutes for initialization.**

### Step 3: Verify Deployment

```bash
./scripts/verify-deployment.sh
```

You should see:
```
✓ All tests passed!
```

### Step 4: Access Kibana

Open your browser:
```
http://localhost:5601
```

**Login:**
- Username: `elastic`
- Password: `changeme`

---

## 🎯 Quick Test

### Generate Test Traffic

```bash
# DNS query (will trigger DNS tunneling detection if query is long enough)
dig $(python3 -c "print('A'*60)")test.com @8.8.8.8

# Port scan (will trigger port scan detection)
nmap -p 22,80,443 scanme.nmap.org
```

### View Alerts

**In Kibana:**
1. Navigate to **Discover**
2. Select `suricata-*` index pattern
3. Filter by: `event.kind:alert`

**Via CLI:**
```bash
# Suricata alerts
docker-compose exec suricata tail -f /var/log/suricata/fast.log

# Zeek notices
docker-compose exec zeek tail -f /opt/zeek/logs/current/notice.log
```

---

## 📊 Access Points

| Service | URL | Credentials |
|---------|-----|-------------|
| **Kibana** | http://localhost:5601 | elastic / changeme |
| **Elasticsearch** | http://localhost:9200 | elastic / changeme |

---

## 🔍 Verify Everything Works

```bash
# Check all containers are running
docker-compose ps

# Check Elasticsearch health
curl -u elastic:changeme http://localhost:9200/_cluster/health?pretty

# Check logs are being generated
docker-compose exec zeek ls -l /opt/zeek/logs/current/
docker-compose exec suricata ls -l /var/log/suricata/

# Run comprehensive tests
./scripts/test-detection.sh
```

---

## 🛠️ Common Commands

### Container Management

```bash
# Start all services
docker-compose up -d

# Stop all services
docker-compose stop

# Restart specific service
docker-compose restart zeek

# View logs
docker-compose logs -f zeek
docker-compose logs -f suricata
docker-compose logs -f filebeat

# Check status
docker-compose ps
```

### Service Access

```bash
# Access Zeek logs
docker-compose exec zeek tail -f /opt/zeek/logs/current/conn.log

# Access Suricata alerts
docker-compose exec suricata tail -f /var/log/suricata/eve.json

# Query Elasticsearch
curl -u elastic:changeme "http://localhost:9200/zeek-*/_search?pretty"
```

---

## 🐛 Quick Troubleshooting

### Issue: "Cannot connect to Docker daemon"

**Solution:**
```bash
# Start Docker service
sudo systemctl start docker  # Linux
open -a Docker              # macOS
```

### Issue: "Elasticsearch won't start"

**Solution:**
```bash
# Increase vm.max_map_count (Linux only)
sudo sysctl -w vm.max_map_count=262144

# Or increase Docker Desktop memory (macOS)
# Docker Desktop > Preferences > Resources > Memory = 8GB+
```

### Issue: "Port 9200 already in use"

**Solution:**
```bash
# Find process using port
sudo lsof -i :9200  # macOS/Linux
netstat -ano | findstr :9200  # Windows

# Stop conflicting service or change port in docker-compose.yml
```

### Issue: "No logs appearing"

**Solution:**
```bash
# Check containers are running
docker-compose ps

# Generate test traffic
ping -c 10 google.com

# Wait 30 seconds and check again
docker-compose exec zeek ls -l /opt/zeek/logs/current/
```

---

## 📚 Next Steps

1. **Explore Kibana**
   - Create visualizations
   - Build dashboards
   - Run threat hunting queries

2. **Customize Detection**
   - Edit Zeek scripts in `zeek-scripts/`
   - Add Suricata rules in `suricata-rules/`
   - Restart services to apply changes

3. **Load Test Data**
   - Download PCAP files to `sample-traffic/`
   - Replay with: `docker-compose exec zeek tcpreplay -i eth0 /pcaps/sample.pcap`

4. **Tune Rules**
   - Review `suricata-rules/tuning_guide.md`
   - Reduce false positives
   - Optimize performance

5. **Learn Threat Hunting**
   - Follow `threat-hunting/hunting_playbook.md`
   - Try KQL queries from `threat-hunting/kql_queries.md`

---

## 🆘 Getting Help

**Documentation:**
- [Full Setup Guide](SETUP.md) - Detailed deployment instructions
- [Architecture](ARCHITECTURE.md) - System design and components
- [Threat Hunting](threat-hunting/hunting_playbook.md) - Hunting methodologies

**Troubleshooting:**
- Check logs: `docker-compose logs [service]`
- Run tests: `./scripts/test-detection.sh`
- Verify health: `./scripts/verify-deployment.sh`

**Support:**
- [GitHub Issues](https://github.com/Raoof128/NIDZS/issues)
- [SETUP.md Troubleshooting Section](SETUP.md#troubleshooting)

---

## ⚠️ Security Notes

**Before Production:**

1. **Change Default Password**
   ```bash
   # Update in docker-compose.yml
   ELASTIC_PASSWORD=YourStrongPasswordHere
   ```

2. **Enable TLS**
   - See `SETUP.md` for TLS configuration

3. **Restrict Access**
   - Bind Elasticsearch to localhost only
   - Use firewall rules
   - Implement VPN access

4. **Regular Updates**
   ```bash
   docker-compose pull
   docker-compose up -d
   ```

---

## 🎉 Success!

You now have a production-grade Network IDS running!

**Recommended First Steps:**
1. Open Kibana: http://localhost:5601
2. Explore the Discover tab
3. Run a sample query from the threat hunting guide
4. Review detection alerts

**Questions?** Check the [main README](README.md) or [open an issue](https://github.com/Raoof128/NIDZS/issues).

---

**Deployment time:** ~5 minutes
**Learning curve:** Beginner-friendly
**Production-ready:** Yes (with password change)
