# Automation Scripts

Collection of automation scripts for deploying, testing, and managing the Network IDS.

---

## 📁 Available Scripts

| Script | Purpose | Complexity |
|--------|---------|------------|
| `deploy.sh` | Automated deployment and initialization | ⭐⭐ Intermediate |
| `verify-deployment.sh` | Health checks and validation | ⭐ Beginner |
| `test-detection.sh` | Comprehensive detection testing | ⭐⭐ Intermediate |
| `generate-traffic.sh` | Synthetic traffic generation | ⭐⭐ Intermediate |
| `backup-data.sh` | Backup Elasticsearch data | ⭐ Beginner |

---

## 🚀 Deployment Scripts

### **deploy.sh**

Automated deployment script with environment detection and prerequisite checking.

**Usage:**
```bash
./scripts/deploy.sh
```

**What it does:**
1. Checks system requirements (Docker, memory, disk space)
2. Configures OS parameters (vm.max_map_count for Elasticsearch)
3. Starts services in proper order (Elasticsearch → Kibana → IDS)
4. Waits for service health checks
5. Displays access points and next steps

**Options:**
```bash
# Deploy with custom environment
./scripts/deploy.sh --env production

# Skip prerequisite checks (advanced)
./scripts/deploy.sh --skip-checks

# Verbose output
./scripts/deploy.sh --verbose
```

**Exit Codes:**
- `0` - Success
- `1` - Docker not available
- `2` - Insufficient resources
- `3` - Service startup failure

**Output Example:**
```
========================================
Network IDS - Automated Deployment
========================================

[✓] Docker daemon running
[✓] Docker Compose available
[✓] System memory: 16GB (meets requirement)
[✓] Disk space: 120GB available

Starting Elasticsearch...
Waiting for Elasticsearch to be ready...
[✓] Elasticsearch is healthy

Starting Kibana...
[✓] Kibana is ready

Starting Zeek and Suricata...
[✓] All services are running

========================================
Deployment Complete!
========================================

Access Points:
  Kibana:        http://localhost:5601
  Elasticsearch: http://localhost:9200

Credentials: elastic / changeme

Next Steps:
  1. Run verification: ./scripts/verify-deployment.sh
  2. Import dashboards: ./elasticsearch-kibana/kibana-dashboards/import-dashboards.sh
  3. Generate test traffic: ./scripts/generate-traffic.sh
```

---

### **verify-deployment.sh**

Comprehensive health check and validation script.

**Usage:**
```bash
./scripts/verify-deployment.sh
```

**Checks Performed:**
- ✅ Docker containers running
- ✅ Service APIs responding
- ✅ Elasticsearch cluster health
- ✅ Kibana accessibility
- ✅ Zeek/Suricata log generation
- ✅ Filebeat data shipping
- ✅ Configuration file existence
- ✅ Volume mounts correctness

**Output Example:**
```
========================================
Network IDS - Deployment Verification
========================================

=== Container Health ===
[Elasticsearch] ✓ Running (healthy)
[Kibana]       ✓ Running (healthy)
[Zeek]         ✓ Running
[Suricata]     ✓ Running
[Filebeat]     ✓ Running

=== Service APIs ===
[Elasticsearch API] ✓ Responding (green)
[Kibana API]        ✓ Responding

=== Log Generation ===
[Zeek logs]     ✓ Found 8 log files
[Suricata logs] ✓ Found eve.json

=== Data Flow ===
[Elasticsearch indices] ✓ 3 indices created

========================================
Verification Summary
========================================
Passed: 18/18
Failed: 0

✓ Deployment is healthy and operational!
```

---

## 🧪 Testing Scripts

### **test-detection.sh**

Comprehensive detection capability testing.

**Usage:**
```bash
./scripts/test-detection.sh
```

**Test Categories:**
1. **Infrastructure Tests** (3 tests)
   - Docker daemon
   - Docker Compose
   - Network configuration

2. **Container Health** (5 tests)
   - All containers running
   - Resource utilization

3. **Service Health** (3 tests)
   - API endpoints responding
   - Cluster health status

4. **Configuration Validation** (5 tests)
   - Config files exist
   - Volume mounts correct
   - Custom scripts loaded

5. **Detection Script Tests** (5 tests)
   - All Zeek scripts present
   - Script syntax valid

6. **Suricata Rule Tests** (2 tests)
   - Rule files loaded
   - Configuration valid

7. **Log Generation** (2 tests)
   - Zeek generating logs
   - Suricata generating logs

8. **Data Flow** (1 test)
   - Elasticsearch indexing data

**Total:** 26 automated tests

**Output:**
```
========================================
Network IDS - Detection Testing
========================================

=== Docker Infrastructure Tests ===
[Docker daemon running] PASS
[Docker Compose available] PASS
[IDS network exists] PASS

=== Zeek Detection Script Tests ===
[DNS tunneling script exists] PASS
[C2 beaconing script exists] PASS
[Lateral movement script exists] PASS
[Port scanning script exists] PASS
[TLS anomaly script exists] PASS

Test Summary
Passed: 26
Failed: 0

✓ All tests passed!
```

---

### **generate-traffic.sh**

Synthetic traffic generation for testing detection capabilities.

**Usage:**
```bash
# Generate normal traffic
./scripts/generate-traffic.sh --type normal

# Generate suspicious traffic
./scripts/generate-traffic.sh --type suspicious

# Generate specific attack pattern
./scripts/generate-traffic.sh --attack dns-tunneling

# Custom duration
./scripts/generate-traffic.sh --duration 300  # 5 minutes
```

**Traffic Types:**

**Normal Traffic:**
- HTTP/HTTPS requests to common sites
- DNS queries for legitimate domains
- SMTP/IMAP email traffic simulation
- SSH connections

**Suspicious Traffic:**
- Long DNS queries (tunneling simulation)
- Port scanning patterns
- Repeated failed SSH attempts
- Unusual TLS certificates

**Specific Attack Patterns:**
- `dns-tunneling` - High-entropy DNS queries
- `port-scan` - Systematic port probing
- `c2-beacon` - Periodic callback simulation
- `lateral-movement` - RDP/SMB attempts
- `web-attack` - SQL injection patterns

**Output:**
```
========================================
Traffic Generator
========================================

Mode: Suspicious Traffic
Duration: 60 seconds
Target: localhost

Generating traffic...
[12:34:56] DNS tunneling pattern (20 queries)
[12:35:01] Port scan simulation (50 ports)
[12:35:15] Failed SSH attempts (10 attempts)
[12:35:30] TLS anomaly (self-signed cert)

Traffic generation complete!

Check for detections:
  ./scripts/verify-deployment.sh
  Or view in Kibana: http://localhost:5601
```

---

## 💾 Backup and Maintenance

### **backup-data.sh**

Backup Elasticsearch indices and configuration.

**Usage:**
```bash
# Backup all data
./scripts/backup-data.sh

# Backup specific index pattern
./scripts/backup-data.sh --pattern "zeek-*"

# Backup to custom directory
./scripts/backup-data.sh --output /backup/nidzs-$(date +%Y%m%d)
```

**What gets backed up:**
- Elasticsearch indices (all matching patterns)
- Index mappings and settings
- Kibana dashboards and visualizations
- Configuration files
- Custom Zeek scripts
- Custom Suricata rules

**Backup Structure:**
```
backup-20241115-123456/
├── elasticsearch/
│   ├── indices/
│   │   ├── zeek-2024.11.15.json
│   │   ├── suricata-2024.11.15.json
│   │   └── filebeat-2024.11.15.json
│   └── mappings/
├── kibana/
│   └── dashboards.ndjson
├── configs/
│   ├── zeek-config/
│   └── suricata-config/
├── zeek-scripts/
└── suricata-rules/
```

**Restore Process:**
```bash
# Restore from backup
./scripts/restore-data.sh backup-20241115-123456/

# Verify restoration
./scripts/verify-deployment.sh
```

---

## 🛠️ Script Development Guidelines

### Adding New Scripts

**1. Script Template:**
```bash
#!/bin/bash
# Script Name and Purpose
# Author: Your Name
# Version: 1.0.0

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Functions
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  --help     Show this help message"
    exit 0
}

# Main logic
main() {
    echo -e "${GREEN}Starting script...${NC}"
    # Your code here
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --help) usage ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

main "$@"
```

**2. Make Executable:**
```bash
chmod +x scripts/new-script.sh
```

**3. Test Thoroughly:**
```bash
shellcheck scripts/new-script.sh  # Lint check
bash -n scripts/new-script.sh     # Syntax check
./scripts/new-script.sh --help    # Usage test
```

**4. Document:**
- Add to this README.md
- Include usage examples
- Document exit codes
- Provide troubleshooting tips

### Best Practices

**Error Handling:**
```bash
set -e                    # Exit on error
set -u                    # Exit on undefined variable
set -o pipefail          # Exit on pipe failure

# Or combine:
set -euo pipefail
```

**Logging:**
```bash
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"
}

log "Starting deployment..."
```

**Input Validation:**
```bash
if [ -z "$INPUT" ]; then
    echo "Error: INPUT is required"
    exit 1
fi
```

**Progress Indicators:**
```bash
echo -n "Waiting for service"
for i in {1..30}; do
    echo -n "."
    sleep 1
done
echo " Done!"
```

---

## 🔍 Troubleshooting

### Script Permission Denied

**Problem:**
```bash
./scripts/deploy.sh
-bash: ./scripts/deploy.sh: Permission denied
```

**Solution:**
```bash
chmod +x scripts/*.sh
```

### Docker Compose Not Found

**Problem:**
```
Error: docker-compose command not found
```

**Solution:**
```bash
# Install Docker Compose
sudo apt-get install docker-compose  # Ubuntu/Debian
brew install docker-compose           # macOS
```

### Service Fails to Start

**Diagnosis:**
```bash
# Check logs
docker-compose logs zeek
docker-compose logs suricata

# Check system resources
docker stats
free -h
df -h
```

**Common Solutions:**
- Increase Docker memory allocation
- Free up disk space
- Check configuration syntax
- Review error messages in logs

### Tests Failing

**If tests fail in test-detection.sh:**

1. **Check container status:**
   ```bash
   docker-compose ps
   ```

2. **Restart services:**
   ```bash
   docker-compose restart
   ```

3. **Check logs for errors:**
   ```bash
   docker-compose logs --tail=50 [service-name]
   ```

4. **Verify data generation:**
   ```bash
   # Generate some traffic
   ping -c 10 google.com

   # Wait 30 seconds
   sleep 30

   # Re-run tests
   ./scripts/test-detection.sh
   ```

---

## 📚 Additional Resources

- [Bash Scripting Guide](https://www.gnu.org/software/bash/manual/)
- [Docker Compose CLI Reference](https://docs.docker.com/compose/reference/)
- [ShellCheck - Shell Script Linter](https://www.shellcheck.net/)
- [Main Setup Guide](../SETUP.md)

---

## 🎯 Quick Reference

```bash
# Deploy everything
./scripts/deploy.sh

# Verify deployment
./scripts/verify-deployment.sh

# Run comprehensive tests
./scripts/test-detection.sh

# Generate test traffic
./scripts/generate-traffic.sh --type suspicious --duration 60

# Backup data
./scripts/backup-data.sh

# View logs
docker-compose logs -f zeek
docker-compose logs -f suricata

# Restart services
docker-compose restart

# Stop all services
docker-compose down

# Remove all data (WARNING: destructive)
docker-compose down -v
```

---

**Last Updated:** 2024-11-15
**Version:** 1.2.0
**Scripts Available:** 5 production-ready automation scripts
