#!/bin/bash
# Network IDS - Deployment Verification Script
# Author: Raouf

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Network IDS - Deployment Verification${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

PASS=0
FAIL=0
WARN=0

# Function to check service
check_service() {
    local service=$1
    local check_command=$2
    local description=$3

    echo -n "[$description] "

    if eval "$check_command" >/dev/null 2>&1; then
        echo -e "${GREEN}PASS${NC}"
        ((PASS++))
        return 0
    else
        echo -e "${RED}FAIL${NC}"
        ((FAIL++))
        return 1
    fi
}

# Function to check with warning
check_warn() {
    local service=$1
    local check_command=$2
    local description=$3

    echo -n "[$description] "

    if eval "$check_command" >/dev/null 2>&1; then
        echo -e "${GREEN}PASS${NC}"
        ((PASS++))
        return 0
    else
        echo -e "${YELLOW}WARN${NC}"
        ((WARN++))
        return 1
    fi
}

echo -e "${YELLOW}Running verification checks...${NC}"
echo ""

# Docker checks
echo -e "${GREEN}=== Docker Environment ===${NC}"
check_service "docker" "docker ps" "Docker daemon running"
check_service "docker-compose" "docker-compose ps" "Docker Compose working"
check_service "network" "docker network inspect ids-network" "IDS network exists"
echo ""

# Container health checks
echo -e "${GREEN}=== Container Status ===${NC}"
check_service "elasticsearch" "docker-compose ps elasticsearch | grep -q Up" "Elasticsearch container"
check_service "kibana" "docker-compose ps kibana | grep -q Up" "Kibana container"
check_service "zeek" "docker-compose ps zeek | grep -q Up" "Zeek container"
check_service "suricata" "docker-compose ps suricata | grep -q Up" "Suricata container"
check_service "filebeat" "docker-compose ps filebeat | grep -q Up" "Filebeat container"
echo ""

# Service health checks
echo -e "${GREEN}=== Service Health ===${NC}"
check_service "es-health" "curl -s -u elastic:changeme http://localhost:9200/_cluster/health | grep -q '\"status\":\"green\\|yellow\"'" "Elasticsearch cluster health"
check_warn "kibana-health" "curl -s http://localhost:5601/api/status | grep -q '\"state\":\"green\"'" "Kibana API status"
echo ""

# Data flow checks
echo -e "${GREEN}=== Data Flow ===${NC}"

# Check Zeek logs
if docker-compose exec zeek ls /opt/zeek/logs/current/ 2>/dev/null | grep -q ".log"; then
    echo -e "[Zeek generating logs] ${GREEN}PASS${NC}"
    ((PASS++))
else
    echo -e "[Zeek generating logs] ${YELLOW}WARN${NC} (may need time to generate)"
    ((WARN++))
fi

# Check Suricata logs
if docker-compose exec suricata ls /var/log/suricata/ 2>/dev/null | grep -q "eve.json"; then
    echo -e "[Suricata generating logs] ${GREEN}PASS${NC}"
    ((PASS++))
else
    echo -e "[Suricata generating logs] ${YELLOW}WARN${NC} (may need traffic)"
    ((WARN++))
fi

# Check Elasticsearch indices
ES_INDICES=$(curl -s -u elastic:changeme "http://localhost:9200/_cat/indices?format=json" 2>/dev/null | grep -c "zeek\|suricata" || echo "0")
if [ "$ES_INDICES" -gt 0 ]; then
    echo -e "[Elasticsearch indices created] ${GREEN}PASS${NC} ($ES_INDICES indices)"
    ((PASS++))
else
    echo -e "[Elasticsearch indices created] ${YELLOW}WARN${NC} (may need time)"
    ((WARN++))
fi

# Check Filebeat shipping
if docker-compose logs filebeat 2>/dev/null | grep -q "Publish event"; then
    echo -e "[Filebeat shipping logs] ${GREEN}PASS${NC}"
    ((PASS++))
else
    echo -e "[Filebeat shipping logs] ${YELLOW}WARN${NC} (may need traffic)"
    ((WARN++))
fi
echo ""

# Resource checks
echo -e "${GREEN}=== Resource Usage ===${NC}"

# Get container stats
echo "Container resource usage:"
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" ids-elasticsearch ids-kibana ids-zeek ids-suricata ids-filebeat 2>/dev/null || echo -e "${YELLOW}Unable to get stats${NC}"
echo ""

# Port checks
echo -e "${GREEN}=== Port Accessibility ===${NC}"
check_service "es-port" "nc -z localhost 9200" "Elasticsearch port 9200"
check_service "kibana-port" "nc -z localhost 5601" "Kibana port 5601"
echo ""

# Configuration checks
echo -e "${GREEN}=== Configuration ===${NC}"
check_service "zeek-config" "docker-compose exec zeek test -f /opt/zeek/share/zeek/site/local.zeek" "Zeek configuration loaded"
check_service "suricata-config" "docker-compose exec suricata test -f /etc/suricata/suricata.yaml" "Suricata configuration loaded"
check_service "filebeat-config" "docker-compose exec filebeat test -f /usr/share/filebeat/filebeat.yml" "Filebeat configuration loaded"
echo ""

# Custom scripts check
echo -e "${GREEN}=== Custom Detection Scripts ===${NC}"
check_warn "zeek-dns-tunnel" "docker-compose exec zeek test -f /opt/zeek/share/zeek/site/custom/detect_dns_tunneling.zeek" "Zeek DNS tunneling script"
check_warn "zeek-c2-beacon" "docker-compose exec zeek test -f /opt/zeek/share/zeek/site/custom/detect_c2_beaconing.zeek" "Zeek C2 beaconing script"
check_warn "zeek-lateral" "docker-compose exec zeek test -f /opt/zeek/share/zeek/site/custom/detect_lateral_movement.zeek" "Zeek lateral movement script"

# Count Suricata rules
RULE_COUNT=$(docker-compose exec suricata find /etc/suricata/rules -name "*.rules" -type f 2>/dev/null | wc -l || echo "0")
if [ "$RULE_COUNT" -gt 0 ]; then
    echo -e "[Custom Suricata rules] ${GREEN}PASS${NC} ($RULE_COUNT rule files)"
    ((PASS++))
else
    echo -e "[Custom Suricata rules] ${YELLOW}WARN${NC}"
    ((WARN++))
fi
echo ""

# Summary
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Verification Summary${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Passed: $PASS${NC}"
echo -e "${YELLOW}Warnings: $WARN${NC}"
echo -e "${RED}Failed: $FAIL${NC}"
echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}✓ Deployment verification successful!${NC}"
    echo ""
    echo -e "${GREEN}System is ready for use.${NC}"
    echo -e "Access Kibana: http://localhost:5601 (elastic/changeme)"
    echo ""

    if [ $WARN -gt 0 ]; then
        echo -e "${YELLOW}Note: Some warnings are normal for new deployments.${NC}"
        echo -e "${YELLOW}Wait 5-10 minutes and re-run this script.${NC}"
    fi

    exit 0
else
    echo -e "${RED}✗ Deployment has issues that need attention.${NC}"
    echo ""
    echo -e "${YELLOW}Troubleshooting:${NC}"
    echo -e "  1. Check logs: docker-compose logs"
    echo -e "  2. Review SETUP.md troubleshooting section"
    echo -e "  3. Ensure adequate resources (8GB RAM, 4 CPU cores)"
    echo ""
    exit 1
fi
