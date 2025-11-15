#!/bin/bash
# Network IDS - Detection Testing Script
# Tests that custom detection rules are working

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Network IDS - Detection Testing${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

TESTS_PASSED=0
TESTS_FAILED=0

# Function to run test
run_test() {
    local test_name=$1
    local test_command=$2
    local expected_result=$3

    echo -n "[Testing: $test_name] "

    if eval "$test_command" >/dev/null 2>&1; then
        if [ "$expected_result" = "pass" ]; then
            echo -e "${GREEN}PASS${NC}"
            ((TESTS_PASSED++))
        else
            echo -e "${RED}FAIL${NC} (expected failure)"
            ((TESTS_FAILED++))
        fi
    else
        if [ "$expected_result" = "fail" ]; then
            echo -e "${GREEN}PASS${NC} (expected failure)"
            ((TESTS_PASSED++))
        else
            echo -e "${RED}FAIL${NC}"
            ((TESTS_FAILED++))
        fi
    fi
}

echo -e "${YELLOW}=== Docker Infrastructure Tests ===${NC}"

run_test "Docker daemon running" "docker ps" "pass"
run_test "Docker Compose available" "docker-compose ps" "pass"
run_test "IDS network exists" "docker network inspect ids-network" "pass"

echo ""
echo -e "${YELLOW}=== Container Health Tests ===${NC}"

run_test "Elasticsearch container running" "docker-compose ps elasticsearch | grep -q Up" "pass"
run_test "Kibana container running" "docker-compose ps kibana | grep -q Up" "pass"
run_test "Zeek container running" "docker-compose ps zeek | grep -q Up" "pass"
run_test "Suricata container running" "docker-compose ps suricata | grep -q Up" "pass"
run_test "Filebeat container running" "docker-compose ps filebeat | grep -q Up" "pass"

echo ""
echo -e "${YELLOW}=== Service Health Tests ===${NC}"

run_test "Elasticsearch API responding" "curl -s -u elastic:changeme http://localhost:9200" "pass"
run_test "Elasticsearch cluster healthy" "curl -s -u elastic:changeme http://localhost:9200/_cluster/health | grep -q '\"status\":\"green\\|yellow\"'" "pass"
run_test "Kibana API responding" "curl -s http://localhost:5601/api/status" "pass"

echo ""
echo -e "${YELLOW}=== Configuration Tests ===${NC}"

run_test "Zeek config exists" "docker-compose exec zeek test -f /opt/zeek/share/zeek/site/local.zeek" "pass"
run_test "Zeek custom scripts mounted" "docker-compose exec zeek test -d /opt/zeek/share/zeek/site/custom" "pass"
run_test "Suricata config exists" "docker-compose exec suricata test -f /etc/suricata/suricata.yaml" "pass"
run_test "Suricata rules mounted" "docker-compose exec suricata test -d /etc/suricata/rules" "pass"
run_test "Filebeat config exists" "docker-compose exec filebeat test -f /usr/share/filebeat/filebeat.yml" "pass"

echo ""
echo -e "${YELLOW}=== Zeek Detection Script Tests ===${NC}"

run_test "DNS tunneling script exists" "docker-compose exec zeek test -f /opt/zeek/share/zeek/site/custom/detect_dns_tunneling.zeek" "pass"
run_test "C2 beaconing script exists" "docker-compose exec zeek test -f /opt/zeek/share/zeek/site/custom/detect_c2_beaconing.zeek" "pass"
run_test "Lateral movement script exists" "docker-compose exec zeek test -f /opt/zeek/share/zeek/site/custom/detect_lateral_movement.zeek" "pass"
run_test "Port scanning script exists" "docker-compose exec zeek test -f /opt/zeek/share/zeek/site/custom/detect_port_scanning.zeek" "pass"
run_test "TLS anomaly script exists" "docker-compose exec zeek test -f /opt/zeek/share/zeek/site/custom/detect_tls_anomalies.zeek" "pass"

echo ""
echo -e "${YELLOW}=== Suricata Rule Tests ===${NC}"

RULE_COUNT=$(docker-compose exec suricata find /etc/suricata/rules -name "*.rules" -type f 2>/dev/null | wc -l || echo "0")
if [ "$RULE_COUNT" -ge 5 ]; then
    echo -e "[Suricata rule files loaded] ${GREEN}PASS${NC} ($RULE_COUNT files)"
    ((TESTS_PASSED++))
else
    echo -e "[Suricata rule files loaded] ${RED}FAIL${NC} (found $RULE_COUNT, expected 5+)"
    ((TESTS_FAILED++))
fi

# Validate Suricata config
echo -n "[Suricata config validation] "
if docker-compose exec suricata suricata -T -c /etc/suricata/suricata.yaml 2>&1 | grep -q "successfully"; then
    echo -e "${GREEN}PASS${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}FAIL${NC}"
    ((TESTS_FAILED++))
fi

echo ""
echo -e "${YELLOW}=== Log Generation Tests ===${NC}"

# Check if logs are being generated
sleep 5

if docker-compose exec zeek ls /opt/zeek/logs/current/ 2>/dev/null | grep -q ".log"; then
    echo -e "[Zeek generating logs] ${GREEN}PASS${NC}"
    ((TESTS_PASSED++))
else
    echo -e "[Zeek generating logs] ${YELLOW}WARN${NC} (may need traffic)"
fi

if docker-compose exec suricata ls /var/log/suricata/ 2>/dev/null | grep -q "eve.json\|fast.log"; then
    echo -e "[Suricata generating logs] ${GREEN}PASS${NC}"
    ((TESTS_PASSED++))
else
    echo -e "[Suricata generating logs] ${YELLOW}WARN${NC} (may need traffic)"
fi

echo ""
echo -e "${YELLOW}=== Data Flow Tests ===${NC}"

# Check Elasticsearch indices
ES_INDICES=$(curl -s -u elastic:changeme "http://localhost:9200/_cat/indices?format=json" 2>/dev/null | grep -c "filebeat\|zeek\|suricata" || echo "0")
if [ "$ES_INDICES" -gt 0 ]; then
    echo -e "[Elasticsearch indices created] ${GREEN}PASS${NC} ($ES_INDICES indices)"
    ((TESTS_PASSED++))
else
    echo -e "[Elasticsearch indices created] ${YELLOW}WARN${NC} (may need time)"
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Test Summary${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed. Check the output above.${NC}"
    exit 1
fi
