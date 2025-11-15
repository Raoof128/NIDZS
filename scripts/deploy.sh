#!/bin/bash
# Network IDS - Automated Deployment Script
# Author: Raouf

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Network IDS - Automated Deployment${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Check if running as root (for Linux)
if [[ "$OSTYPE" == "linux-gnu"* ]] && [[ $EUID -ne 0 ]]; then
   echo -e "${YELLOW}Note: Some operations may require sudo privileges${NC}"
fi

# Check prerequisites
echo -e "${GREEN}[1/8] Checking prerequisites...${NC}"

command -v docker >/dev/null 2>&1 || { echo -e "${RED}Error: docker is not installed${NC}" >&2; exit 1; }
command -v docker-compose >/dev/null 2>&1 || { echo -e "${RED}Error: docker-compose is not installed${NC}" >&2; exit 1; }

echo -e "${GREEN}✓ Docker found: $(docker --version)${NC}"
echo -e "${GREEN}✓ Docker Compose found: $(docker-compose --version)${NC}"
echo ""

# Create necessary directories
echo -e "${GREEN}[2/8] Creating directory structure...${NC}"

mkdir -p elasticsearch-kibana/data/elasticsearch
mkdir -p elasticsearch-kibana/data/kibana
mkdir -p elasticsearch-kibana/data/filebeat
mkdir -p logs/zeek logs/suricata
mkdir -p sample-traffic

# Set permissions (Linux only)
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo -e "${YELLOW}Setting directory permissions...${NC}"
    sudo chown -R 1000:1000 elasticsearch-kibana/data/elasticsearch 2>/dev/null || true
    sudo chown -R 1000:1000 elasticsearch-kibana/data/kibana 2>/dev/null || true
    chmod -R 777 logs
fi

echo -e "${GREEN}✓ Directories created${NC}"
echo ""

# Configure vm.max_map_count for Elasticsearch (Linux only)
echo -e "${GREEN}[3/8] Configuring system settings...${NC}"

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    CURRENT_MAX_MAP=$(sysctl -n vm.max_map_count 2>/dev/null || echo "0")
    if [ "$CURRENT_MAX_MAP" -lt 262144 ]; then
        echo -e "${YELLOW}Increasing vm.max_map_count for Elasticsearch...${NC}"
        sudo sysctl -w vm.max_map_count=262144
        echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
    fi
    echo -e "${GREEN}✓ vm.max_map_count = $(sysctl -n vm.max_map_count)${NC}"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo -e "${YELLOW}macOS detected - ensure Docker Desktop has adequate resources:${NC}"
    echo -e "${YELLOW}  - Memory: 8GB minimum (16GB recommended)${NC}"
    echo -e "${YELLOW}  - CPU: 4 cores minimum${NC}"
fi
echo ""

# Create Docker network
echo -e "${GREEN}[4/8] Creating Docker network...${NC}"
docker network create ids-network 2>/dev/null || echo -e "${YELLOW}Network already exists${NC}"
echo -e "${GREEN}✓ Network ready${NC}"
echo ""

# Build custom images
echo -e "${GREEN}[5/8] Building custom Docker images...${NC}"
echo -e "${YELLOW}This may take several minutes...${NC}"

# Build Zeek image
if [ -f "configs/zeek-config/Dockerfile" ]; then
    echo -e "${YELLOW}Building Zeek image...${NC}"
    docker-compose build zeek
    echo -e "${GREEN}✓ Zeek image built${NC}"
fi

# Build Suricata image
if [ -f "configs/suricata-config/Dockerfile" ]; then
    echo -e "${YELLOW}Building Suricata image...${NC}"
    docker-compose build suricata
    echo -e "${GREEN}✓ Suricata image built${NC}"
fi
echo ""

# Pull remaining images
echo -e "${GREEN}[6/8] Pulling Docker images...${NC}"
docker-compose pull elasticsearch kibana filebeat
echo -e "${GREEN}✓ Images pulled${NC}"
echo ""

# Start services
echo -e "${GREEN}[7/8] Starting services...${NC}"

echo -e "${YELLOW}Starting Elasticsearch...${NC}"
docker-compose up -d elasticsearch

echo -e "${YELLOW}Waiting for Elasticsearch to be ready (60-90 seconds)...${NC}"
sleep 30
for i in {1..12}; do
    if curl -s -u elastic:changeme http://localhost:9200/_cluster/health >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Elasticsearch is ready${NC}"
        break
    fi
    echo -n "."
    sleep 5
done
echo ""

echo -e "${YELLOW}Starting remaining services...${NC}"
docker-compose up -d kibana filebeat zeek suricata

echo -e "${YELLOW}Waiting for services to initialize (30 seconds)...${NC}"
sleep 30
echo -e "${GREEN}✓ All services started${NC}"
echo ""

# Verify deployment
echo -e "${GREEN}[8/8] Verifying deployment...${NC}"

echo -n "Checking Elasticsearch... "
if curl -s -u elastic:changeme http://localhost:9200/_cluster/health | grep -q '"status":"green\|yellow"'; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
fi

echo -n "Checking Kibana... "
if curl -s http://localhost:5601/api/status | grep -q '"state":"green"'; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${YELLOW}⚠ (still initializing)${NC}"
fi

echo -n "Checking Zeek... "
if docker-compose ps zeek | grep -q "Up"; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
fi

echo -n "Checking Suricata... "
if docker-compose ps suricata | grep -q "Up"; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
fi

echo -n "Checking Filebeat... "
if docker-compose ps filebeat | grep -q "Up"; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Deployment Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${GREEN}Access Points:${NC}"
echo -e "  Kibana:        http://localhost:5601"
echo -e "  Elasticsearch: http://localhost:9200"
echo -e "  Credentials:   elastic / changeme"
echo ""
echo -e "${YELLOW}⚠  IMPORTANT: Change default password in production!${NC}"
echo ""
echo -e "${GREEN}Next Steps:${NC}"
echo -e "  1. Wait 2-3 minutes for full initialization"
echo -e "  2. Access Kibana at http://localhost:5601"
echo -e "  3. Run verification: ./scripts/verify-deployment.sh"
echo -e "  4. Review logs: docker-compose logs -f"
echo ""
echo -e "${GREEN}Documentation:${NC}"
echo -e "  - Setup Guide:  SETUP.md"
echo -e "  - Architecture: ARCHITECTURE.md"
echo -e "  - Main README:  README.md"
echo ""
