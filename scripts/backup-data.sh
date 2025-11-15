#!/bin/bash
# Elasticsearch Data Backup Script
# Backs up Elasticsearch indices, Kibana objects, and configurations

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
ES_URL="${ES_URL:-http://localhost:9200}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-changeme}"
KIBANA_URL="${KIBANA_URL:-http://localhost:5601}"
BACKUP_DIR="${BACKUP_DIR:-./backups/backup-$(date +%Y%m%d-%H%M%S)}"
INDEX_PATTERN="${INDEX_PATTERN:-*}"

# Function to print header
print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}Network IDS - Backup Tool${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
}

# Function to show usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --output DIR      Output directory (default: ./backups/backup-TIMESTAMP)"
    echo "  --pattern PATTERN Index pattern to backup (default: *)"
    echo "  --indices-only    Backup only Elasticsearch indices"
    echo "  --config-only     Backup only configuration files"
    echo "  --help            Show this help message"
    echo ""
    echo "Examples:"
    echo "  # Full backup"
    echo "  $0"
    echo ""
    echo "  # Backup only Zeek indices"
    echo "  $0 --pattern 'zeek-*'"
    echo ""
    echo "  # Backup to specific directory"
    echo "  $0 --output /mnt/backup/nidzs-$(date +%Y%m%d)"
    echo ""
    echo "  # Config only backup"
    echo "  $0 --config-only"
    exit 0
}

# Check prerequisites
check_prerequisites() {
    echo -e "${YELLOW}Checking prerequisites...${NC}"

    # Check if jq is available
    if ! command -v jq >/dev/null 2>&1; then
        echo -e "${RED}Error: jq is required but not installed${NC}"
        echo "Install with: sudo apt install jq (Linux) or brew install jq (macOS)"
        exit 1
    fi

    # Check Elasticsearch availability
    if ! curl -s -u "${ES_USER}:${ES_PASS}" "${ES_URL}" >/dev/null 2>&1; then
        echo -e "${RED}Error: Cannot connect to Elasticsearch at ${ES_URL}${NC}"
        exit 1
    fi

    echo -e "${GREEN}✓ Prerequisites OK${NC}"
    echo ""
}

# Backup Elasticsearch indices
backup_elasticsearch_indices() {
    echo -e "${YELLOW}Backing up Elasticsearch indices...${NC}"

    local indices_dir="${BACKUP_DIR}/elasticsearch/indices"
    mkdir -p "$indices_dir"

    # Get list of indices matching pattern
    local indices=$(curl -s -u "${ES_USER}:${ES_PASS}" "${ES_URL}/_cat/indices/${INDEX_PATTERN}?h=index" 2>/dev/null)

    if [ -z "$indices" ]; then
        echo -e "${YELLOW}⚠ No indices found matching pattern: ${INDEX_PATTERN}${NC}"
        return
    fi

    echo "Found indices:"
    echo "$indices"
    echo ""

    local count=0
    while IFS= read -r index; do
        [ -z "$index" ] && continue

        echo -n "Backing up index: $index... "

        # Export index data
        curl -s -u "${ES_USER}:${ES_PASS}" \
            "${ES_URL}/${index}/_search?scroll=5m&size=1000" \
            -H 'Content-Type: application/json' \
            -d '{"query":{"match_all":{}}}' \
            > "${indices_dir}/${index}.json" 2>/dev/null

        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓${NC}"
            ((count++))
        else
            echo -e "${RED}✗${NC}"
        fi

        # Also backup index mapping
        curl -s -u "${ES_USER}:${ES_PASS}" \
            "${ES_URL}/${index}/_mapping" \
            > "${indices_dir}/${index}_mapping.json" 2>/dev/null

    done <<< "$indices"

    echo ""
    echo -e "${GREEN}✓ Backed up $count indices${NC}"
}

# Backup index mappings
backup_index_mappings() {
    echo -e "${YELLOW}Backing up index mappings...${NC}"

    local mappings_dir="${BACKUP_DIR}/elasticsearch/mappings"
    mkdir -p "$mappings_dir"

    curl -s -u "${ES_USER}:${ES_PASS}" \
        "${ES_URL}/_all/_mapping" \
        > "${mappings_dir}/all_mappings.json" 2>/dev/null

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Index mappings backed up${NC}"
    else
        echo -e "${RED}✗ Failed to backup mappings${NC}"
    fi
}

# Backup Kibana objects
backup_kibana_objects() {
    echo -e "${YELLOW}Backing up Kibana objects...${NC}"

    local kibana_dir="${BACKUP_DIR}/kibana"
    mkdir -p "$kibana_dir"

    # Export saved objects (dashboards, visualizations, searches)
    curl -s -X POST \
        -u "${ES_USER}:${ES_PASS}" \
        "${KIBANA_URL}/api/saved_objects/_export" \
        -H 'kbn-xsrf: true' \
        -H 'Content-Type: application/json' \
        -d '{
            "type": ["dashboard", "visualization", "search", "index-pattern"],
            "includeReferencesDeep": true
        }' \
        > "${kibana_dir}/saved_objects.ndjson" 2>/dev/null

    if [ $? -eq 0 ] && [ -s "${kibana_dir}/saved_objects.ndjson" ]; then
        echo -e "${GREEN}✓ Kibana objects backed up${NC}"
    else
        echo -e "${YELLOW}⚠ No Kibana objects found or export failed${NC}"
    fi
}

# Backup configuration files
backup_configurations() {
    echo -e "${YELLOW}Backing up configuration files...${NC}"

    local config_dir="${BACKUP_DIR}/configs"
    mkdir -p "$config_dir"

    # Backup Zeek configs
    if [ -d "./configs/zeek-config" ]; then
        echo -n "Zeek configuration... "
        cp -r "./configs/zeek-config" "${config_dir}/"
        echo -e "${GREEN}✓${NC}"
    fi

    # Backup Suricata configs
    if [ -d "./configs/suricata-config" ]; then
        echo -n "Suricata configuration... "
        cp -r "./configs/suricata-config" "${config_dir}/"
        echo -e "${GREEN}✓${NC}"
    fi

    # Backup Elasticsearch config
    if [ -d "./elasticsearch-kibana" ]; then
        echo -n "Elasticsearch/Kibana configuration... "
        mkdir -p "${config_dir}/elasticsearch-kibana"
        cp -r "./elasticsearch-kibana"/*.yml "${config_dir}/elasticsearch-kibana/" 2>/dev/null || true
        echo -e "${GREEN}✓${NC}"
    fi

    # Backup docker-compose.yml
    if [ -f "./docker-compose.yml" ]; then
        echo -n "Docker Compose configuration... "
        cp "./docker-compose.yml" "${config_dir}/"
        echo -e "${GREEN}✓${NC}"
    fi

    echo -e "${GREEN}✓ Configuration files backed up${NC}"
}

# Backup custom scripts and rules
backup_custom_content() {
    echo -e "${YELLOW}Backing up custom scripts and rules...${NC}"

    # Backup Zeek scripts
    if [ -d "./zeek-scripts" ]; then
        echo -n "Zeek custom scripts... "
        cp -r "./zeek-scripts" "${BACKUP_DIR}/"
        echo -e "${GREEN}✓${NC}"
    fi

    # Backup Suricata rules
    if [ -d "./suricata-rules" ]; then
        echo -n "Suricata custom rules... "
        cp -r "./suricata-rules" "${BACKUP_DIR}/"
        echo -e "${GREEN}✓${NC}"
    fi

    echo -e "${GREEN}✓ Custom content backed up${NC}"
}

# Create backup metadata
create_backup_metadata() {
    echo -e "${YELLOW}Creating backup metadata...${NC}"

    cat > "${BACKUP_DIR}/backup_info.json" <<EOF
{
    "backup_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "backup_version": "1.2.0",
    "elasticsearch_url": "${ES_URL}",
    "kibana_url": "${KIBANA_URL}",
    "index_pattern": "${INDEX_PATTERN}",
    "hostname": "$(hostname)",
    "user": "$(whoami)",
    "components": {
        "elasticsearch_indices": true,
        "elasticsearch_mappings": true,
        "kibana_objects": true,
        "configurations": true,
        "custom_scripts": true
    }
}
EOF

    echo -e "${GREEN}✓ Metadata created${NC}"
}

# Compress backup
compress_backup() {
    echo -e "${YELLOW}Compressing backup...${NC}"

    local parent_dir=$(dirname "$BACKUP_DIR")
    local backup_name=$(basename "$BACKUP_DIR")

    cd "$parent_dir"
    tar -czf "${backup_name}.tar.gz" "$backup_name" 2>/dev/null

    if [ $? -eq 0 ]; then
        local size=$(du -h "${backup_name}.tar.gz" | cut -f1)
        echo -e "${GREEN}✓ Backup compressed: ${backup_name}.tar.gz ($size)${NC}"

        # Optionally remove uncompressed backup
        read -p "Remove uncompressed backup? (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf "$backup_name"
            echo -e "${GREEN}✓ Uncompressed backup removed${NC}"
        fi
    else
        echo -e "${RED}✗ Compression failed${NC}"
    fi
}

# Display backup summary
display_summary() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}Backup Summary${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    echo "Backup Location: ${BACKUP_DIR}"
    echo ""

    if [ -d "$BACKUP_DIR" ]; then
        echo "Contents:"
        du -sh "${BACKUP_DIR}"/* 2>/dev/null | sed 's/^/  /'
        echo ""

        local total_size=$(du -sh "$BACKUP_DIR" | cut -f1)
        echo "Total Size: $total_size"
    fi

    echo ""
    echo -e "${GREEN}Backup complete!${NC}"
    echo ""
    echo "Restore with:"
    echo "  ./scripts/restore-data.sh ${BACKUP_DIR}"
}

# Main function
main() {
    print_header

    echo "Configuration:"
    echo "  Elasticsearch: ${ES_URL}"
    echo "  Kibana: ${KIBANA_URL}"
    echo "  Index Pattern: ${INDEX_PATTERN}"
    echo "  Output: ${BACKUP_DIR}"
    echo ""

    check_prerequisites

    # Create backup directory
    mkdir -p "$BACKUP_DIR"

    # Perform backup operations
    if [ "$INDICES_ONLY" = true ]; then
        backup_elasticsearch_indices
        backup_index_mappings
    elif [ "$CONFIG_ONLY" = true ]; then
        backup_configurations
        backup_custom_content
    else
        backup_elasticsearch_indices
        backup_index_mappings
        backup_kibana_objects
        backup_configurations
        backup_custom_content
    fi

    create_backup_metadata
    display_summary

    # Optionally compress
    read -p "Compress backup? (Y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        compress_backup
    fi

    echo ""
    echo -e "${GREEN}✓ All backup operations complete!${NC}"
}

# Parse arguments
INDICES_ONLY=false
CONFIG_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --output)
            BACKUP_DIR="$2"
            shift 2
            ;;
        --pattern)
            INDEX_PATTERN="$2"
            shift 2
            ;;
        --indices-only)
            INDICES_ONLY=true
            shift
            ;;
        --config-only)
            CONFIG_ONLY=true
            shift
            ;;
        --help)
            usage
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            usage
            ;;
    esac
done

main
