#!/bin/bash
# Performance Metrics Collection Script
# Collects comprehensive performance metrics from Network IDS deployment

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
OUTPUT_DIR="${OUTPUT_DIR:-./metrics-$(date +%Y%m%d-%H%M%S)}"
INTERVAL="${INTERVAL:-60}"  # Collection interval in seconds
DURATION="${DURATION:-3600}"  # Total duration in seconds (default 1 hour)
ES_URL="${ES_URL:-http://localhost:9200}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-changeme}"

# Function to print header
print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}Network IDS - Performance Metrics${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
}

# Function to check prerequisites
check_prerequisites() {
    echo -e "${YELLOW}Checking prerequisites...${NC}"

    # Check if Docker is running
    if ! docker ps >/dev/null 2>&1; then
        echo -e "${RED}Error: Docker is not running${NC}"
        exit 1
    fi

    # Check if containers are running
    local containers=("elasticsearch" "kibana" "zeek" "suricata" "filebeat")
    for container in "${containers[@]}"; do
        if ! docker-compose ps | grep -q "$container.*Up"; then
            echo -e "${RED}Warning: $container container is not running${NC}"
        fi
    done

    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    echo -e "${GREEN}✓ Prerequisites checked${NC}"
    echo ""
}

# Function to collect Docker stats
collect_docker_stats() {
    local timestamp=$(date +%s)

    echo -e "${YELLOW}Collecting Docker container stats...${NC}"

    docker stats --no-stream --format \
        '{"timestamp":'$timestamp',"container":"{{.Name}}","cpu":"{{.CPUPerc}}","memory":"{{.MemUsage}}","net_io":"{{.NetIO}}","block_io":"{{.BlockIO}}"}' \
        >> "$OUTPUT_DIR/docker_stats.jsonl"

    echo -e "${GREEN}✓ Docker stats collected${NC}"
}

# Function to collect Zeek statistics
collect_zeek_stats() {
    local timestamp=$(date +%s)

    echo -e "${YELLOW}Collecting Zeek performance stats...${NC}"

    # Get Zeek netstats
    if docker-compose exec -T zeek zeekctl netstats 2>/dev/null > /tmp/zeek_netstats.txt; then
        {
            echo -n '{"timestamp":'$timestamp',"type":"netstats","data":"'
            cat /tmp/zeek_netstats.txt | tr '\n' ' ' | sed 's/"/\\"/g'
            echo '"}'
        } >> "$OUTPUT_DIR/zeek_stats.jsonl"

        echo -e "${GREEN}✓ Zeek stats collected${NC}"
    else
        echo -e "${YELLOW}⚠ Could not collect Zeek stats${NC}"
    fi
}

# Function to collect Suricata statistics
collect_suricata_stats() {
    local timestamp=$(date +%s)

    echo -e "${YELLOW}Collecting Suricata performance stats...${NC}"

    # Get latest stats from Suricata stats.log
    if docker-compose exec -T suricata tail -20 /var/log/suricata/stats.log 2>/dev/null > /tmp/suricata_stats.txt; then
        {
            echo -n '{"timestamp":'$timestamp',"type":"stats","data":"'
            cat /tmp/suricata_stats.txt | tr '\n' ' ' | sed 's/"/\\"/g'
            echo '"}'
        } >> "$OUTPUT_DIR/suricata_stats.jsonl"

        echo -e "${GREEN}✓ Suricata stats collected${NC}"
    else
        echo -e "${YELLOW}⚠ Could not collect Suricata stats${NC}"
    fi
}

# Function to collect Elasticsearch metrics
collect_elasticsearch_stats() {
    local timestamp=$(date +%s)

    echo -e "${YELLOW}Collecting Elasticsearch stats...${NC}"

    # Cluster health
    curl -s -u "${ES_USER}:${ES_PASS}" "${ES_URL}/_cluster/health" 2>/dev/null | \
        jq -c ". + {timestamp: $timestamp}" >> "$OUTPUT_DIR/es_health.jsonl" || \
        echo -e "${YELLOW}⚠ Could not collect ES cluster health${NC}"

    # Node stats
    curl -s -u "${ES_USER}:${ES_PASS}" "${ES_URL}/_nodes/stats/jvm,process,os,indices" 2>/dev/null | \
        jq -c ".nodes | to_entries[] | {timestamp: $timestamp, node: .key, stats: .value}" >> "$OUTPUT_DIR/es_nodes.jsonl" || \
        echo -e "${YELLOW}⚠ Could not collect ES node stats${NC}"

    # Index stats
    curl -s -u "${ES_USER}:${ES_PASS}" "${ES_URL}/_cat/indices?format=json" 2>/dev/null | \
        jq -c ".[] | . + {timestamp: $timestamp}" >> "$OUTPUT_DIR/es_indices.jsonl" || \
        echo -e "${YELLOW}⚠ Could not collect ES index stats${NC}"

    echo -e "${GREEN}✓ Elasticsearch stats collected${NC}"
}

# Function to collect alert metrics
collect_alert_metrics() {
    local timestamp=$(date +%s)

    echo -e "${YELLOW}Collecting alert metrics...${NC}"

    # Alert count by severity
    curl -s -u "${ES_USER}:${ES_PASS}" "${ES_URL}/suricata-*/_search?size=0" \
        -H 'Content-Type: application/json' \
        -d '{
            "aggs": {
                "severity": {
                    "terms": {"field": "alert.severity.keyword"}
                }
            }
        }' 2>/dev/null | \
        jq -c ". + {timestamp: $timestamp}" >> "$OUTPUT_DIR/alert_severity.jsonl" || \
        echo -e "${YELLOW}⚠ Could not collect alert severity stats${NC}"

    # Alert count by category
    curl -s -u "${ES_USER}:${ES_PASS}" "${ES_URL}/suricata-*/_search?size=0" \
        -H 'Content-Type: application/json' \
        -d '{
            "aggs": {
                "category": {
                    "terms": {"field": "alert.category.keyword"}
                }
            }
        }' 2>/dev/null | \
        jq -c ". + {timestamp: $timestamp}" >> "$OUTPUT_DIR/alert_category.jsonl" || \
        echo -e "${YELLOW}⚠ Could not collect alert category stats${NC}"

    echo -e "${GREEN}✓ Alert metrics collected${NC}"
}

# Function to collect system metrics
collect_system_metrics() {
    local timestamp=$(date +%s)

    echo -e "${YELLOW}Collecting system metrics...${NC}"

    # CPU usage
    {
        echo -n '{"timestamp":'$timestamp',"cpu_usage":'
        top -bn1 | grep "Cpu(s)" | awk '{print $2}' | tr -d '%us,'
        echo '}'
    } >> "$OUTPUT_DIR/system_cpu.jsonl"

    # Memory usage
    {
        echo -n '{"timestamp":'$timestamp',"memory":'
        free -m | awk 'NR==2{printf "{\"total\":%s,\"used\":%s,\"free\":%s,\"percent\":%.2f}", $2,$3,$4,$3*100/$2 }'
        echo '}'
    } >> "$OUTPUT_DIR/system_memory.jsonl"

    # Disk I/O (if iostat available)
    if command -v iostat >/dev/null 2>&1; then
        {
            echo -n '{"timestamp":'$timestamp',"disk_io":"'
            iostat -x 1 2 | tail -5 | tr '\n' ' ' | sed 's/"/\\"/g'
            echo '"}'
        } >> "$OUTPUT_DIR/system_disk.jsonl"
    fi

    echo -e "${GREEN}✓ System metrics collected${NC}"
}

# Function to generate summary report
generate_summary() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}Collection Summary${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""

    echo -e "${GREEN}Metrics collected in: ${OUTPUT_DIR}${NC}"
    echo ""
    echo "Files created:"
    ls -lh "$OUTPUT_DIR"
    echo ""

    # Count data points
    if [ -f "$OUTPUT_DIR/docker_stats.jsonl" ]; then
        local count=$(wc -l < "$OUTPUT_DIR/docker_stats.jsonl")
        echo "Docker stats: $count data points"
    fi

    if [ -f "$OUTPUT_DIR/es_health.jsonl" ]; then
        local count=$(wc -l < "$OUTPUT_DIR/es_health.jsonl")
        echo "ES health checks: $count data points"
    fi

    echo ""
    echo -e "${YELLOW}Analysis Commands:${NC}"
    echo ""
    echo "# View Docker CPU usage:"
    echo "cat $OUTPUT_DIR/docker_stats.jsonl | jq -r '.container + \": \" + .cpu'"
    echo ""
    echo "# View ES cluster health:"
    echo "cat $OUTPUT_DIR/es_health.jsonl | jq '.status'"
    echo ""
    echo "# Calculate average CPU (container):"
    echo "cat $OUTPUT_DIR/docker_stats.jsonl | jq -r 'select(.container==\"zeek\") | .cpu' | sed 's/%//' | awk '{sum+=\$1; count++} END {print \"Average: \" sum/count \"%\"}'"
    echo ""
}

# Main collection loop
main() {
    print_header

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --duration)
                DURATION="$2"
                shift 2
                ;;
            --interval)
                INTERVAL="$2"
                shift 2
                ;;
            --output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --duration SECONDS    Total collection duration (default: 3600)"
                echo "  --interval SECONDS    Collection interval (default: 60)"
                echo "  --output DIR          Output directory (default: ./metrics-TIMESTAMP)"
                echo "  --help                Show this help message"
                echo ""
                echo "Examples:"
                echo "  # Collect for 1 hour (default)"
                echo "  $0"
                echo ""
                echo "  # Collect for 24 hours at 5-minute intervals"
                echo "  $0 --duration 86400 --interval 300"
                echo ""
                echo "  # Quick 5-minute test"
                echo "  $0 --duration 300 --interval 30"
                exit 0
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done

    echo "Configuration:"
    echo "  Duration: ${DURATION}s ($(($DURATION / 60)) minutes)"
    echo "  Interval: ${INTERVAL}s"
    echo "  Output: ${OUTPUT_DIR}"
    echo ""

    check_prerequisites

    # Calculate iterations
    local iterations=$((DURATION / INTERVAL))
    local current=0

    echo -e "${GREEN}Starting metrics collection...${NC}"
    echo "Press Ctrl+C to stop early"
    echo ""

    # Collection loop
    while [ $current -lt $iterations ]; do
        local progress=$(( (current * 100) / iterations ))
        echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] Collection ${current}/${iterations} (${progress}%)${NC}"
        echo ""

        # Collect all metrics
        collect_docker_stats
        collect_zeek_stats
        collect_suricata_stats
        collect_elasticsearch_stats
        collect_alert_metrics
        collect_system_metrics

        echo ""

        # Increment counter
        ((current++))

        # Sleep if not last iteration
        if [ $current -lt $iterations ]; then
            echo -e "${YELLOW}Sleeping for ${INTERVAL}s until next collection...${NC}"
            echo ""
            sleep "$INTERVAL"
        fi
    done

    generate_summary

    echo -e "${GREEN}✓ Metrics collection complete!${NC}"
}

# Run main function
main "$@"
