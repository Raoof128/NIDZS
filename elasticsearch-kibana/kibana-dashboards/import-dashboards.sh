#!/bin/bash
# Kibana Dashboard Import Script
# Automatically imports all dashboards into Kibana

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
KIBANA_URL="${KIBANA_URL:-http://localhost:5601}"
KIBANA_USER="${KIBANA_USER:-elastic}"
KIBANA_PASS="${KIBANA_PASS:-changeme}"
DASHBOARD_DIR="$(dirname "$0")"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Kibana Dashboard Import Tool${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${YELLOW}Configuration:${NC}"
echo -e "  Kibana URL: ${KIBANA_URL}"
echo -e "  Dashboard Directory: ${DASHBOARD_DIR}"
echo ""

# Function to check Kibana availability
check_kibana() {
    echo -n "Checking Kibana availability... "

    if curl -s -f -u "${KIBANA_USER}:${KIBANA_PASS}" "${KIBANA_URL}/api/status" > /dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}"
        return 0
    else
        echo -e "${RED}FAILED${NC}"
        echo -e "${RED}Error: Cannot connect to Kibana at ${KIBANA_URL}${NC}"
        echo "Please ensure:"
        echo "  1. Kibana is running"
        echo "  2. URL is correct (default: http://localhost:5601)"
        echo "  3. Credentials are correct (default: elastic/changeme)"
        exit 1
    fi
}

# Function to import dashboard
import_dashboard() {
    local dashboard_file=$1
    local dashboard_name=$(basename "$dashboard_file" .ndjson)

    echo -n "Importing ${dashboard_name}... "

    response=$(curl -s -w "\n%{http_code}" -X POST \
        "${KIBANA_URL}/api/saved_objects/_import?overwrite=true" \
        -u "${KIBANA_USER}:${KIBANA_PASS}" \
        -H "kbn-xsrf: true" \
        --form file=@"${dashboard_file}" 2>&1)

    http_code=$(echo "$response" | tail -n1)

    if [ "$http_code" = "200" ]; then
        echo -e "${GREEN}SUCCESS${NC}"
        return 0
    else
        echo -e "${RED}FAILED (HTTP $http_code)${NC}"
        return 1
    fi
}

# Main execution
main() {
    check_kibana

    echo ""
    echo -e "${YELLOW}Starting dashboard import...${NC}"
    echo ""

    # If specific dashboard provided as argument
    if [ $# -gt 0 ]; then
        dashboard_file="$1"
        if [ ! -f "$dashboard_file" ]; then
            dashboard_file="${DASHBOARD_DIR}/$1"
        fi

        if [ ! -f "$dashboard_file" ]; then
            echo -e "${RED}Error: Dashboard file not found: $1${NC}"
            exit 1
        fi

        import_dashboard "$dashboard_file"
    else
        # Import all dashboards in directory
        dashboard_count=0
        success_count=0

        for dashboard in "${DASHBOARD_DIR}"/*.ndjson; do
            if [ -f "$dashboard" ]; then
                ((dashboard_count++))
                if import_dashboard "$dashboard"; then
                    ((success_count++))
                fi
            fi
        done

        echo ""
        echo -e "${BLUE}========================================${NC}"
        echo -e "${BLUE}Import Summary${NC}"
        echo -e "${BLUE}========================================${NC}"
        echo -e "Total dashboards: ${dashboard_count}"
        echo -e "${GREEN}Successful: ${success_count}${NC}"
        echo -e "${RED}Failed: $((dashboard_count - success_count))${NC}"

        if [ $success_count -eq $dashboard_count ] && [ $dashboard_count -gt 0 ]; then
            echo ""
            echo -e "${GREEN}✓ All dashboards imported successfully!${NC}"
            echo ""
            echo "Access your dashboards at:"
            echo "  ${KIBANA_URL}/app/dashboards"
        elif [ $dashboard_count -eq 0 ]; then
            echo ""
            echo -e "${YELLOW}⚠ No dashboard files (.ndjson) found in ${DASHBOARD_DIR}${NC}"
            echo ""
            echo "Please ensure dashboard files are present and have .ndjson extension"
        fi
    fi
}

# Run main function
main "$@"
