#!/bin/bash
# Network Traffic Generator
# Generates synthetic network traffic for testing detection capabilities

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
TRAFFIC_TYPE="${TRAFFIC_TYPE:-normal}"
DURATION="${DURATION:-60}"
TARGET="${TARGET:-8.8.8.8}"

# Function to print header
print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}Network Traffic Generator${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
}

# Function to show usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --type TYPE       Traffic type: normal, suspicious, attack (default: normal)"
    echo "  --duration SECS   Duration in seconds (default: 60)"
    echo "  --attack NAME     Specific attack pattern to generate"
    echo "  --target IP       Target IP for traffic (default: 8.8.8.8)"
    echo "  --help            Show this help message"
    echo ""
    echo "Traffic Types:"
    echo "  normal           Normal business traffic (HTTP, DNS, SSH)"
    echo "  suspicious       Suspicious but not clearly malicious traffic"
    echo "  attack           Clear attack patterns"
    echo ""
    echo "Attack Patterns:"
    echo "  dns-tunneling    High-entropy DNS queries"
    echo "  port-scan        Systematic port scanning"
    echo "  c2-beacon        Periodic callback simulation"
    echo "  lateral-movement RDP/SMB connection attempts"
    echo "  web-attack       SQL injection and XSS patterns"
    echo ""
    echo "Examples:"
    echo "  # Generate normal traffic for 60 seconds"
    echo "  $0 --type normal --duration 60"
    echo ""
    echo "  # Generate DNS tunneling attack pattern"
    echo "  $0 --attack dns-tunneling --duration 120"
    echo ""
    echo "  # Generate port scan"
    echo "  $0 --attack port-scan --target 192.168.1.100"
    exit 0
}

# Generate normal traffic
generate_normal_traffic() {
    echo -e "${GREEN}Generating normal traffic...${NC}"
    local end_time=$((SECONDS + DURATION))

    while [ $SECONDS -lt $end_time ]; do
        local timestamp=$(date +'%H:%M:%S')

        # HTTP/HTTPS requests
        if command -v curl >/dev/null 2>&1; then
            echo -e "${YELLOW}[$timestamp]${NC} HTTP request to google.com"
            curl -s -o /dev/null http://www.google.com 2>/dev/null || true
        fi

        sleep 2

        # DNS queries
        if command -v dig >/dev/null 2>&1; then
            local domains=("google.com" "github.com" "amazon.com" "microsoft.com" "apple.com")
            local domain=${domains[$RANDOM % ${#domains[@]}]}
            echo -e "${YELLOW}[$timestamp]${NC} DNS query for $domain"
            dig +short "$domain" @8.8.8.8 >/dev/null 2>&1 || true
        fi

        sleep 3

        # Simulate some HTTPS
        if command -v curl >/dev/null 2>&1; then
            echo -e "${YELLOW}[$timestamp]${NC} HTTPS request to github.com"
            curl -s -o /dev/null https://api.github.com 2>/dev/null || true
        fi

        sleep 5
    done

    echo -e "${GREEN}Normal traffic generation complete${NC}"
}

# Generate DNS tunneling pattern
generate_dns_tunneling() {
    echo -e "${YELLOW}Generating DNS tunneling pattern...${NC}"
    local end_time=$((SECONDS + DURATION))
    local count=0

    while [ $SECONDS -lt $end_time ]; do
        # Generate high-entropy subdomain
        local entropy_string=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 60 | head -n 1)
        local domain="${entropy_string}.tunnel.example.com"

        if command -v dig >/dev/null 2>&1; then
            echo -e "${RED}[$(date +'%H:%M:%S')]${NC} DNS tunneling: $domain"
            dig +short "$domain" @8.8.8.8 >/dev/null 2>&1 || true
            ((count++))
        fi

        sleep 2

        # Also generate some TXT queries (common for C2)
        if [ $((RANDOM % 3)) -eq 0 ]; then
            local txt_data=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 40 | head -n 1)
            echo -e "${RED}[$(date +'%H:%M:%S')]${NC} TXT query: ${txt_data}.data.example.com"
            dig TXT "${txt_data}.data.example.com" @8.8.8.8 >/dev/null 2>&1 || true
            ((count++))
        fi

        sleep 3
    done

    echo -e "${GREEN}Generated $count DNS tunneling queries${NC}"
}

# Generate port scan pattern
generate_port_scan() {
    echo -e "${YELLOW}Generating port scan pattern...${NC}"

    if ! command -v nc >/dev/null 2>&1; then
        echo -e "${RED}Error: netcat (nc) is required for port scanning${NC}"
        echo "Install with: sudo apt install netcat (Linux) or brew install netcat (macOS)"
        return 1
    fi

    local ports=(21 22 23 25 80 443 445 3389 8080 8443)
    local extended_ports=$(seq 1 100)
    local all_ports=("${ports[@]}" ${extended_ports})
    local scanned=0

    echo -e "${RED}[$(date +'%H:%M:%S')]${NC} Starting port scan of $TARGET"

    for port in ${all_ports[@]}; do
        echo -e "${RED}[$(date +'%H:%M:%S')]${NC} Scanning port $port"
        timeout 1 nc -zv "$TARGET" "$port" 2>/dev/null || true
        ((scanned++))

        [ $scanned -ge 50 ] && break
    done

    echo -e "${GREEN}Port scan complete: $scanned ports scanned${NC}"
}

# Generate C2 beaconing pattern
generate_c2_beaconing() {
    echo -e "${YELLOW}Generating C2 beaconing pattern...${NC}"
    local end_time=$((SECONDS + DURATION))
    local beacon_interval=10
    local count=0

    echo "Beaconing to C2 server (simulated) every ${beacon_interval} seconds"

    while [ $SECONDS -lt $end_time ]; do
        if command -v curl >/dev/null 2>&1; then
            echo -e "${RED}[$(date +'%H:%M:%S')]${NC} C2 beacon #$count to $TARGET"
            # Simulate beacon with consistent timing
            curl -s -o /dev/null --connect-timeout 2 "http://$TARGET:8080/beacon" 2>/dev/null || true
            ((count++))
        fi

        sleep "$beacon_interval"
    done

    echo -e "${GREEN}Generated $count C2 beacons${NC}"
}

# Generate lateral movement pattern
generate_lateral_movement() {
    echo -e "${YELLOW}Generating lateral movement pattern...${NC}"

    if ! command -v nc >/dev/null 2>&1; then
        echo -e "${RED}Error: netcat (nc) is required${NC}"
        return 1
    fi

    local internal_ips=("192.168.1.10" "192.168.1.11" "192.168.1.12" "192.168.1.20" "192.168.1.21")
    local smb_port=445
    local rdp_port=3389

    echo -e "${RED}[$(date +'%H:%M:%S')]${NC} Simulating lateral movement"

    for ip in "${internal_ips[@]}"; do
        echo -e "${RED}[$(date +'%H:%M:%S')]${NC} Attempting SMB connection to $ip:$smb_port"
        timeout 1 nc -zv "$ip" "$smb_port" 2>/dev/null || true

        sleep 2

        echo -e "${RED}[$(date +'%H:%M:%S')]${NC} Attempting RDP connection to $ip:$rdp_port"
        timeout 1 nc -zv "$ip" "$rdp_port" 2>/dev/null || true

        sleep 3
    done

    echo -e "${GREEN}Lateral movement simulation complete${NC}"
}

# Generate web attack patterns
generate_web_attack() {
    echo -e "${YELLOW}Generating web attack patterns...${NC}"

    if ! command -v curl >/dev/null 2>&1; then
        echo -e "${RED}Error: curl is required${NC}"
        return 1
    fi

    local sql_patterns=(
        "' OR '1'='1"
        "'; DROP TABLE users--"
        "1' UNION SELECT NULL--"
        "admin'--"
    )

    local xss_patterns=(
        "<script>alert('XSS')</script>"
        "<img src=x onerror=alert('XSS')>"
        "javascript:alert('XSS')"
    )

    echo -e "${RED}[$(date +'%H:%M:%S')]${NC} SQL injection attempts"
    for pattern in "${sql_patterns[@]}"; do
        local encoded=$(echo "$pattern" | jq -sRr @uri)
        echo -e "${RED}[$(date +'%H:%M:%S')]${NC} Testing: $pattern"
        curl -s -o /dev/null "http://$TARGET/login?user=$encoded" 2>/dev/null || true
        sleep 2
    done

    echo -e "${RED}[$(date +'%H:%M:%S')]${NC} XSS attempts"
    for pattern in "${xss_patterns[@]}"; do
        local encoded=$(echo "$pattern" | jq -sRr @uri)
        echo -e "${RED}[$(date +'%H:%M:%S')]${NC} Testing: $pattern"
        curl -s -o /dev/null "http://$TARGET/search?q=$encoded" 2>/dev/null || true
        sleep 2
    done

    echo -e "${GREEN}Web attack simulation complete${NC}"
}

# Generate suspicious traffic
generate_suspicious_traffic() {
    echo -e "${YELLOW}Generating suspicious traffic...${NC}"
    local end_time=$((SECONDS + DURATION))

    while [ $SECONDS -lt $end_time ]; do
        # Mix of concerning but not definitively malicious activity
        local activity=$((RANDOM % 4))

        case $activity in
            0)
                # Unusual DNS patterns
                local unusual_domain="subdomain-$(date +%s).unusual-pattern.com"
                echo -e "${YELLOW}[$(date +'%H:%M:%S')]${NC} Unusual DNS: $unusual_domain"
                dig +short "$unusual_domain" @8.8.8.8 >/dev/null 2>&1 || true
                ;;
            1)
                # High-frequency requests
                echo -e "${YELLOW}[$(date +'%H:%M:%S')]${NC} High-frequency HTTP requests"
                for i in {1..5}; do
                    curl -s -o /dev/null "http://www.example.com?req=$i" 2>/dev/null || true
                done
                ;;
            2)
                # Odd hour activity (simulated)
                echo -e "${YELLOW}[$(date +'%H:%M:%S')]${NC} Unusual time-of-day access pattern"
                curl -s -o /dev/null "https://internal.example.com/admin" 2>/dev/null || true
                ;;
            3)
                # Multiple failed attempts (simulated)
                echo -e "${YELLOW}[$(date +'%H:%M:%S')]${NC} Multiple authentication attempts"
                for i in {1..3}; do
                    curl -s -o /dev/null -d "user=admin&pass=wrong$i" "http://$TARGET/login" 2>/dev/null || true
                done
                ;;
        esac

        sleep 5
    done

    echo -e "${GREEN}Suspicious traffic generation complete${NC}"
}

# Main function
main() {
    print_header

    echo "Configuration:"
    echo "  Type: $TRAFFIC_TYPE"
    echo "  Duration: ${DURATION}s"
    echo "  Target: $TARGET"
    echo ""

    case $TRAFFIC_TYPE in
        normal)
            generate_normal_traffic
            ;;
        suspicious)
            generate_suspicious_traffic
            ;;
        dns-tunneling)
            generate_dns_tunneling
            ;;
        port-scan)
            generate_port_scan
            ;;
        c2-beacon)
            generate_c2_beaconing
            ;;
        lateral-movement)
            generate_lateral_movement
            ;;
        web-attack)
            generate_web_attack
            ;;
        attack)
            # Generate all attack patterns
            generate_dns_tunneling &
            sleep 15
            generate_port_scan &
            sleep 15
            generate_c2_beaconing &
            wait
            ;;
        *)
            echo -e "${RED}Unknown traffic type: $TRAFFIC_TYPE${NC}"
            usage
            ;;
    esac

    echo ""
    echo -e "${GREEN}Traffic generation complete!${NC}"
    echo ""
    echo "Check for detections:"
    echo "  1. Run: ./scripts/verify-deployment.sh"
    echo "  2. View Kibana: http://localhost:5601"
    echo "  3. Check logs: docker-compose logs zeek suricata"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --type)
            TRAFFIC_TYPE="$2"
            shift 2
            ;;
        --duration)
            DURATION="$2"
            shift 2
            ;;
        --attack)
            TRAFFIC_TYPE="$2"
            shift 2
            ;;
        --target)
            TARGET="$2"
            shift 2
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
