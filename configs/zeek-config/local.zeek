##! Local site policy for Network IDS
##! Customized for threat detection and analysis

# ============================================
# Core Zeek Scripts
# ============================================
@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/frameworks/intel
@load base/frameworks/files

# ============================================
# Protocol Analyzers
# ============================================
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/dns
@load protocols/ftp
@load protocols/http
@load protocols/smtp
@load protocols/ssh
@load protocols/ssl
@load protocols/smb
@load protocols/rdp
@load protocols/dhcp

# ============================================
# File Analysis
# ============================================
@load frameworks/files/hash-all-files
@load frameworks/files/detect-MHR
@load frameworks/files/extract-all-files

# ============================================
# Security Policies
# ============================================
@load policy/protocols/conn/vlan-logging
@load policy/protocols/conn/mac-logging
@load policy/protocols/ssl/validate-certs
@load policy/protocols/ssl/known-certs
@load policy/protocols/ssl/log-hostcerts-only
@load policy/protocols/ssh/detect-bruteforcing
@load policy/protocols/ssh/geo-data
@load policy/protocols/http/detect-sqli
@load policy/protocols/http/detect-webapps
@load policy/protocols/ftp/detect-bruteforcing
@load policy/protocols/smb
@load policy/misc/detect-traceroute

# ============================================
# Threat Detection
# ============================================
@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice
@load policy/integration/collective-intel

# Software detection
@load policy/frameworks/software/vulnerable
@load policy/frameworks/software/version-changes
@load policy/frameworks/software/windows-version-detection

# ============================================
# Custom Detection Scripts
# ============================================
# Load custom scripts from /opt/zeek/share/zeek/site/custom/
@load custom/detect_dns_tunneling
@load custom/detect_c2_beaconing
@load custom/detect_lateral_movement
@load custom/detect_port_scanning
@load custom/detect_tls_anomalies

# ============================================
# Network Configuration
# ============================================
# Define local networks (loaded from networks.cfg)
@load misc/known-devices

# ============================================
# Logging Configuration
# ============================================
# Enable all logs
redef Log::enable_local_logging = T;
redef Log::enable_remote_logging = F;

# Log rotation settings
redef Log::default_rotation_interval = 1 hr;
redef Log::default_rotation_postprocessor_cmd = "gzip";

# ============================================
# Performance Tuning
# ============================================
# Increase table sizes for high-traffic environments
redef table_incremental_step = 1000;
redef table_expire_interval = 10 min;

# Connection tracking
redef Conn::registration_timeout = 10 min;

# DNS configuration
redef DNS::max_pending_queries = 10000;

# HTTP configuration
redef HTTP::max_pending_requests = 1000;

# SSL configuration
redef SSL::max_pending_certs = 1000;

# ============================================
# Notice Configuration
# ============================================
# Configure notice actions
redef Notice::emailed_types += {
    DNS::DNS_Tunneling_Detected,
    C2::Beaconing_Detected,
    LateralMovement::Suspicious_RDP_Activity,
    LateralMovement::Suspicious_SMB_Activity,
    PortScan::Port_Scan_Detected,
    SSL::TLS_Anomaly_Detected,
};

# Notice policy
hook Notice::policy(n: Notice::Info)
{
    # Add custom notice handling logic here
    if (n$note == DNS::DNS_Tunneling_Detected)
    {
        add n$actions[Notice::ACTION_LOG];
        add n$actions[Notice::ACTION_EMAIL];
    }
}

# ============================================
# Intel Framework Configuration
# ============================================
# Configure threat intelligence feeds
redef Intel::read_files += {
    "/opt/zeek/share/zeek/site/intel/malware-domains.txt",
    "/opt/zeek/share/zeek/site/intel/tor-exit-nodes.txt",
};

# ============================================
# File Extraction Configuration
# ============================================
# Extract executables and archives for analysis
redef FileExtract::default_limit = 10485760; # 10MB

hook FileExtract::extract(f: fa_file, meta: fa_metadata) &priority=5
{
    if (f$mime_type in {
        "application/x-dosexec",
        "application/x-executable",
        "application/pdf",
        "application/zip",
        "application/x-rar",
    })
    {
        FileExtract::set_limit(f, 10485760);
    }
}

# ============================================
# GeoIP Configuration (if available)
# ============================================
@load policy/protocols/conn/community-id

# ============================================
# JSON Logging (for Filebeat integration)
# ============================================
@load policy/tuning/json-logs

# ============================================
# Statistics
# ============================================
# Enable packet statistics
redef Pcap::bufsize = 256;

# ============================================
# Custom Global Variables
# ============================================
# Tracking suspicious activity thresholds
global suspicious_dns_query_length = 50;
global suspicious_connection_count = 100;
global beacon_interval_tolerance = 5.0; # seconds

# ============================================
# Initialization
# ============================================
event zeek_init()
{
    print "Network IDS - Zeek Started";
    print fmt("Custom scripts loaded from: %s", @DIR);
}

event zeek_done()
{
    print "Network IDS - Zeek Stopped";
}
