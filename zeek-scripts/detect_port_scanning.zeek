##! Port Scanning Detection Script
##! Detects network reconnaissance and port scanning activity
##! Author: Raouf - Network IDS Project
##!
##! Detection Methods:
##! - Horizontal scanning (same port, multiple hosts)
##! - Vertical scanning (multiple ports, same host)
##! - SYN flood patterns
##! - Failed connection attempts
##! - TCP NULL, FIN, XMAS scans

@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/protocols/conn

module PortScan;

export {
    redef enum Notice::Type += {
        ## Horizontal port scan detected
        Port_Scan_Detected,
        ## Vertical port scan detected
        Host_Scan_Detected,
        ## SYN scan detected
        SYN_Scan_Detected,
        ## Failed connection flood
        Failed_Connection_Flood,
        ## Stealth scan detected (NULL, FIN, XMAS)
        Stealth_Scan_Detected,
    };

    ## Threshold for horizontal scan (unique hosts)
    const horizontal_scan_threshold = 20 &redef;

    ## Threshold for vertical scan (unique ports)
    const vertical_scan_threshold = 30 &redef;

    ## Threshold for failed connections
    const failed_connection_threshold = 15 &redef;

    ## Observation window
    const scan_window = 1min &redef;

    ## Minimum connection duration to not be considered a scan
    const min_connection_duration = 1.0 sec &redef;

    ## Common scan ports (often targeted)
    const common_scan_ports = set(
        21/tcp, 22/tcp, 23/tcp, 25/tcp, 53/tcp,
        80/tcp, 110/tcp, 135/tcp, 139/tcp, 143/tcp,
        443/tcp, 445/tcp, 993/tcp, 995/tcp, 1433/tcp,
        3306/tcp, 3389/tcp, 5900/tcp, 8080/tcp, 8443/tcp
    ) &redef;

    ## Scan tracking
    type ScanTracker: record {
        unique_hosts: set[addr];
        unique_ports: set[port];
        failed_connections: count;
        syn_count: count;
        null_fin_xmas: count;
        first_seen: time;
        last_seen: time;
    };

    global scan_tracking: table[addr] of ScanTracker &create_expire=5min;
}

## Helper function to check if connection looks like a scan
function is_scan_like(c: connection): bool
{
    # Short-lived connections
    if (c$duration < min_connection_duration)
        return T;

    # No data transferred
    if (c$orig_bytes + c$resp_bytes < 100)
        return T;

    # Connection rejected
    if (c$conn$conn_state == "REJ" || c$conn$conn_state == "S0")
        return T;

    return F;
}

## Check TCP flags for stealth scans
function check_stealth_scan(flags: string): bool
{
    # NULL scan (no flags)
    if (|flags| == 0)
        return T;

    # FIN scan
    if ("F" in flags && "S" !in flags && "A" !in flags)
        return T;

    # XMAS scan (FIN, PSH, URG)
    if ("F" in flags && "P" in flags && "U" in flags)
        return T;

    return F;
}

event connection_state_remove(c: connection)
{
    # Skip if not enough info
    if (!c?$conn)
        return;

    # Skip local-to-local connections
    if (Site::is_local_addr(c$id$orig_h) && Site::is_local_addr(c$id$resp_h))
        return;

    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    local dport = c$id$resp_p;
    local now = network_time();

    # Initialize tracker
    if (src !in scan_tracking)
    {
        scan_tracking[src] = ScanTracker(
            $unique_hosts=set(),
            $unique_ports=set(),
            $failed_connections=0,
            $syn_count=0,
            $null_fin_xmas=0,
            $first_seen=now,
            $last_seen=now
        );
    }

    local tracker = scan_tracking[src];
    tracker$last_seen = now;

    # Track unique destinations
    add tracker$unique_hosts[dst];
    add tracker$unique_ports[dport];

    # Check connection state for scan indicators
    if (c$conn$conn_state == "S0")  # Connection attempt seen, no reply
    {
        ++tracker$syn_count;
    }

    if (c$conn$conn_state == "REJ" || c$conn$conn_state == "RSTOS0" || c$conn$conn_state == "RSTO")
    {
        ++tracker$failed_connections;
    }

    # Check for stealth scan flags
    if (c?$conn && c$conn?$history)
    {
        if (check_stealth_scan(c$conn$history))
        {
            ++tracker$null_fin_xmas;
        }
    }

    # Analyze patterns
    local duration = tracker$last_seen - tracker$first_seen;

    # Detection 1: Horizontal Scan (many hosts, same/few ports)
    if (|tracker$unique_hosts| >= horizontal_scan_threshold)
    {
        NOTICE([$note=Port_Scan_Detected,
                $conn=c,
                $msg=fmt("Horizontal port scan: %s scanning %d hosts", src, |tracker$unique_hosts|),
                $sub=fmt("Ports: %d, Duration: %.1fs", |tracker$unique_ports|, duration),
                $identifier=cat(src, "horizontal_scan")]);
    }

    # Detection 2: Vertical Scan (many ports, same/few hosts)
    if (|tracker$unique_ports| >= vertical_scan_threshold)
    {
        NOTICE([$note=Host_Scan_Detected,
                $conn=c,
                $msg=fmt("Vertical port scan: %s scanned %d ports", src, |tracker$unique_ports|),
                $sub=fmt("Hosts: %d, Duration: %.1fs", |tracker$unique_hosts|, duration),
                $identifier=cat(src, "vertical_scan")]);
    }

    # Detection 3: SYN Scan
    if (tracker$syn_count >= 10)
    {
        NOTICE([$note=SYN_Scan_Detected,
                $conn=c,
                $msg=fmt("SYN scan detected: %s", src),
                $sub=fmt("SYN attempts: %d, Hosts: %d", tracker$syn_count, |tracker$unique_hosts|),
                $identifier=cat(src, "syn_scan")]);
    }

    # Detection 4: Failed Connection Flood
    if (tracker$failed_connections >= failed_connection_threshold)
    {
        NOTICE([$note=Failed_Connection_Flood,
                $conn=c,
                $msg=fmt("Failed connection flood: %s", src),
                $sub=fmt("Failed: %d, Success rate: %.1f%%",
                         tracker$failed_connections,
                         (1.0 - tracker$failed_connections / (|tracker$unique_hosts| * 1.0)) * 100),
                $identifier=cat(src, "failed_flood")]);
    }

    # Detection 5: Stealth Scan
    if (tracker$null_fin_xmas >= 5)
    {
        NOTICE([$note=Stealth_Scan_Detected,
                $conn=c,
                $msg=fmt("Stealth scan detected: %s", src),
                $sub=fmt("NULL/FIN/XMAS probes: %d", tracker$null_fin_xmas),
                $identifier=cat(src, "stealth_scan")]);
    }
}

## SumStats-based detection for real-time alerting
event zeek_init()
{
    # Track unique destination IPs
    local host_scan_reducer: SumStats::Reducer = [$stream="port_scan.hosts",
                                                   $apply=set(SumStats::UNIQUE)];

    SumStats::create([$name="detect-horizontal-scan",
                      $epoch=scan_window,
                      $reducers=set(host_scan_reducer),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
                          {
                          return result["port_scan.hosts"]$unique + 0.0;
                          },
                      $threshold=horizontal_scan_threshold + 0.0,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                          {
                          local scanner = key$host;
                          NOTICE([$note=Port_Scan_Detected,
                                  $src=scanner,
                                  $msg=fmt("Port scan detected: %s", scanner),
                                  $sub=fmt("%.0f unique hosts scanned in %s",
                                           result["port_scan.hosts"]$unique,
                                           scan_window),
                                  $identifier=cat(scanner, "sumstats_horizontal")]);
                          }]);

    # Track unique destination ports
    local port_scan_reducer: SumStats::Reducer = [$stream="port_scan.ports",
                                                   $apply=set(SumStats::UNIQUE)];

    SumStats::create([$name="detect-vertical-scan",
                      $epoch=scan_window,
                      $reducers=set(port_scan_reducer),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
                          {
                          return result["port_scan.ports"]$unique + 0.0;
                          },
                      $threshold=vertical_scan_threshold + 0.0,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                          {
                          local scanner = key$host;
                          NOTICE([$note=Host_Scan_Detected,
                                  $src=scanner,
                                  $msg=fmt("Host scan detected: %s", scanner),
                                  $sub=fmt("%.0f unique ports scanned in %s",
                                           result["port_scan.ports"]$unique,
                                           scan_window),
                                  $identifier=cat(scanner, "sumstats_vertical")]);
                          }]);

    print "Port Scan Detection: Monitoring started";
}

## Feed SumStats
event new_connection(c: connection) &priority=-5
{
    # Track hosts and ports
    SumStats::observe("port_scan.hosts",
                      [$host=c$id$orig_h],
                      [$str=cat(c$id$resp_h)]);

    SumStats::observe("port_scan.ports",
                      [$host=c$id$orig_h],
                      [$str=cat(c$id$resp_p)]);
}

event zeek_done()
{
    print "Port Scan Detection: Monitoring stopped";
    print fmt("Tracked %d unique scanners", |scan_tracking|);
}
