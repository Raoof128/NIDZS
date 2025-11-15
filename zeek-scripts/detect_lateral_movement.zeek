##! Lateral Movement Detection Script
##! Detects SMB/RDP lateral movement attempts in the network
##! Author: Raouf - Network IDS Project
##!
##! Detection Methods:
##! - Multiple RDP connections from single source
##! - Unusual SMB file access patterns
##! - Credential spraying attempts
##! - Administrative share access
##! - Rapid successive logins across multiple hosts

@load base/protocols/smb
@load base/protocols/rdp
@load base/protocols/conn
@load base/frameworks/notice
@load base/frameworks/sumstats

module LateralMovement;

export {
    redef enum Notice::Type += {
        ## RDP lateral movement detected
        Suspicious_RDP_Activity,
        ## SMB lateral movement detected
        Suspicious_SMB_Activity,
        ## Credential spraying attempt
        Credential_Spray_Detected,
        ## Administrative share access
        Admin_Share_Access,
        ## Multiple host access in short time
        Rapid_Multi_Host_Access,
    };

    ## Maximum RDP connections per source in observation window
    const max_rdp_connections = 5 &redef;

    ## Maximum SMB targets per source in observation window
    const max_smb_targets = 10 &redef;

    ## Observation window for tracking
    const observation_window = 5min &redef;

    ## Administrative shares
    const admin_shares = set("ADMIN$", "C$", "IPC$", "D$", "E$") &redef;

    ## Suspicious SMB paths
    const suspicious_paths = /\\Windows\\System32\\/ | /\\Temp\\/ | /\\ProgramData\\/;

    ## RDP tracking
    type RDPTracker: record {
        destinations: set[addr];
        connection_count: count;
        first_seen: time;
    };

    global rdp_tracking: table[addr] of RDPTracker &create_expire=observation_window;

    ## SMB tracking
    type SMBTracker: record {
        destinations: set[addr];
        shares_accessed: set[string];
        paths_accessed: vector of string;
        connection_count: count;
        first_seen: time;
    };

    global smb_tracking: table[addr] of SMBTracker &create_expire=observation_window;
}

## RDP Connection Analysis
event rdp_client_info(c: connection, cookie: string)
{
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    # Skip if both are local
    if (Site::is_local_addr(src) && Site::is_local_addr(dst))
    {
        # Initialize tracking
        if (src !in rdp_tracking)
        {
            rdp_tracking[src] = RDPTracker(
                $destinations=set(),
                $connection_count=0,
                $first_seen=network_time()
            );
        }

        local tracker = rdp_tracking[src];
        add tracker$destinations[dst];
        ++tracker$connection_count;

        # Alert on multiple RDP connections
        if (|tracker$destinations| >= max_rdp_connections)
        {
            NOTICE([$note=Suspicious_RDP_Activity,
                    $conn=c,
                    $msg=fmt("Lateral movement via RDP: %s accessed %d hosts", src, |tracker$destinations|),
                    $sub=fmt("Connections: %d in %s window", tracker$connection_count, observation_window),
                    $identifier=cat(src, "rdp_lateral")]);
        }

        # Alert on rapid successive connections
        if (tracker$connection_count >= 3)
        {
            local duration = network_time() - tracker$first_seen;
            if (duration < 1min)
            {
                NOTICE([$note=Rapid_Multi_Host_Access,
                        $conn=c,
                        $msg=fmt("Rapid RDP connections: %s", src),
                        $sub=fmt("%d connections in %.1f seconds", tracker$connection_count, duration),
                        $identifier=cat(src, "rdp_rapid")]);
            }
        }
    }
}

## SMB File Access Analysis
event smb_file_open(c: connection, file_id: count, file_name: string)
{
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    # Initialize tracking
    if (src !in smb_tracking)
    {
        smb_tracking[src] = SMBTracker(
            $destinations=set(),
            $shares_accessed=set(),
            $paths_accessed=vector(),
            $connection_count=0,
            $first_seen=network_time()
        );
    }

    local tracker = smb_tracking[src];
    add tracker$destinations[dst];
    tracker$paths_accessed += file_name;
    ++tracker$connection_count;

    # Extract share name
    if (/\\/ in file_name)
    {
        local parts = split_string(file_name, /\\/);
        if (|parts| > 0)
        {
            local share = parts[0];
            add tracker$shares_accessed[share];

            # Check for administrative share access
            if (share in admin_shares)
            {
                NOTICE([$note=Admin_Share_Access,
                        $conn=c,
                        $msg=fmt("Administrative share access: %s -> %s\\%s", src, dst, share),
                        $sub=fmt("File: %s", file_name),
                        $identifier=cat(src, dst, share)]);
            }
        }
    }

    # Check for suspicious paths
    if (suspicious_paths in file_name)
    {
        NOTICE([$note=Suspicious_SMB_Activity,
                $conn=c,
                $msg=fmt("Suspicious SMB file access: %s -> %s", src, dst),
                $sub=fmt("File: %s", file_name),
                $identifier=cat(src, dst, file_name)]);
    }

    # Alert on multiple SMB targets
    if (|tracker$destinations| >= max_smb_targets)
    {
        NOTICE([$note=Suspicious_SMB_Activity,
                $conn=c,
                $msg=fmt("Lateral movement via SMB: %s accessed %d hosts", src, |tracker$destinations|),
                $sub=fmt("Shares: %d, Files: %d", |tracker$shares_accessed|, |tracker$paths_accessed|),
                $identifier=cat(src, "smb_lateral")]);
    }
}

## SMB Tree Connect (Share Mounting)
event smb2_tree_connect_request(c: connection, hdr: SMB2::Header, path: string)
{
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    # Initialize tracking
    if (src !in smb_tracking)
    {
        smb_tracking[src] = SMBTracker(
            $destinations=set(),
            $shares_accessed=set(),
            $paths_accessed=vector(),
            $connection_count=0,
            $first_seen=network_time()
        );
    }

    local tracker = smb_tracking[src];

    # Extract share name from path (\\server\share)
    if (/\\/ in path)
    {
        local parts = split_string(path, /\\/);
        if (|parts| >= 2)
        {
            local share = parts[|parts| - 1];
            add tracker$shares_accessed[share];

            # Check for administrative share
            if (share in admin_shares)
            {
                NOTICE([$note=Admin_Share_Access,
                        $conn=c,
                        $msg=fmt("Administrative share connection: %s -> %s", src, path),
                        $sub=fmt("Share: %s", share),
                        $identifier=cat(src, path)]);
            }
        }
    }

    # Check for IPC$ share (often used in attacks)
    if (/IPC\$/ in path)
    {
        # Track for potential credential spraying
        if (|tracker$destinations| >= 3)
        {
            NOTICE([$note=Credential_Spray_Detected,
                    $conn=c,
                    $msg=fmt("Potential credential spraying via SMB: %s", src),
                    $sub=fmt("IPC$ connections to %d hosts", |tracker$destinations|),
                    $identifier=cat(src, "ipc_spray")]);
        }
    }
}

## Detect PSExec-like activity
event smb_file_open(c: connection, file_id: count, file_name: string) &priority=-5
{
    # PSExec creates files like PSEXESVC.exe in ADMIN$ share
    if (/PSEXE/ in file_name || /ADMIN\$.*\.exe/ in file_name)
    {
        NOTICE([$note=Suspicious_SMB_Activity,
                $conn=c,
                $msg=fmt("Potential PSExec activity: %s -> %s", c$id$orig_h, c$id$resp_h),
                $sub=fmt("File: %s", file_name),
                $identifier=cat(c$id$orig_h, c$id$resp_h, "psexec")]);
    }

    # WMI execution
    if (/\\ROOT\\CIMV2/ in file_name)
    {
        NOTICE([$note=Suspicious_SMB_Activity,
                $conn=c,
                $msg=fmt("Potential WMI execution: %s -> %s", c$id$orig_h, c$id$resp_h),
                $sub=fmt("File: %s", file_name),
                $identifier=cat(c$id$orig_h, c$id$resp_h, "wmi")]);
    }
}

## SumStats for tracking connection rates
event zeek_init()
{
    # Track RDP connection rates
    local rdp_reducer: SumStats::Reducer = [$stream="rdp.connections",
                                             $apply=set(SumStats::UNIQUE)];

    SumStats::create([$name="detect-rdp-lateral-movement",
                      $epoch=observation_window,
                      $reducers=set(rdp_reducer),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
                          {
                          return result["rdp.connections"]$unique + 0.0;
                          },
                      $threshold=max_rdp_connections + 0.0,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                          {
                          local src = key$host;
                          NOTICE([$note=Suspicious_RDP_Activity,
                                  $src=src,
                                  $msg=fmt("RDP lateral movement pattern: %s", src),
                                  $sub=fmt("%.0f unique destinations in %s",
                                           result["rdp.connections"]$unique,
                                           observation_window),
                                  $identifier=cat(src, "rdp_sumstats")]);
                          }]);

    # Track SMB connection rates
    local smb_reducer: SumStats::Reducer = [$stream="smb.connections",
                                             $apply=set(SumStats::UNIQUE)];

    SumStats::create([$name="detect-smb-lateral-movement",
                      $epoch=observation_window,
                      $reducers=set(smb_reducer),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
                          {
                          return result["smb.connections"]$unique + 0.0;
                          },
                      $threshold=max_smb_targets + 0.0,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                          {
                          local src = key$host;
                          NOTICE([$note=Suspicious_SMB_Activity,
                                  $src=src,
                                  $msg=fmt("SMB lateral movement pattern: %s", src),
                                  $sub=fmt("%.0f unique destinations in %s",
                                           result["smb.connections"]$unique,
                                           observation_window),
                                  $identifier=cat(src, "smb_sumstats")]);
                          }]);

    print "Lateral Movement Detection: Monitoring started";
}

## Track RDP connections for SumStats
event rdp_client_info(c: connection, cookie: string) &priority=-10
{
    SumStats::observe("rdp.connections",
                      [$host=c$id$orig_h],
                      [$str=cat(c$id$resp_h)]);
}

## Track SMB connections for SumStats
event smb2_tree_connect_request(c: connection, hdr: SMB2::Header, path: string) &priority=-10
{
    SumStats::observe("smb.connections",
                      [$host=c$id$orig_h],
                      [$str=cat(c$id$resp_h)]);
}

event zeek_done()
{
    print "Lateral Movement Detection: Monitoring stopped";
}
