##! Command & Control Beaconing Detection Script
##! Detects periodic callback patterns indicative of C2 communication
##! Author: Raouf - Network IDS Project
##!
##! Detection Methods:
##! - Periodic connection intervals (beaconing)
##! - Consistent connection sizes (low variance)
##! - Connections to uncommon ports
##! - Regularity in connection timing
##! - Long-duration connections with periodic activity

@load base/protocols/conn
@load base/frameworks/notice
@load base/frameworks/sumstats

module C2;

export {
    redef enum Notice::Type += {
        ## C2 beaconing pattern detected
        Beaconing_Detected,
        ## Suspicious periodic connections
        Periodic_Connection_Pattern,
        ## Potential C2 heartbeat detected
        Heartbeat_Detected,
    };

    ## Minimum number of connections to establish pattern
    const min_connections = 5 &redef;

    ## Maximum jitter (seconds) for timing variance
    const max_jitter = 5.0 &redef;

    ## Minimum beacon interval (seconds)
    const min_beacon_interval = 10.0 &redef;

    ## Maximum beacon interval (seconds)
    const max_beacon_interval = 3600.0 &redef;

    ## Maximum coefficient of variation for connection size
    const max_size_cv = 0.3 &redef;

    ## Suspicious ports (uncommon for normal traffic)
    const suspicious_ports = set(
        4444/tcp, 5555/tcp, 6666/tcp, 7777/tcp, 8888/tcp, 9999/tcp,
        1337/tcp, 31337/tcp, 12345/tcp, 54321/tcp
    ) &redef;

    ## Connection tracking table
    type BeaconInfo: record {
        timestamps: vector of time;
        intervals: vector of interval;
        sizes: vector of count;
        first_seen: time;
        last_seen: time;
        connection_count: count;
    };

    global beacon_tracking: table[addr, addr, port] of BeaconInfo &create_expire=1hr;
}

## Calculate mean of interval vector
function calc_mean_interval(intervals: vector of interval): interval
{
    local sum = 0.0;
    local count = 0;

    for (i in intervals)
    {
        sum += interval_to_double(intervals[i]);
        ++count;
    }

    if (count == 0)
        return 0.0 secs;

    return double_to_interval(sum / count);
}

## Calculate standard deviation of intervals
function calc_stddev_interval(intervals: vector of interval, mean: interval): double
{
    local sum_sq_diff = 0.0;
    local count = 0;
    local mean_val = interval_to_double(mean);

    for (i in intervals)
    {
        local diff = interval_to_double(intervals[i]) - mean_val;
        sum_sq_diff += diff * diff;
        ++count;
    }

    if (count <= 1)
        return 0.0;

    return sqrt(sum_sq_diff / (count - 1));
}

## Calculate coefficient of variation for sizes
function calc_size_cv(sizes: vector of count): double
{
    if (|sizes| == 0)
        return 0.0;

    # Calculate mean
    local sum = 0;
    for (i in sizes)
        sum += sizes[i];
    local mean = sum / |sizes|;

    if (mean == 0)
        return 0.0;

    # Calculate standard deviation
    local sum_sq_diff = 0.0;
    for (i in sizes)
    {
        local diff = sizes[i] - mean;
        sum_sq_diff += diff * diff;
    }

    local stddev = sqrt(sum_sq_diff / |sizes|);

    # Return coefficient of variation
    return stddev / mean;
}

## Check if timing pattern indicates beaconing
function is_beaconing(info: BeaconInfo): bool
{
    if (|info$intervals| < min_connections - 1)
        return F;

    local mean = calc_mean_interval(info$intervals);
    local mean_seconds = interval_to_double(mean);

    # Check if interval is in suspicious range
    if (mean_seconds < min_beacon_interval || mean_seconds > max_beacon_interval)
        return F;

    local stddev = calc_stddev_interval(info$intervals, mean);

    # Check for low variance (consistent timing)
    if (stddev < max_jitter)
        return T;

    # Check coefficient of variation for timing
    local cv = stddev / mean_seconds;
    if (cv < 0.3)  # Less than 30% variation
        return T;

    return F;
}

event connection_state_remove(c: connection)
{
    # Only analyze established connections
    if (!c?$conn || !c$conn?$orig_bytes || !c$conn?$resp_bytes)
        return;

    # Skip local connections
    if (Site::is_local_addr(c$id$orig_h) && Site::is_local_addr(c$id$resp_h))
        return;

    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    local dport = c$id$resp_p;
    local now = network_time();

    # Initialize tracking if new
    if ([src, dst, dport] !in beacon_tracking)
    {
        beacon_tracking[src, dst, dport] = BeaconInfo(
            $timestamps=vector(),
            $intervals=vector(),
            $sizes=vector(),
            $first_seen=now,
            $last_seen=now,
            $connection_count=0
        );
    }

    local info = beacon_tracking[src, dst, dport];

    # Update tracking info
    info$timestamps += now;
    info$last_seen = now;
    info$sizes += c$conn$orig_bytes + c$conn$resp_bytes;
    ++info$connection_count;

    # Calculate interval if we have previous connection
    if (|info$timestamps| > 1)
    {
        local last_idx = |info$timestamps| - 2;
        local interval = now - info$timestamps[last_idx];
        info$intervals += interval;
    }

    # Analyze pattern if we have enough data
    if (info$connection_count >= min_connections)
    {
        # Check for beaconing pattern
        if (is_beaconing(info))
        {
            local mean = calc_mean_interval(info$intervals);
            local size_cv = calc_size_cv(info$sizes);

            NOTICE([$note=Beaconing_Detected,
                    $conn=c,
                    $msg=fmt("C2 beaconing detected: %s -> %s:%s", src, dst, dport),
                    $sub=fmt("Connections: %d, Avg Interval: %.1fs, Size CV: %.2f",
                             info$connection_count,
                             interval_to_double(mean),
                             size_cv),
                    $identifier=cat(src, dst, dport)]);
        }

        # Check for consistent small payloads (heartbeat)
        local size_cv = calc_size_cv(info$sizes);
        if (size_cv < max_size_cv)
        {
            local mean_interval = calc_mean_interval(info$intervals);

            if (interval_to_double(mean_interval) >= min_beacon_interval)
            {
                NOTICE([$note=Heartbeat_Detected,
                        $conn=c,
                        $msg=fmt("C2 heartbeat pattern: %s -> %s:%s", src, dst, dport),
                        $sub=fmt("Connections: %d, Consistent sizes (CV: %.2f)",
                                 info$connection_count, size_cv),
                        $identifier=cat(src, dst, dport)]);
            }
        }
    }

    # Check for suspicious port usage
    if (dport in suspicious_ports && info$connection_count >= 3)
    {
        NOTICE([$note=Periodic_Connection_Pattern,
                $conn=c,
                $msg=fmt("Suspicious port usage pattern: %s -> %s:%s", src, dst, dport),
                $sub=fmt("Connections: %d to uncommon port", info$connection_count),
                $identifier=cat(src, dst, dport)]);
    }
}

event zeek_init()
{
    print "C2 Beaconing Detection: Monitoring started";
}

event zeek_done()
{
    print "C2 Beaconing Detection: Monitoring stopped";
    print fmt("Tracked %d unique connection pairs", |beacon_tracking|);
}
