##! DNS Tunneling Detection Script
##! Detects DNS-based data exfiltration and C2 communication
##! Author: Raouf - Network IDS Project
##!
##! Detection Methods:
##! - Abnormally long DNS queries (>50 characters)
##! - High entropy in subdomain labels
##! - Excessive TXT record queries
##! - Unusual query patterns (base64, hex encoding)
##! - High query rate from single source

@load base/protocols/dns
@load base/frameworks/notice
@load base/frameworks/sumstats

module DNS;

export {
    redef enum Notice::Type += {
        ## DNS tunneling detected based on query characteristics
        DNS_Tunneling_Detected,
        ## Suspicious TXT record queries
        Suspicious_TXT_Queries,
        ## High query rate from single source
        DNS_Query_Flood,
    };

    ## Threshold for query length (characters)
    const query_length_threshold = 50 &redef;

    ## Threshold for Shannon entropy
    const entropy_threshold = 3.5 &redef;

    ## Maximum queries per minute per source
    const max_queries_per_minute = 100 &redef;

    ## Suspicious query patterns (regex)
    const suspicious_patterns = /[A-Za-z0-9+\/]{20,}/ &redef;

    ## Whitelist domains (won't trigger alerts)
    const whitelist_domains = set(
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "cloudflare.com",
        "akamai.net",
        "amazonaws.com",
    ) &redef;
}

## Calculate Shannon entropy of a string
function calculate_entropy(s: string): double
{
    local char_freq: table[string] of count = table();
    local len = |s|;
    local entropy = 0.0;

    if (len == 0)
        return 0.0;

    # Count character frequencies
    for (i in s)
    {
        local c = s[i];
        if (c !in char_freq)
            char_freq[c] = 0;
        ++char_freq[c];
    }

    # Calculate entropy
    for (c in char_freq)
    {
        local freq = char_freq[c] / double_to_count(len + 0.0);
        if (freq > 0.0)
            entropy += freq * ln(freq) / ln(2.0);
    }

    return -entropy;
}

## Extract subdomain from FQDN
function get_subdomain(query: string): string
{
    local parts = split_string(query, /\./);
    if (|parts| <= 2)
        return "";

    # Return everything except last two parts (domain.tld)
    local subdomain = "";
    for (i in parts)
    {
        if (i < |parts| - 2)
        {
            subdomain = cat(subdomain, parts[i]);
            if (i < |parts| - 3)
                subdomain = cat(subdomain, ".");
        }
    }
    return subdomain;
}

## Check if domain is whitelisted
function is_whitelisted(query: string): bool
{
    for (domain in whitelist_domains)
    {
        if (strstr(query, domain) > 0)
            return T;
    }
    return F;
}

## Extract base domain from query
function get_base_domain(query: string): string
{
    local parts = split_string(query, /\./);
    if (|parts| < 2)
        return query;

    return cat(parts[|parts| - 2], ".", parts[|parts| - 1]);
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    # Skip whitelisted domains
    if (is_whitelisted(query))
        return;

    local query_len = |query|;
    local subdomain = get_subdomain(query);
    local subdomain_len = |subdomain|;

    # Detection 1: Abnormally long queries
    if (query_len > query_length_threshold)
    {
        local entropy = calculate_entropy(subdomain);

        NOTICE([$note=DNS_Tunneling_Detected,
                $conn=c,
                $msg=fmt("DNS tunneling detected: abnormally long query (%d chars)", query_len),
                $sub=fmt("Query: %s, Entropy: %.2f", query, entropy),
                $identifier=cat(c$id$orig_h, query)]);
    }

    # Detection 2: High entropy in subdomain
    if (subdomain_len > 10)
    {
        local entropy = calculate_entropy(subdomain);
        if (entropy > entropy_threshold)
        {
            NOTICE([$note=DNS_Tunneling_Detected,
                    $conn=c,
                    $msg=fmt("DNS tunneling detected: high entropy subdomain (%.2f)", entropy),
                    $sub=fmt("Query: %s, Subdomain: %s", query, subdomain),
                    $identifier=cat(c$id$orig_h, query)]);
        }
    }

    # Detection 3: Suspicious TXT record queries
    if (qtype == 16)  # TXT record
    {
        if (subdomain_len > 20 || suspicious_patterns in subdomain)
        {
            NOTICE([$note=Suspicious_TXT_Queries,
                    $conn=c,
                    $msg="Suspicious TXT record query detected",
                    $sub=fmt("Query: %s, Length: %d", query, query_len),
                    $identifier=cat(c$id$orig_h, query)]);
        }
    }

    # Detection 4: Base64/Hex encoded data in queries
    if (suspicious_patterns in subdomain)
    {
        NOTICE([$note=DNS_Tunneling_Detected,
                $conn=c,
                $msg="DNS query contains encoded data pattern",
                $sub=fmt("Query: %s", query),
                $identifier=cat(c$id$orig_h, query)]);
    }
}

## Track query rates per source IP
event zeek_init()
{
    # SumStats for query rate monitoring
    local r1: SumStats::Reducer = [$stream="dns.query.rate",
                                   $apply=set(SumStats::SUM)];

    SumStats::create([$name="detect-dns-query-flood",
                      $epoch=1min,
                      $reducers=set(r1),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
                          {
                          return result["dns.query.rate"]$sum;
                          },
                      $threshold=max_queries_per_minute + 0.0,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                          {
                          local src_ip = key$host;
                          NOTICE([$note=DNS_Query_Flood,
                                  $src=src_ip,
                                  $msg=fmt("DNS query flood detected from %s", src_ip),
                                  $sub=fmt("Queries: %.0f in 1 minute", result["dns.query.rate"]$sum),
                                  $identifier=cat(src_ip)]);
                          }]);
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) &priority=-5
{
    # Increment query counter
    SumStats::observe("dns.query.rate", [$host=c$id$orig_h], [$num=1]);
}

event zeek_done()
{
    print "DNS Tunneling Detection: Monitoring stopped";
}
