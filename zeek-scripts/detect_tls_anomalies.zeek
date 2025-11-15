##! TLS/SSL Anomaly Detection Script
##! Detects suspicious TLS/SSL behavior and certificate issues
##! Author: Raouf - Network IDS Project
##!
##! Detection Methods:
##! - Self-signed certificates
##! - Expired certificates
##! - Certificate validation failures
##! - Unusual cipher suites
##! - Short-lived certificates
##! - JA3 fingerprint anomalies
##! - SSL/TLS version downgrade attacks

@load base/protocols/ssl
@load base/frameworks/notice
@load base/frameworks/files
@load policy/protocols/ssl/validate-certs

module SSL;

export {
    redef enum Notice::Type += {
        ## TLS anomaly detected
        TLS_Anomaly_Detected,
        ## Self-signed certificate
        Self_Signed_Certificate,
        ## Expired certificate
        Expired_Certificate,
        ## Certificate validation failure
        Certificate_Validation_Failed,
        ## Weak cipher suite usage
        Weak_Cipher_Suite,
        ## SSL version downgrade
        SSL_Version_Downgrade,
        ## Suspicious JA3 fingerprint
        Suspicious_JA3_Fingerprint,
    };

    ## Weak/deprecated cipher suites
    const weak_ciphers = set(
        "TLS_RSA_WITH_RC4_128_MD5",
        "TLS_RSA_WITH_RC4_128_SHA",
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_RSA_WITH_DES_CBC_SHA",
        "TLS_DH_anon_WITH_AES_128_CBC_SHA",
        "TLS_NULL_WITH_NULL_NULL"
    ) &redef;

    ## Acceptable TLS versions
    const acceptable_tls_versions = set("TLSv12", "TLSv13") &redef;

    ## Suspicious JA3 hashes (known malware/tools)
    const suspicious_ja3_hashes = set(
        "6734f37431670b3ab4292b8f60f29984",  # Metasploit
        "51c64c77e60f3980eea90869b68c58a8",  # Cobalt Strike
        "a0e9f5d64349fb13191bc781f81f42e1",  # Meterpreter
    ) &redef;

    ## Certificate lifetime threshold (days)
    const min_cert_lifetime = 7 &redef;

    ## Track certificate issues per server
    type CertIssueTracker: record {
        self_signed_count: count;
        expired_count: count;
        validation_failed_count: count;
        first_seen: time;
    };

    global cert_issues: table[addr] of CertIssueTracker &create_expire=1hr;
}

## Check certificate validity period
function check_cert_lifetime(not_before: time, not_after: time): interval
{
    return not_after - not_before;
}

## SSL/TLS Certificate Validation Event
event ssl_established(c: connection)
{
    if (!c?$ssl)
        return;

    local server = c$id$resp_h;
    local ssl_info = c$ssl;

    # Initialize tracker
    if (server !in cert_issues)
    {
        cert_issues[server] = CertIssueTracker(
            $self_signed_count=0,
            $expired_count=0,
            $validation_failed_count=0,
            $first_seen=network_time()
        );
    }

    local tracker = cert_issues[server];

    # Check TLS version
    if (ssl_info?$version)
    {
        if (ssl_info$version !in acceptable_tls_versions)
        {
            NOTICE([$note=SSL_Version_Downgrade,
                    $conn=c,
                    $msg=fmt("Deprecated TLS version: %s -> %s", c$id$orig_h, server),
                    $sub=fmt("Version: %s (should use TLSv1.2+)", ssl_info$version),
                    $identifier=cat(server, ssl_info$version)]);
        }
    }

    # Check cipher suite
    if (ssl_info?$cipher)
    {
        if (ssl_info$cipher in weak_ciphers)
        {
            NOTICE([$note=Weak_Cipher_Suite,
                    $conn=c,
                    $msg=fmt("Weak cipher suite: %s -> %s", c$id$orig_h, server),
                    $sub=fmt("Cipher: %s", ssl_info$cipher),
                    $identifier=cat(server, ssl_info$cipher)]);
        }
    }

    # Check validation status
    if (ssl_info?$validation_status)
    {
        if (ssl_info$validation_status != "ok")
        {
            ++tracker$validation_failed_count;

            NOTICE([$note=Certificate_Validation_Failed,
                    $conn=c,
                    $msg=fmt("Certificate validation failed: %s", server),
                    $sub=fmt("Status: %s, Subject: %s",
                             ssl_info$validation_status,
                             ssl_info?$subject ? ssl_info$subject : "unknown"),
                    $identifier=cat(server, "validation_failed")]);
        }
    }

    # Check for self-signed certificate
    if (ssl_info?$subject && ssl_info?$issuer)
    {
        if (ssl_info$subject == ssl_info$issuer)
        {
            ++tracker$self_signed_count;

            NOTICE([$note=Self_Signed_Certificate,
                    $conn=c,
                    $msg=fmt("Self-signed certificate: %s", server),
                    $sub=fmt("Subject: %s", ssl_info$subject),
                    $identifier=cat(server, "self_signed")]);
        }
    }

    # Check certificate validity period
    if (ssl_info?$cert && ssl_info$cert?$x509)
    {
        local x509 = ssl_info$cert$x509;

        # Check if expired
        if (x509?$certificate && x509$certificate?$not_valid_after)
        {
            local not_after = x509$certificate$not_valid_after;
            if (not_after < network_time())
            {
                ++tracker$expired_count;

                NOTICE([$note=Expired_Certificate,
                        $conn=c,
                        $msg=fmt("Expired certificate: %s", server),
                        $sub=fmt("Expired: %s, Subject: %s",
                                 strftime("%Y-%m-%d", not_after),
                                 ssl_info$subject),
                        $identifier=cat(server, "expired")]);
            }

            # Check for short-lived certificates (potential evasion)
            if (x509$certificate?$not_valid_before)
            {
                local lifetime = check_cert_lifetime(x509$certificate$not_valid_before, not_after);
                if (lifetime < min_cert_lifetime * 1day)
                {
                    NOTICE([$note=TLS_Anomaly_Detected,
                            $conn=c,
                            $msg=fmt("Short-lived certificate: %s", server),
                            $sub=fmt("Lifetime: %.1f days (threshold: %d days)",
                                     lifetime / 1day,
                                     min_cert_lifetime),
                            $identifier=cat(server, "short_lived")]);
                }
            }
        }
    }

    # Check for certificate chain issues
    if (ssl_info?$cert_chain && |ssl_info$cert_chain| == 0)
    {
        NOTICE([$note=TLS_Anomaly_Detected,
                $conn=c,
                $msg=fmt("Missing certificate chain: %s", server),
                $sub=fmt("Server: %s", server),
                $identifier=cat(server, "no_chain")]);
    }

    # Check JA3 fingerprint if available
    if (ssl_info?$ja3)
    {
        if (ssl_info$ja3 in suspicious_ja3_hashes)
        {
            NOTICE([$note=Suspicious_JA3_Fingerprint,
                    $conn=c,
                    $msg=fmt("Suspicious JA3 fingerprint: %s", c$id$orig_h),
                    $sub=fmt("JA3: %s, Server: %s", ssl_info$ja3, server),
                    $identifier=cat(c$id$orig_h, ssl_info$ja3)]);
        }
    }
}

## SSL Client Hello Analysis
event ssl_client_hello(c: connection, version: count, record_version: count,
                       possible_ts: time, client_random: string, session_id: string,
                       ciphers: index_vec, comp_methods: index_vec) &priority=5
{
    # Check for SSLv2/SSLv3 usage
    if (version < 0x0301)  # Less than TLS 1.0
    {
        NOTICE([$note=SSL_Version_Downgrade,
                $conn=c,
                $msg=fmt("Ancient SSL version in use: %s -> %s", c$id$orig_h, c$id$resp_h),
                $sub=fmt("Version: %d (SSLv2/SSLv3)", version),
                $identifier=cat(c$id$orig_h, c$id$resp_h, "ancient_ssl")]);
    }

    # Check for cipher suite downgrade attacks
    if (|ciphers| > 0)
    {
        # Check if only weak ciphers are offered
        local weak_cipher_count = 0;
        for (i in ciphers)
        {
            # Check against known weak cipher identifiers
            if (ciphers[i] <= 0x0005)  # NULL, weak export ciphers
            {
                ++weak_cipher_count;
            }
        }

        if (weak_cipher_count == |ciphers|)
        {
            NOTICE([$note=Weak_Cipher_Suite,
                    $conn=c,
                    $msg=fmt("Only weak ciphers offered: %s", c$id$orig_h),
                    $sub=fmt("Weak ciphers: %d/%d", weak_cipher_count, |ciphers|),
                    $identifier=cat(c$id$orig_h, "only_weak")]);
        }
    }
}

## SSL Server Hello Analysis
event ssl_server_hello(c: connection, version: count, record_version: count,
                       possible_ts: time, server_random: string, session_id: string,
                       cipher: count, comp_method: count) &priority=5
{
    # Check for version downgrade
    if (version < 0x0303)  # Less than TLS 1.2
    {
        NOTICE([$note=SSL_Version_Downgrade,
                $conn=c,
                $msg=fmt("TLS downgrade detected: %s", c$id$resp_h),
                $sub=fmt("Negotiated version: %d (should be TLS 1.2+)", version),
                $identifier=cat(c$id$resp_h, version)]);
    }
}

## Detect SSL/TLS heartbeat (potential Heartbleed)
event ssl_heartbeat(c: connection, is_request: bool, length: count, data: string)
{
    # Heartbleed typically involves oversized heartbeat requests
    if (is_request && length > 16384)  # Max allowed is 16KB
    {
        NOTICE([$note=TLS_Anomaly_Detected,
                $conn=c,
                $msg=fmt("Potential Heartbleed attempt: %s -> %s", c$id$orig_h, c$id$resp_h),
                $sub=fmt("Heartbeat length: %d bytes (max: 16384)", length),
                $identifier=cat(c$id$orig_h, c$id$resp_h, "heartbleed")]);
    }
}

event zeek_init()
{
    print "TLS Anomaly Detection: Monitoring started";
}

event zeek_done()
{
    print "TLS Anomaly Detection: Monitoring stopped";
    print fmt("Tracked %d servers with certificate issues", |cert_issues|);

    # Summary of issues
    for (server in cert_issues)
    {
        local tracker = cert_issues[server];
        if (tracker$self_signed_count > 0 || tracker$expired_count > 0 ||
            tracker$validation_failed_count > 0)
        {
            print fmt("  %s: Self-signed=%d, Expired=%d, Validation Failed=%d",
                      server,
                      tracker$self_signed_count,
                      tracker$expired_count,
                      tracker$validation_failed_count);
        }
    }
}
