# KQL Query Library

Pre-built Kibana Query Language (KQL) queries for common threat hunting scenarios.

---

## 🔍 Network Traffic Analysis

### Find All DNS TXT Record Queries
```kql
event.dataset:zeek.dns AND zeek.dns.qtype_name:TXT
```

### High-Entropy DNS Queries
```kql
event.dataset:zeek.dns AND zeek.dns.query:(*[A-Za-z0-9]{20,}* OR *[0-9]{15,}*)
```

### Large HTTP Uploads
```kql
event.dataset:zeek.http AND http.request.method:POST AND http.request.body.bytes > 10000000
```

### Non-Standard Ports for Common Services
```kql
event.dataset:zeek.conn AND (
  (network.transport:tcp AND destination.port:80 AND zeek.conn.service:!http) OR
  (network.transport:tcp AND destination.port:443 AND zeek.conn.service:!ssl)
)
```

---

## 🚨 Alert Analysis

### All Suricata Alerts
```kql
event.dataset:suricata AND event.kind:alert
```

### High-Severity Alerts
```kql
event.dataset:suricata AND event.kind:alert AND alert.severity:(1 OR 2)
```

### Alerts by Signature
```kql
event.dataset:suricata AND event.kind:alert
| stats count() by alert.signature
| sort count() desc
```

### Alerts Timeline
```kql
event.dataset:suricata AND event.kind:alert
| timechart count() by alert.category
```

---

## 🔐 Authentication & Lateral Movement

### RDP Connections
```kql
event.dataset:zeek.rdp OR destination.port:3389
```

### SMB Admin Share Access
```kql
event.dataset:zeek.smb AND zeek.smb.path:(*ADMIN$* OR *C$* OR *IPC$*)
```

### Multiple Failed Logins (if auth logs available)
```kql
event.outcome:failure AND event.category:authentication
| stats count() by source.ip, user.name
| where count() > 5
```

### Lateral Movement Pattern
```kql
event.dataset:zeek.smb OR event.dataset:zeek.rdp
| stats dc(destination.ip) by source.ip
| where dc(destination.ip) > 3
```

---

## 🌐 C2 Communication

### Periodic Connections (Potential Beaconing)
```kql
event.dataset:zeek.conn
| stats count() by source.ip, destination.ip, destination.port
| where count() > 20
```

### Long-Duration Connections
```kql
event.dataset:zeek.conn AND zeek.conn.duration > 3600
```

### Connections to Uncommon Ports
```kql
event.dataset:zeek.conn AND destination.port > 10000
| stats count() by destination.port
| sort count() desc
```

### HTTPS to Non-Standard Ports
```kql
event.dataset:zeek.ssl AND destination.port:!443
```

---

## 🛡️ TLS/SSL Analysis

### Self-Signed Certificates
```kql
event.dataset:zeek.ssl AND zeek.ssl.validation_status:"self signed certificate"
```

### Expired Certificates
```kql
event.dataset:zeek.ssl AND zeek.ssl.validation_status:*expired*
```

### Weak Cipher Suites
```kql
event.dataset:zeek.ssl AND zeek.ssl.cipher:(*RC4* OR *DES* OR *3DES*)
```

### Old TLS Versions
```kql
event.dataset:zeek.ssl AND zeek.ssl.version:(SSLv2 OR SSLv3 OR TLSv10 OR TLSv11)
```

---

## 🔎 Reconnaissance Detection

### Port Scanning Activity
```kql
event.dataset:zeek.conn AND zeek.conn.state:(S0 OR REJ)
| stats dc(destination.port) by source.ip
| where dc(destination.port) > 20
```

### Horizontal Scanning
```kql
event.dataset:zeek.conn
| stats dc(destination.ip) by source.ip, destination.port
| where dc(destination.ip) > 10
```

### Nmap Detection
```kql
event.dataset:suricata AND alert.signature:*Nmap*
```

---

## 📊 Statistics & Baselines

### Top Source IPs
```kql
event.dataset:zeek.conn
| stats count() by source.ip
| sort count() desc
| head 10
```

### Top Destination IPs (External)
```kql
event.dataset:zeek.conn AND NOT destination.ip:(10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16)
| stats count() by destination.ip
| sort count() desc
| head 10
```

### Protocol Distribution
```kql
event.dataset:zeek.conn
| stats count() by network.protocol
```

### Traffic Volume by Hour
```kql
event.dataset:zeek.conn
| timechart span=1h sum(network.bytes)
```

---

## 🦠 Malware Detection

### Known Malicious User-Agents
```kql
event.dataset:zeek.http AND http.request.user_agent:(*bot* OR *crawler* OR *scanner*)
```

### Executable Downloads
```kql
event.dataset:zeek.http AND http.response.mime_type:(application/x-dosexec OR application/x-executable)
```

### Suspicious File Extensions
```kql
event.dataset:zeek.files AND file.name:(*  .exe OR *.dll OR *.bat OR *.ps1)
```

---

## 🌍 GeoIP Analysis

### Connections to High-Risk Countries
```kql
event.dataset:zeek.conn AND destination.geo.country_iso_code:(RU OR CN OR KP OR IR)
```

### Unusual Geographic Access
```kql
event.dataset:zeek.conn AND destination.geo.continent_name:!("North America" OR "Europe")
```

---

## ⏰ Time-Based Analysis

### After-Hours Activity
```kql
event.dataset:zeek.conn AND @timestamp:[00:00 TO 06:00]
```

### Weekend Activity
```kql
event.dataset:zeek.conn AND @timestamp:[Saturday TO Sunday]
```

---

## 🎯 IOC Hunting

### Search for Specific IP
```kql
source.ip:10.0.0.50 OR destination.ip:10.0.0.50
```

### Search for Domain
```kql
zeek.dns.query:*evil.com* OR http.request.host:*evil.com*
```

### Search for File Hash
```kql
file.hash.md5:098f6bcd4621d373cade4e832627b4f6
```

---

## 📈 Advanced Queries

### Connections with No Data Transfer (Potential Scanning)
```kql
event.dataset:zeek.conn AND zeek.conn.orig_bytes:0 AND zeek.conn.resp_bytes:0
```

### Failed Connections Followed by Success
```kql
event.dataset:zeek.conn AND zeek.conn.state:(S0 OR REJ OR RSTO)
```

Then pivot to:
```kql
event.dataset:zeek.conn AND source.ip:[IP_FROM_ABOVE] AND zeek.conn.state:SF
```

### Rare Processes Making Network Connections (if host data available)
```kql
event.category:network AND process.name:*
| stats count() by process.name
| where count() < 5
```

---

## 🛠️ Query Building Tips

1. **Use wildcards strategically**
   - `*admin*` - Contains "admin" anywhere
   - `admin*` - Starts with "admin"
   - `*.exe` - Ends with ".exe"

2. **Combine conditions**
   - `AND` - Both must be true
   - `OR` - Either can be true
   - `NOT` - Must not be true

3. **Use parentheses for logic**
   ```kql
   (source.ip:10.0.0.0/8 OR source.ip:192.168.0.0/16) AND NOT destination.port:80
   ```

4. **Field existence checks**
   ```kql
   _exists_:alert.signature
   ```

5. **Numeric ranges**
   ```kql
   destination.port >= 1024 AND destination.port <= 65535
   ```

---

## 📊 Aggregation Examples

### Count by Field
```kql
event.dataset:zeek.dns
| stats count() by zeek.dns.query
```

### Unique Count
```kql
event.dataset:zeek.conn
| stats dc(destination.ip) by source.ip
```

### Sum Values
```kql
event.dataset:zeek.conn
| stats sum(network.bytes) by source.ip
```

### Multiple Aggregations
```kql
event.dataset:zeek.conn
| stats count(), sum(network.bytes), avg(zeek.conn.duration) by source.ip
```

---

## ⚡ Performance Tips

1. **Limit time range** - Use shortest needed timeframe
2. **Index patterns** - Be specific (zeek-* vs *)
3. **Filter early** - Put most restrictive filters first
4. **Use fields wisely** - Prefer keyword fields over text
5. **Limit results** - Add `| head 100` for large queries

---

**Related:** [hunting_playbook.md](hunting_playbook.md)
