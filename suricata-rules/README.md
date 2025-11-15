# Suricata Custom Rules

Custom detection rules for signature-based network intrusion detection.

---

## 📁 Rule Files Overview

| File | Rules | Description |
|------|-------|-------------|
| `emerging_threats.rules` | 30+ | Current threat landscape patterns |
| `ransomware_signatures.rules` | 40+ | Ransomware family detection |
| `botnet_detection.rules` | 50+ | C2 communication patterns |
| `protocol_exploits.rules` | 60+ | CVE exploits and protocol attacks |
| `custom_detections.rules` | 10+ | Environment-specific rules |

**Total:** 190+ detection signatures

---

## 🎯 Rule Categories

### **Ransomware (SID: 2400000-2400999)**
- WannaCry, Ryuk, LockBit, REvil, Maze, Conti, DarkSide, BlackMatter, Hive, Babuk, Phobos
- Generic ransomware behaviors (shadow copy deletion, TOR payment sites, etc.)

### **Botnets (SID: 2500000-2500999)**
- Emotet, TrickBot, QakBot, Mirai, Dridex, Cobalt Strike, Metasploit, Zeus, njRAT, Ursnif, IcedID
- Generic C2 patterns (beaconing, IRC channels, P2P communication)

### **Protocol Exploits (SID: 2600000-2600999)**
- SMB: EternalBlue, SMBGhost, BlueKeep, EternalRomance, Zerologon
- Web: Log4Shell, Struts, ProxyShell, ProxyLogon, Spring4Shell
- Others: Shellshock, Heartbleed, PrintNightmare

### **Emerging Threats (SID: 2300000-2399999)**
- Web attacks (SQL injection, XSS, command injection)
- Data exfiltration patterns
- Cryptocurrency mining
- Reconnaissance tools (Nmap, Masscan)

### **Custom Detections (SID: 2700000-2799999)**
- Policy violations (TOR, VPNs, crypto exchanges)
- Internal scanning
- Unusual traffic patterns

---

## ✍️ Rule Syntax

### Basic Structure
```
alert <protocol> <src_ip> <src_port> -> <dst_ip> <dst_port> (
  msg:"<description>";
  <detection_options>;
  classtype:<type>;
  sid:<unique_id>;
  rev:<revision>;
)
```

### Example Rule
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"ET MALWARE Cobalt Strike Beacon User-Agent";
  flow:established,to_server;
  content:"User-Agent: Mozilla/5.0 (compatible; MSIE";
  http_header;
  classtype:trojan-activity;
  sid:2500050;
  rev:1;
)
```

---

## 🔧 Rule Management

### **Enable/Disable Rules**

```bash
# Disable specific rule (comment out)
# alert tcp ... (sid:2300001; ...)

# Disable entire category (in suricata.yaml)
# Comment out rule file in rule-files section
```

### **Test Rules**

```bash
# Validate syntax
docker-compose exec suricata suricata -T -c /etc/suricata/suricata.yaml

# Test with PCAP
docker-compose exec suricata suricata -c /etc/suricata/suricata.yaml -r /pcaps/test.pcap
```

### **Update Rules**

```bash
# Update from Emerging Threats
docker-compose exec suricata suricata-update

# Reload Suricata
docker-compose restart suricata
```

---

## 📊 Rule Performance

### **Check Rule Performance**

```bash
# View rule performance stats
docker-compose exec suricata cat /var/log/suricata/rule_perf.log | head -20
```

### **Identify Slow Rules**

Rules with high processing time may need optimization:
- Use `fast_pattern` for most distinctive content
- Limit use of PCRE (regex)
- Use `depth` and `offset` to reduce search space

---

## 🎨 Writing Custom Rules

### **Best Practices**

1. **Use Specific Classtype**
   ```suricata
   classtype:trojan-activity;  # Good
   classtype:misc-activity;     # Too generic
   ```

2. **Add Fast Pattern**
   ```suricata
   content:"malware"; fast_pattern; content:"payload";
   ```

3. **Use Direction Correctly**
   ```suricata
   alert http $HOME_NET any -> $EXTERNAL_NET any  # Outbound
   alert http $EXTERNAL_NET any -> $HOME_NET any  # Inbound
   ```

4. **Include Metadata**
   ```suricata
   metadata:policy balanced-ips drop, policy security-ips drop;
   reference:url,https://example.com/ioc;
   ```

### **Rule Template**

```suricata
alert <protocol> <source> <port> -> <dest> <port> (
  msg:"<CATEGORY> <Description>";
  flow:<direction>;
  content:"<most_unique_string>"; fast_pattern;
  <additional_detection_logic>;
  classtype:<appropriate_class>;
  sid:<2700000+>;
  rev:1;
)
```

---

## 🚨 Alert Tuning

See [tuning_guide.md](tuning_guide.md) for comprehensive tuning strategies.

### **Quick Tuning**

1. **High False Positives**
   - Add to `threshold.config`
   - Increase detection threshold
   - Add source/dest IP exceptions

2. **Missing Detections**
   - Lower threshold
   - Broaden match criteria
   - Add additional content matches

3. **Performance Issues**
   - Disable low-value rules
   - Optimize PCRE patterns
   - Use `fast_pattern` strategically

---

## 📈 Rule Statistics

### **Count Rules by Category**

```bash
grep -h "^alert" *.rules | wc -l
```

### **List All SIDs**

```bash
grep -h "sid:" *.rules | sed 's/.*sid:\([0-9]*\).*/\1/' | sort -n
```

### **Find Duplicate SIDs**

```bash
grep -h "sid:" *.rules | sed 's/.*sid:\([0-9]*\).*/\1/' | sort | uniq -d
```

---

## 🔍 Hunting with Rules

Use rules as hunting queries:

```bash
# Find all ransomware rules
grep -n "RANSOMWARE" *.rules

# Find rules for specific CVE
grep -n "CVE-2021-44228" *.rules

# Find rules with high severity
grep -n "classtype:attempted-admin" *.rules
```

---

## 📚 Resources

- [Suricata Rules Format](https://suricata.readthedocs.io/en/latest/rules/intro.html)
- [Emerging Threats Rules](https://rules.emergingthreats.net/)
- [Suricata Rule Writing](https://suricata.readthedocs.io/en/latest/rule-management/suricata-update.html)

---

## ✅ Validation Checklist

- [ ] All rules have unique SIDs
- [ ] SID ranges match categories (2300000-2799999)
- [ ] Rules tested with sample PCAPs
- [ ] No syntax errors (`suricata -T`)
- [ ] Performance benchmarked
- [ ] False positives tuned
- [ ] Documentation updated

---

**Questions?** See main [README.md](../README.md) or [tuning_guide.md](tuning_guide.md)
