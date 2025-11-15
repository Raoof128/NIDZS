# Sample Traffic Directory

This directory contains sample PCAP files for testing the Network IDS.

---

## 📁 Directory Purpose

Place test PCAP files here for:
- Testing detection rules
- Validating Zeek/Suricata configurations
- Training and demonstrations
- Performance benchmarking

---

## 🔍 Recommended Test Datasets

### **Public PCAP Repositories**

1. **CICIDS2017** - Comprehensive intrusion dataset
   - https://www.unb.ca/cic/datasets/ids-2017.html
   - Contains: DDoS, brute force, web attacks, infiltration

2. **Stratosphere IPS** - Malware captures
   - https://www.stratosphereips.org/datasets-overview
   - Contains: Botnet traffic, malware C2

3. **Malware Traffic Analysis** - Real-world malware PCAPs
   - https://www.malware-traffic-analysis.net/
   - Updated weekly with new malware samples

4. **SecRepo** - Security data samples
   - http://www.secrepo.com/
   - Various attack scenarios

---

## 🚀 Usage

### **Replay PCAP with tcpreplay**

```bash
# Replay to Zeek
docker-compose exec zeek tcpreplay -i eth0 /pcaps/malicious.pcap

# Replay to Suricata
docker-compose exec suricata tcpreplay -i any /pcaps/malicious.pcap
```

### **Offline Analysis with Zeek**

```bash
# Analyze PCAP offline
docker-compose exec zeek zeek -r /pcaps/malicious.pcap custom/detect_dns_tunneling.zeek

# Check generated logs
docker-compose exec zeek ls -l /opt/zeek/logs/current/
```

### **Offline Analysis with Suricata**

```bash
# Analyze PCAP offline
docker-compose exec suricata suricata -c /etc/suricata/suricata.yaml -r /pcaps/malicious.pcap

# Check alerts
docker-compose exec suricata cat /var/log/suricata/fast.log
```

---

## 📊 Example PCAPs to Download

```bash
# Create sample-traffic directory if needed
cd sample-traffic

# Download sample malware PCAP
wget https://www.malware-traffic-analysis.net/sample.pcap

# Download port scan PCAP
wget https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=nmap-1.pcap

# Generate custom traffic (requires nmap, hping3)
# Port scan
nmap -p 1-1000 192.168.1.1 -oN /tmp/scan.txt

# Capture during scan
tcpdump -i eth0 -w portscan.pcap port 80
```

---

## ⚠️ Security Notice

**Do NOT execute malware from PCAP files!**

- Only replay network traffic for analysis
- Use isolated lab environment
- Never run on production networks
- Malware PCAPs may contain real threats

---

## 📋 Naming Convention

Use descriptive names:
```
attack-type_date_description.pcap

Examples:
- portscan_2024-11-15_nmap-syn.pcap
- malware_2024-11-15_emotet-c2.pcap
- webattack_2024-11-15_sqli-attempt.pcap
- ddos_2024-11-15_syn-flood.pcap
```

---

## 🔬 Generating Custom Test Traffic

### **DNS Tunneling Test**

```bash
# Generate long DNS queries
for i in {1..50}; do
    dig $(python3 -c "print('A'*60)")test.com @8.8.8.8
done
```

### **Port Scan Test**

```bash
# Horizontal scan
nmap -sS -p 22,80,443 192.168.1.0/24

# Vertical scan
nmap -p 1-1000 192.168.1.10
```

### **C2 Beaconing Simulation**

```bash
# Periodic connections
while true; do
    curl -s http://example.com >/dev/null
    sleep 60
done
```

---

## 📂 File Structure

```
sample-traffic/
├── README.md (this file)
├── malicious/
│   ├── emotet_c2.pcap
│   ├── wannacry.pcap
│   └── cobalt_strike.pcap
├── attacks/
│   ├── sql_injection.pcap
│   ├── xss_attack.pcap
│   └── command_injection.pcap
├── reconnaissance/
│   ├── nmap_scan.pcap
│   ├── masscan.pcap
│   └── dns_enum.pcap
└── normal/
    └── baseline_traffic.pcap
```

---

## ✅ Testing Checklist

- [ ] Download at least 3 malware PCAPs
- [ ] Download attack scenario PCAPs (SQL injection, XSS, etc.)
- [ ] Generate port scan PCAP
- [ ] Create baseline normal traffic PCAP
- [ ] Test replay functionality
- [ ] Verify detection alerts generated
- [ ] Document detection accuracy

---

**Note:** `.pcap` files are gitignored. Only documentation is tracked in version control.
