# Screenshots & Visuals

Visual documentation of the Network IDS deployment, dashboards, and detection capabilities.

---

## 📸 Screenshot Gallery

This directory contains screenshots and visual documentation of the project for portfolio presentation and documentation purposes.

---

## 📁 Recommended Screenshots

### **1. Architecture Diagram**
**File:** `architecture-diagram.png`
**Content:** Visual representation of the complete stack
- Network traffic flow
- Component interactions
- Data pipeline
- Service dependencies

**Creation:** Export from ARCHITECTURE.md diagrams or create using draw.io

---

### **2. Kibana Dashboards**

#### **Network Overview Dashboard**
**File:** `dashboard-network-overview.png`
**Shows:**
- Connection volume timeline
- Protocol distribution chart
- Top talkers table
- Real-time metrics

#### **Threat Detection Dashboard**
**File:** `dashboard-threat-detection.png`
**Shows:**
- Alert timeline
- Severity distribution
- Top signatures
- Alert source breakdown (Zeek vs Suricata)

#### **DNS Analysis Dashboard**
**File:** `dashboard-dns-analysis.png`
**Shows:**
- DNS query volume
- Query type distribution
- Long query detection (tunneling indicators)
- Suspicious TXT queries

---

### **3. Alert Examples**

#### **DNS Tunneling Detection**
**File:** `alert-dns-tunneling.png`
**Demonstrates:** Real Zeek detection of DNS tunneling attempt
**Should show:**
- High-entropy domain query
- Query length >50 characters
- Source IP and query details
- Notice log entry

#### **Port Scan Detection**
**File:** `alert-port-scan.png`
**Demonstrates:** Zeek port scan detection
**Should show:**
- Scanning host IP
- Number of ports scanned
- Time window
- Notice severity

#### **Lateral Movement Detection**
**File:** `alert-lateral-movement.png`
**Demonstrates:** RDP/SMB lateral movement
**Should show:**
- Source and destination IPs
- Protocol (RDP/SMB)
- Multiple connection attempts
- Time correlation

---

### **4. Zeek Logs**

**File:** `zeek-logs-example.png`
**Shows:** Zeek log output demonstrating:
- JSON format
- Rich metadata (protocols, timestamps, IPs)
- Custom script output
- Connection details

**Command to capture:**
```bash
docker-compose exec zeek tail -20 /opt/zeek/logs/current/conn.log | jq
```

---

### **5. Suricata Alerts**

**File:** `suricata-alerts-example.png`
**Shows:** Suricata EVE JSON output:
- Alert signature
- Source/destination
- Severity level
- Payload information

**Command to capture:**
```bash
docker-compose exec suricata tail -20 /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'
```

---

### **6. Deployment Success**

**File:** `deployment-success.png`
**Shows:** Successful deployment output from `deploy.sh`:
- All containers running
- Health checks passed
- Access points displayed
- Green success indicators

---

### **7. Test Results**

**File:** `test-results-passing.png`
**Shows:** Output from `test-detection.sh`:
- All 26 tests passed
- Green checkmarks
- Summary statistics

---

### **8. Performance Metrics**

**File:** `performance-dashboard.png`
**Shows:** System performance (from `docker stats` or Kibana):
- CPU usage per container
- Memory utilization
- Network I/O
- Packet processing rate

---

### **9. Threat Hunting in Action**

**File:** `threat-hunting-kibana.png`
**Shows:** Kibana Discover interface:
- KQL query in search bar
- Filtered results
- Event details expanded
- Field analysis sidebar

**Example Query to capture:**
```kql
event.dataset:zeek.dns AND zeek.dns.query_length > 50
```

---

### **10. Elasticsearch Cluster Health**

**File:** `elasticsearch-health.png`
**Shows:** Elasticsearch cluster status:
```bash
curl -u elastic:changeme http://localhost:9200/_cluster/health?pretty
```
**Demonstrates:**
- Cluster status: green
- Number of nodes
- Active shards
- Index count

---

## 🎨 Creating Screenshots

### **Taking Screenshots**

**macOS:**
```bash
# Full screen
Cmd + Shift + 3

# Selection
Cmd + Shift + 4

# Window
Cmd + Shift + 4, then Space
```

**Linux (GNOME):**
```bash
# Screenshot tool
gnome-screenshot -i

# Or install Flameshot
sudo apt install flameshot
flameshot gui
```

**Windows:**
```bash
# Snipping Tool
Win + Shift + S

# Or use Greenshot
https://getgreenshot.org/
```

### **Optimization**

**Compress screenshots:**
```bash
# Install optipng
sudo apt install optipng  # Linux
brew install optipng      # macOS

# Optimize PNG files
optipng -o7 screenshots/*.png

# Or use ImageMagick
convert input.png -quality 85 output.png
```

**Recommended settings:**
- Format: PNG (lossless) or JPG (80-90% quality)
- Resolution: 1920x1080 or higher
- File size: <500KB per screenshot (optimize if larger)

---

## 📐 Screenshot Standards

### **Best Practices**

1. **Clean Interface:**
   - Hide sensitive information (real IPs, hostnames)
   - Use consistent test data
   - Remove clutter from desktop/browser

2. **Consistent Branding:**
   - Same browser/terminal theme
   - Consistent Kibana theme (dark or light)
   - Professional appearance

3. **Highlighting:**
   - Use arrows or boxes to highlight key elements
   - Add annotations if needed (use draw.io, Preview, or GIMP)

4. **Context:**
   - Include timestamps
   - Show full interface when possible
   - Capture legends and labels

5. **File Naming:**
   ```
   [component]-[feature]-[description].png

   Examples:
   kibana-dashboard-threat-detection.png
   zeek-alert-dns-tunneling.png
   deployment-success-output.png
   ```

### **Sensitive Information**

**Always redact or replace:**
- Internal IP addresses (use 10.0.0.0/8 range)
- Real domain names (use example.com, test.local)
- Credentials or API keys
- Real usernames
- Production hostnames

**Safe replacement values:**
- IPs: 10.0.0.1, 10.0.0.2, 192.168.1.100
- Domains: example.com, malicious.test, attacker.example
- Users: analyst, admin, testuser
- Hosts: ids-server, monitoring-host, test-client

---

## 🖼️ Using Screenshots

### **In Documentation**

**Markdown syntax:**
```markdown
![Dashboard Screenshot](screenshots/dashboard-threat-detection.png)
*Figure 1: Threat Detection Dashboard showing real-time alerts*
```

**With captions:**
```markdown
<figure>
  <img src="screenshots/zeek-alert-dns-tunneling.png" alt="DNS Tunneling Alert">
  <figcaption>Zeek detecting high-entropy DNS query indicative of tunneling</figcaption>
</figure>
```

### **In Presentations**

- Use high-resolution (1920x1080+) for presentations
- Create a PowerPoint/Keynote deck with annotated screenshots
- Add speaker notes explaining what each screenshot demonstrates
- Practice walkthrough for interviews

### **In Portfolio/GitHub**

- Add screenshot gallery to main README
- Create a Wiki page with visual walkthrough
- Include in GitHub Releases for versioning
- Use screenshots in social media posts about the project

---

## 🎬 Video Demonstrations

### **Recommended Recordings**

**1. Deployment Demo (2-3 minutes)**
- Clone repository
- Run deploy.sh
- Show successful startup
- Access Kibana
- Quick tour of dashboards

**2. Detection in Action (3-5 minutes)**
- Generate malicious traffic
- Show alerts in real-time
- Investigate in Kibana
- Demonstrate threat hunting query

**3. Complete Walkthrough (10-15 minutes)**
- Architecture explanation
- Component overview
- Detection capabilities
- Threat hunting example
- Performance metrics

### **Recording Tools**

**Screen Recording:**
- **macOS:** QuickTime (Cmd+Shift+5)
- **Linux:** SimpleScreenRecorder, OBS Studio
- **Windows:** OBS Studio, Xbox Game Bar (Win+G)

**Video Editing:**
- **Free:** DaVinci Resolve, Shotcut
- **Paid:** Adobe Premiere, Final Cut Pro

**GIF Creation:**
```bash
# Convert video to GIF
ffmpeg -i input.mp4 -vf "fps=10,scale=800:-1:flags=lanczos" output.gif

# Optimize GIF
gifsicle -O3 --lossy=80 -o optimized.gif output.gif
```

---

## 📋 Screenshot Checklist

Before creating portfolio/documentation:

- [ ] Architecture diagram created and added
- [ ] All 3 Kibana dashboards captured
- [ ] At least 3 different alert types shown
- [ ] Deployment success screenshot
- [ ] Test results (all passing)
- [ ] Zeek log example
- [ ] Suricata alert example
- [ ] Threat hunting in Kibana
- [ ] Performance metrics
- [ ] Screenshots optimized (<500KB each)
- [ ] Sensitive information redacted
- [ ] Files properly named
- [ ] Added to main README or documentation

---

## 🔗 Integration with README

### **Add Screenshot Gallery Section**

```markdown
## 📸 Screenshots

### Deployment
![Deployment Success](screenshots/deployment-success.png)

### Dashboards
![Threat Detection Dashboard](screenshots/dashboard-threat-detection.png)
![DNS Analysis Dashboard](screenshots/dashboard-dns-analysis.png)

### Live Detection
![DNS Tunneling Alert](screenshots/alert-dns-tunneling.png)
![Port Scan Detection](screenshots/alert-port-scan.png)
```

---

## 💡 Tips for Professional Screenshots

1. **Use Dark Mode** - Generally looks more professional in security contexts
2. **Maximize Windows** - Show full interface, not just partial views
3. **Include Legends** - Ensure all labels and legends are visible
4. **Consistent Timezone** - Use UTC or clearly label timezone
5. **Professional Browser** - Clear bookmarks bar, use clean tab titles
6. **Terminal Aesthetics** - Use a nice theme (Solarized, Dracula, etc.)
7. **Real-Looking Data** - Use realistic but safe test data

---

## 📚 Additional Resources

- [Creating Great Screenshots - Mozilla](https://developer.mozilla.org/en-US/docs/MDN/Contribute/Howto/Screenshots)
- [GIMP Tutorial](https://www.gimp.org/tutorials/) - For editing and annotation
- [Draw.io](https://www.diagrams.net/) - For creating diagrams
- [Carbon](https://carbon.now.sh/) - Beautiful code screenshots

---

**Last Updated:** 2024-11-15
**Version:** 1.2.0
**Status:** Ready for screenshot collection

**Note:** This directory is currently empty. Screenshots will be added as the project is deployed and demonstrated. For your portfolio, please follow the guidelines above to create professional, informative visual documentation.
