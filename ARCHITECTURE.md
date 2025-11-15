# Network IDS Architecture

This document details the system architecture, data flows, and design decisions for the Network Intrusion Detection System.

---

## 📐 System Architecture Overview

### **High-Level Architecture**

```
┌─────────────────────────────────────────────────────────────────────┐
│                        NETWORK TRAFFIC SOURCES                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │ Live Capture │  │ PCAP Replay  │  │  Simulated   │              │
│  │  (eth0/en0)  │  │   (tcpreplay)│  │   Attacks    │              │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘              │
└─────────┼──────────────────┼──────────────────┼────────────────────┘
          │                  │                  │
          └──────────────────┴──────────────────┘
                             │
          ┌──────────────────┴──────────────────┐
          │                                     │
    ┌─────▼──────┐                      ┌──────▼─────┐
    │   ZEEK     │                      │  SURICATA  │
    │ Container  │                      │ Container  │
    │            │                      │            │
    │ Protocol   │                      │ Signature  │
    │ Analysis   │                      │ Detection  │
    │            │                      │            │
    │ Logs:      │                      │ Alerts:    │
    │ • conn.log │                      │ • eve.json │
    │ • dns.log  │                      │ • fast.log │
    │ • http.log│                      │ • stats.log│
    │ • ssl.log  │                      │            │
    │ • smb.log  │                      │            │
    │ • rdp.log  │                      │            │
    └─────┬──────┘                      └──────┬─────┘
          │                                     │
          │        ┌──────────────┐            │
          └────────► FILEBEAT     ◄────────────┘
                   │ Container    │
                   │              │
                   │ Log Shipping │
                   │ & Parsing    │
                   └──────┬───────┘
                          │
                   ┌──────▼───────┐
                   │ ELASTICSEARCH│
                   │  Container   │
                   │              │
                   │ Indices:     │
                   │ • zeek-*     │
                   │ • suricata-* │
                   │              │
                   │ Storage &    │
                   │ Aggregation  │
                   └──────┬───────┘
                          │
                   ┌──────▼───────┐
                   │   KIBANA     │
                   │  Container   │
                   │              │
                   │ • Dashboards │
                   │ • Hunting    │
                   │ • Analytics  │
                   └──────────────┘
                          │
                   ┌──────▼───────┐
                   │   ANALYSTS   │
                   │ (Port 5601)  │
                   └──────────────┘
```

---

## 🏗️ Component Architecture

### **1. Detection Layer**

#### **Zeek (Protocol Analysis)**

```
┌─────────────────────────────────────────────────────────────┐
│                    ZEEK ARCHITECTURE                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐         ┌─────────────┐                  │
│  │   Manager   │────────►│   Logger    │                  │
│  │  (Control)  │         │ (Log Files) │                  │
│  └─────────────┘         └─────────────┘                  │
│         │                                                   │
│         ▼                                                   │
│  ┌─────────────┐         ┌─────────────┐                  │
│  │   Proxy     │◄────────┤   Worker 1  │                  │
│  │(Load Bal.)  │         │(Packet Proc)│                  │
│  └─────┬───────┘         └─────────────┘                  │
│        │                                                    │
│        ├────────────────►┌─────────────┐                  │
│        │                 │   Worker 2  │                  │
│        │                 │(Packet Proc)│                  │
│        │                 └─────────────┘                  │
│        │                                                    │
│        └────────────────►┌─────────────┐                  │
│                          │   Worker N  │                  │
│                          │(Packet Proc)│                  │
│                          └─────────────┘                  │
│                                                             │
│  Custom Scripts Loaded:                                     │
│  ├── detect_dns_tunneling.zeek                            │
│  ├── detect_c2_beaconing.zeek                             │
│  ├── detect_lateral_movement.zeek                         │
│  ├── detect_port_scanning.zeek                            │
│  └── detect_tls_anomalies.zeek                            │
│                                                             │
└─────────────────────────────────────────────────────────────┘

Log Output:
  /opt/zeek/logs/current/
    ├── conn.log          (All connections)
    ├── dns.log           (DNS queries/responses)
    ├── http.log          (HTTP traffic)
    ├── ssl.log           (TLS/SSL metadata)
    ├── smb.log           (SMB file shares)
    ├── rdp.log           (RDP connections)
    ├── notice.log        (Anomaly alerts)
    └── custom_alerts.log (Custom detection hits)
```

#### **Suricata (Signature Detection)**

```
┌─────────────────────────────────────────────────────────────┐
│                 SURICATA ARCHITECTURE                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐  │
│  │           Packet Acquisition (AF_PACKET)            │  │
│  └───────────────────┬─────────────────────────────────┘  │
│                      │                                     │
│         ┌────────────┼────────────┐                        │
│         ▼            ▼            ▼                        │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐                  │
│  │ Worker 1 │ │ Worker 2 │ │ Worker N │                  │
│  │          │ │          │ │          │                  │
│  │ Decode   │ │ Decode   │ │ Decode   │                  │
│  │ Stream   │ │ Stream   │ │ Stream   │                  │
│  │ Detect   │ │ Detect   │ │ Detect   │                  │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘                  │
│       │            │            │                         │
│       └────────────┴────────────┘                         │
│                    │                                       │
│         ┌──────────▼──────────┐                           │
│         │   Output Threads    │                           │
│         │  • EVE JSON         │                           │
│         │  • Fast Log         │                           │
│         │  • Stats            │                           │
│         └─────────────────────┘                           │
│                                                             │
│  Rule Sources:                                             │
│  ├── Emerging Threats (ET Open)                           │
│  ├── Custom Ransomware Rules                              │
│  ├── Custom Botnet Signatures                             │
│  ├── Protocol Exploit Rules                               │
│  └── Behavioral Anomaly Rules                             │
│                                                             │
└─────────────────────────────────────────────────────────────┘

Log Output:
  /var/log/suricata/
    ├── eve.json      (Unified JSON output - alerts, flows, etc.)
    ├── fast.log      (Fast alert format)
    ├── stats.log     (Performance statistics)
    └── suricata.log  (Daemon logs)
```

### **2. Aggregation Layer**

#### **Filebeat (Log Shipping)**

```
┌─────────────────────────────────────────────────────────────┐
│                  FILEBEAT ARCHITECTURE                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Input Sources:                                             │
│  ┌──────────────────┐         ┌──────────────────┐        │
│  │  Zeek Logs       │         │ Suricata Logs    │        │
│  │ /var/log/zeek/   │         │ /var/log/suricata│        │
│  └────────┬─────────┘         └────────┬─────────┘        │
│           │                            │                   │
│           └────────────┬───────────────┘                   │
│                        ▼                                    │
│              ┌─────────────────┐                           │
│              │  Harvester      │                           │
│              │  (File Reader)  │                           │
│              └────────┬────────┘                           │
│                       ▼                                     │
│              ┌─────────────────┐                           │
│              │  Processors     │                           │
│              │  • Parse JSON   │                           │
│              │  • Add metadata │                           │
│              │  • Enrich       │                           │
│              └────────┬────────┘                           │
│                       ▼                                     │
│              ┌─────────────────┐                           │
│              │  Output Buffer  │                           │
│              └────────┬────────┘                           │
│                       ▼                                     │
│              ┌─────────────────┐                           │
│              │  Elasticsearch  │                           │
│              │   (Bulk API)    │                           │
│              └─────────────────┘                           │
│                                                             │
│  Modules Enabled:                                          │
│  ├── Zeek Module (native parsing)                         │
│  └── Suricata Module (EVE JSON parsing)                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### **3. Storage & Analysis Layer**

#### **Elasticsearch Cluster**

```
┌─────────────────────────────────────────────────────────────┐
│              ELASTICSEARCH ARCHITECTURE                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐  │
│  │                  Master Node                         │  │
│  │  • Cluster coordination                              │  │
│  │  • Index management                                  │  │
│  └────────────────────┬─────────────────────────────────┘  │
│                       │                                     │
│  ┌────────────────────▼────────────────────┐               │
│  │           Data Node (Primary)           │               │
│  │                                          │               │
│  │  Indices:                                │               │
│  │  ┌────────────────────────────────┐    │               │
│  │  │ zeek-YYYY.MM.DD                │    │               │
│  │  │  Shards: 1                     │    │               │
│  │  │  Replicas: 0                   │    │               │
│  │  │  Docs: ~500K/day               │    │               │
│  │  │  Size: ~2GB/day                │    │               │
│  │  └────────────────────────────────┘    │               │
│  │                                          │               │
│  │  ┌────────────────────────────────┐    │               │
│  │  │ suricata-YYYY.MM.DD            │    │               │
│  │  │  Shards: 1                     │    │               │
│  │  │  Replicas: 0                   │    │               │
│  │  │  Docs: ~100K/day               │    │               │
│  │  │  Size: ~500MB/day              │    │               │
│  │  └────────────────────────────────┘    │               │
│  └──────────────────────────────────────────┘               │
│                                                             │
│  Index Lifecycle Management:                               │
│  • Hot Phase: 0-7 days (fast SSD)                         │
│  • Warm Phase: 7-30 days (slower storage)                 │
│  • Delete Phase: >30 days                                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘

Mappings:
  zeek-*:
    • @timestamp (date)
    • source.ip (ip)
    • destination.ip (ip)
    • network.protocol (keyword)
    • zeek.* (dynamic mapping per log type)

  suricata-*:
    • @timestamp (date)
    • alert.signature (text)
    • alert.severity (integer)
    • source.ip (ip)
    • destination.ip (ip)
    • network.protocol (keyword)
```

#### **Kibana Interface**

```
┌─────────────────────────────────────────────────────────────┐
│                  KIBANA ARCHITECTURE                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  User Interface (Port 5601)                                 │
│  ┌─────────────────────────────────────────────────────┐  │
│  │                   Main Menu                          │  │
│  │  ┌─────────────┬─────────────┬─────────────┐        │  │
│  │  │  Discover   │ Dashboards  │  Analytics  │        │  │
│  │  └─────────────┴─────────────┴─────────────┘        │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                             │
│  Pre-Built Dashboards:                                     │
│  ┌─────────────────────────────────────────────────────┐  │
│  │ 1. Network Overview                                  │  │
│  │    • Traffic volume over time                        │  │
│  │    • Top talkers (source/dest IPs)                   │  │
│  │    • Protocol distribution                           │  │
│  │    • Geographic heat map                             │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐  │
│  │ 2. Threat Hunting Dashboard                          │  │
│  │    • Alert timeline                                  │  │
│  │    • Top threats by signature                        │  │
│  │    • DNS anomalies                                   │  │
│  │    • TLS certificate issues                          │  │
│  │    • Port scanning activity                          │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐  │
│  │ 3. Performance Metrics                               │  │
│  │    • Packet processing rate                          │  │
│  │    • Alert generation latency                        │  │
│  │    • False positive trends                           │  │
│  │    • System resource usage                           │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                             │
│  Saved Searches (KQL Queries):                             │
│  • SMB reconnaissance attempts                             │
│  • DNS C2 callbacks                                        │
│  • Port scanning activity                                  │
│  • TLS anomalies                                           │
│  • Lateral movement patterns                               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔄 Data Flow Diagrams

### **End-to-End Data Flow**

```
1. PACKET CAPTURE
   ┌──────────────┐
   │ Network      │
   │ Interface    │
   │ (eth0/en0)   │
   └──────┬───────┘
          │ Raw packets
          ▼
   ┌──────────────┐
   │ libpcap      │
   │ (Capture)    │
   └──────┬───────┘
          │
          ├──────────────────────────────┐
          │                              │
          ▼                              ▼

2. DETECTION
   ┌──────────────┐              ┌──────────────┐
   │ Zeek Worker  │              │  Suricata    │
   │ Threads      │              │  Workers     │
   └──────┬───────┘              └──────┬───────┘
          │                              │
          │ Parse protocols              │ Match signatures
          │ Generate metadata            │ Generate alerts
          │                              │
          ▼                              ▼
   ┌──────────────┐              ┌──────────────┐
   │ conn.log     │              │  eve.json    │
   │ dns.log      │              │  fast.log    │
   │ http.log     │              │              │
   │ ... (15+)    │              │              │
   └──────┬───────┘              └──────┬───────┘
          │                              │
          │                              │

3. LOG SHIPPING
          │                              │
          └──────────────┬───────────────┘
                         ▼
                  ┌──────────────┐
                  │  Filebeat    │
                  │  Harvester   │
                  └──────┬───────┘
                         │
                         │ JSON parsing
                         │ Field enrichment
                         │ Metadata addition
                         │
                         ▼
                  ┌──────────────┐
                  │ Filebeat     │
                  │ Buffer       │
                  └──────┬───────┘
                         │
                         │ Bulk API (batch 1000)
                         │

4. STORAGE
                         ▼
                  ┌──────────────┐
                  │Elasticsearch │
                  │ Ingest Node  │
                  └──────┬───────┘
                         │
                         │ Index routing
                         │ Pipeline processing
                         │
                         ▼
          ┌──────────────┴──────────────┐
          │                             │
   ┌──────▼───────┐            ┌────────▼──────┐
   │ zeek-*       │            │ suricata-*    │
   │ Index        │            │ Index         │
   └──────┬───────┘            └────────┬──────┘
          │                             │
          │                             │

5. ANALYSIS
          │                             │
          └──────────────┬──────────────┘
                         ▼
                  ┌──────────────┐
                  │  Kibana      │
                  │  Query       │
                  │  Engine      │
                  └──────┬───────┘
                         │
                         ▼
                  ┌──────────────┐
                  │ Dashboards   │
                  │ Visualizations│
                  │ Alerts       │
                  └──────────────┘
                         │
                         ▼
                  ┌──────────────┐
                  │   Analyst    │
                  └──────────────┘
```

### **Detection Logic Flow**

```
ZEEK DETECTION PIPELINE
─────────────────────────────────────────────────────
Packet → Protocol Parser → Event Generator → Logger
         │                 │
         │                 └──► Policy Scripts
         │                      │
         │                      ├─► detect_dns_tunneling.zeek
         │                      │   • Checks query length
         │                      │   • Calculates entropy
         │                      │   • Flags if > threshold
         │                      │
         │                      ├─► detect_c2_beaconing.zeek
         │                      │   • Tracks connection intervals
         │                      │   • Detects periodic patterns
         │                      │   • Raises notice if suspicious
         │                      │
         │                      └─► detect_lateral_movement.zeek
         │                          • Monitors RDP/SMB
         │                          • Tracks unique destinations
         │                          • Alerts on spray patterns
         │
         └──► Metadata Extraction
              • Source/Dest IPs
              • Ports, Protocols
              • Timestamps
              • Application data

SURICATA DETECTION PIPELINE
─────────────────────────────────────────────────────
Packet → Decode → Stream Reassembly → Detection Engine
                                       │
                                       ├─► Rule Match
                                       │   • Signature comparison
                                       │   • Pattern matching
                                       │   • Threshold checks
                                       │
                                       ├─► Protocol Analysis
                                       │   • HTTP parser
                                       │   • TLS parser
                                       │   • SMB parser
                                       │
                                       └─► Output
                                           • Generate alert
                                           • Log to EVE JSON
                                           • Update statistics
```

---

## 🎛️ Configuration Architecture

### **Configuration Hierarchy**

```
configs/
├── zeek-config/
│   ├── node.cfg                    # Cluster topology
│   │   • Manager node config
│   │   • Worker thread count
│   │   • Interface assignments
│   │
│   ├── networks.cfg                # Local networks
│   │   • Internal IP ranges
│   │   • Monitored subnets
│   │
│   ├── local.zeek                  # Main config
│   │   • @load directives
│   │   • Custom script imports
│   │   • Global settings
│   │
│   └── zeekctl.cfg                 # Zeek control
│       • Log rotation
│       • Crash handling
│
├── suricata-config/
│   ├── suricata.yaml               # Main config
│   │   • Threading model
│   │   • AF_PACKET settings
│   │   • Rule paths
│   │   • Output modules
│   │
│   ├── threshold.config            # Alert thresholds
│   │   • Suppress noisy rules
│   │   • Rate limiting
│   │
│   └── classification.config       # Alert priorities
│       • Severity levels
│       • Alert categorization
│
├── filebeat-config/
│   ├── filebeat.yml                # Main config
│   │   • Input paths
│   │   • Processors
│   │   • Elasticsearch output
│   │
│   └── modules.d/
│       ├── zeek.yml                # Zeek module
│       └── suricata.yml            # Suricata module
│
└── elasticsearch-kibana/
    ├── elasticsearch.yml           # ES config
    │   • Cluster name
    │   • Memory settings
    │   • Index templates
    │
    └── kibana.yml                  # Kibana config
        • Elasticsearch URL
        • Server port
        • Security settings
```

---

## 🔒 Security Architecture

### **Network Isolation**

```
┌─────────────────────────────────────────────────────────────┐
│                    HOST NETWORK                              │
│                                                              │
│  ┌────────────────────────────────────────────────────┐    │
│  │           Docker Network: ids-network               │    │
│  │           Subnet: 172.20.0.0/16                     │    │
│  │                                                      │    │
│  │  ┌──────────────┐    ┌──────────────┐             │    │
│  │  │ Zeek         │    │ Suricata     │             │    │
│  │  │ 172.20.0.10  │    │ 172.20.0.11  │             │    │
│  │  └──────┬───────┘    └──────┬───────┘             │    │
│  │         │                    │                      │    │
│  │         └────────┬───────────┘                      │    │
│  │                  │                                  │    │
│  │         ┌────────▼─────────┐                        │    │
│  │         │ Filebeat         │                        │    │
│  │         │ 172.20.0.12      │                        │    │
│  │         └────────┬─────────┘                        │    │
│  │                  │                                  │    │
│  │         ┌────────▼─────────┐                        │    │
│  │         │ Elasticsearch    │                        │    │
│  │         │ 172.20.0.20      │                        │    │
│  │         └────────┬─────────┘                        │    │
│  │                  │                                  │    │
│  │         ┌────────▼─────────┐                        │    │
│  │         │ Kibana           │◄───────────────┐       │    │
│  │         │ 172.20.0.21      │                │       │    │
│  │         └──────────────────┘                │       │    │
│  │                                              │       │    │
│  └──────────────────────────────────────────────┼──────┘    │
│                                                  │           │
│  Port Mappings:                                 │           │
│  • 5601 → Kibana (172.20.0.21:5601)            │           │
│  • 9200 → Elasticsearch (172.20.0.20:9200)     │           │
│                                                  │           │
└──────────────────────────────────────────────────┼───────────┘
                                                   │
                                            ┌──────▼──────┐
                                            │   Analyst   │
                                            │  Workstation│
                                            └─────────────┘
```

### **Authentication & Authorization**

```
┌─────────────────────────────────────────────────────────────┐
│                SECURITY LAYERS                               │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Layer 1: Container Isolation                               │
│  ┌──────────────────────────────────────────────┐          │
│  │ • Dedicated network namespace                │          │
│  │ • Resource limits (CPU, memory)              │          │
│  │ • Read-only filesystems where possible       │          │
│  │ • Non-root user execution                    │          │
│  └──────────────────────────────────────────────┘          │
│                                                             │
│  Layer 2: Network Security                                  │
│  ┌──────────────────────────────────────────────┐          │
│  │ • Internal-only communication (172.20.0.0/16)│          │
│  │ • Kibana/ES exposed only on localhost        │          │
│  │ • No direct internet access from containers  │          │
│  └──────────────────────────────────────────────┘          │
│                                                             │
│  Layer 3: Authentication                                    │
│  ┌──────────────────────────────────────────────┐          │
│  │ • Elasticsearch native auth (elastic/pass)   │          │
│  │ • Kibana session management                  │          │
│  │ • TLS for inter-service communication        │          │
│  └──────────────────────────────────────────────┘          │
│                                                             │
│  Layer 4: Access Control                                    │
│  ┌──────────────────────────────────────────────┐          │
│  │ • Role-based access control (RBAC)           │          │
│  │ • Index-level permissions                    │          │
│  │ • Field-level security                       │          │
│  └──────────────────────────────────────────────┘          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 📊 Performance Architecture

### **Resource Allocation**

| Service | CPU Limit | Memory Limit | Disk I/O | Priority |
|---------|-----------|--------------|----------|----------|
| **Zeek** | 4 cores | 4GB | High | Critical |
| **Suricata** | 4 cores | 4GB | High | Critical |
| **Elasticsearch** | 2 cores | 8GB | Very High | High |
| **Kibana** | 1 core | 1GB | Low | Medium |
| **Filebeat** | 0.5 core | 512MB | Medium | High |

### **Scaling Strategy**

```
VERTICAL SCALING (Single Host)
─────────────────────────────────
Current: 8-core, 16GB RAM
  ├─► Zeek: 4 workers
  ├─► Suricata: 4 workers
  ├─► Elasticsearch: 8GB heap
  └─► Total capacity: ~50K pps

Scale Up: 16-core, 32GB RAM
  ├─► Zeek: 8 workers
  ├─► Suricata: 8 workers
  ├─► Elasticsearch: 16GB heap
  └─► Total capacity: ~100K pps


HORIZONTAL SCALING (Multi-Host)
─────────────────────────────────
Sensor Nodes (multiple hosts):
  ├─► Zeek + Suricata + Filebeat
  ├─► Each processes local traffic
  └─► Ship logs to central SIEM

SIEM Node (dedicated host):
  ├─► Elasticsearch cluster (3 nodes)
  ├─► Kibana
  └─► Aggregates all sensor logs
```

---

## 🔍 Detection Coverage Matrix

```
┌─────────────────────────────────────────────────────────────┐
│           MITRE ATT&CK Coverage                              │
├──────────────────┬──────────────────┬──────────────────────┤
│ Tactic           │ Technique        │ Detection Method     │
├──────────────────┼──────────────────┼──────────────────────┤
│ Reconnaissance   │ Network Scanning │ Zeek: Port scan      │
│                  │ Active Scanning  │ Suricata: Nmap sigs  │
├──────────────────┼──────────────────┼──────────────────────┤
│ Initial Access   │ Exploit Public   │ Suricata: CVE rules  │
│                  │ Phishing         │ Zeek: Email analysis │
├──────────────────┼──────────────────┼──────────────────────┤
│ Execution        │ Command Shell    │ Suricata: Web shells │
│                  │ PowerShell       │ Zeek: HTTP anomalies │
├──────────────────┼──────────────────┼──────────────────────┤
│ Persistence      │ Web Shell        │ Suricata: Upload sigs│
│                  │ Scheduled Task   │ Zeek: SMB activity   │
├──────────────────┼──────────────────┼──────────────────────┤
│ Command & Control│ DNS Tunneling    │ Zeek: Custom script  │
│                  │ HTTPS C2         │ Zeek: TLS anomalies  │
│                  │ Beaconing        │ Zeek: Custom script  │
├──────────────────┼──────────────────┼──────────────────────┤
│ Lateral Movement │ RDP              │ Zeek: Custom script  │
│                  │ SMB              │ Zeek: Custom script  │
│                  │ Pass-the-Hash    │ Suricata: NTLM rules │
├──────────────────┼──────────────────┼──────────────────────┤
│ Exfiltration     │ DNS Exfiltration │ Zeek: Custom script  │
│                  │ HTTPS Transfer   │ Suricata: Large upload│
│                  │ Alternative Protocol│ Zeek: Uncommon ports│
└──────────────────┴──────────────────┴──────────────────────┘
```

---

## 📈 Monitoring & Observability

### **Health Check Architecture**

```
┌─────────────────────────────────────────────────────────────┐
│                MONITORING STACK                              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Metrics Collection:                                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │ Zeek Stats   │  │ Suricata     │  │ Elasticsearch│    │
│  │ • Packets/s  │  │ Stats        │  │ Cluster API  │    │
│  │ • Dropped    │  │ • Capture %  │  │ • Index stats│    │
│  │ • Lag time   │  │ • Alerts/s   │  │ • Heap usage │    │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘    │
│         │                 │                 │             │
│         └─────────────────┴─────────────────┘             │
│                           │                               │
│                  ┌────────▼────────┐                      │
│                  │ Filebeat        │                      │
│                  │ (Metrics Module)│                      │
│                  └────────┬────────┘                      │
│                           │                               │
│                  ┌────────▼────────┐                      │
│                  │ Elasticsearch   │                      │
│                  │ (Metrics Index) │                      │
│                  └────────┬────────┘                      │
│                           │                               │
│                  ┌────────▼────────┐                      │
│                  │ Kibana Dashboard│                      │
│                  │ "System Health" │                      │
│                  └─────────────────┘                      │
│                                                             │
│  Key Metrics Tracked:                                      │
│  • Packet Processing Rate (pps)                           │
│  • Alert Generation Latency (seconds)                     │
│  • False Positive Rate (%)                                │
│  • CPU/Memory/Disk Usage                                  │
│  • Service Uptime                                          │
│  • Log Ingestion Rate (events/s)                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Deployment Models

### **Model 1: Single-Host Lab** (Current Implementation)

```
┌────────────────────────────────────────┐
│         Single Docker Host             │
│  ┌──────────────────────────────────┐ │
│  │ All Services Co-Located:         │ │
│  │ • Zeek                           │ │
│  │ • Suricata                       │ │
│  │ • Filebeat                       │ │
│  │ • Elasticsearch                  │ │
│  │ • Kibana                         │ │
│  └──────────────────────────────────┘ │
│                                        │
│  Use Case: Portfolio, testing, demos  │
│  Capacity: ~50K pps, 10GB logs/day    │
└────────────────────────────────────────┘
```

### **Model 2: Distributed Sensors**

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│  Sensor 1   │  │  Sensor 2   │  │  Sensor N   │
│  ┌────────┐ │  │  ┌────────┐ │  │  ┌────────┐ │
│  │ Zeek   │ │  │  │ Zeek   │ │  │  │ Zeek   │ │
│  │Suricata│ │  │  │Suricata│ │  │  │Suricata│ │
│  │Filebeat│ │  │  │Filebeat│ │  │  │Filebeat│ │
│  └───┬────┘ │  │  └───┬────┘ │  │  └───┬────┘ │
└──────┼──────┘  └──────┼──────┘  └──────┼──────┘
       │                │                │
       └────────────────┴────────────────┘
                        │
              ┌─────────▼──────────┐
              │   Central SIEM     │
              │  ┌──────────────┐ │
              │  │Elasticsearch │ │
              │  │  (3-node)    │ │
              │  └──────┬───────┘ │
              │  ┌──────▼───────┐ │
              │  │   Kibana     │ │
              │  └──────────────┘ │
              └────────────────────┘

Use Case: Enterprise deployment
Capacity: 500K+ pps, 100GB+ logs/day
```

---

**This architecture enables:**
- ✅ Scalable detection at 50K+ pps
- ✅ Multi-layered threat coverage
- ✅ Real-time threat hunting
- ✅ Production-grade reliability
- ✅ Portfolio-ready demonstrability

See [SETUP.md](SETUP.md) for deployment instructions.
