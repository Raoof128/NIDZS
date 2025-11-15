# Logs Directory

This directory stores logs from Zeek and Suricata.

## Structure

```
logs/
├── zeek/
│   ├── current/      # Current session logs
│   │   ├── conn.log
│   │   ├── dns.log
│   │   ├── http.log
│   │   └── ...
│   └── archived/     # Rotated logs
│
└── suricata/
    ├── eve.json      # Unified JSON output
    ├── fast.log      # Fast alert format
    ├── stats.log     # Performance stats
    └── suricata.log  # Daemon logs
```

## Viewing Logs

### Zeek Logs

```bash
# View connection logs
docker-compose exec zeek tail -f /opt/zeek/logs/current/conn.log

# View DNS queries
docker-compose exec zeek tail -f /opt/zeek/logs/current/dns.log

# View notices (alerts)
docker-compose exec zeek tail -f /opt/zeek/logs/current/notice.log
```

### Suricata Logs

```bash
# View all events (JSON format)
docker-compose exec suricata tail -f /var/log/suricata/eve.json

# View fast alerts
docker-compose exec suricata tail -f /var/log/suricata/fast.log

# View statistics
docker-compose exec suricata tail -f /var/log/suricata/stats.log
```

## Log Rotation

Zeek automatically rotates logs every hour. Archived logs are compressed with gzip.

## Disk Space

Monitor disk usage:

```bash
du -sh logs/*
```

Clean old logs (older than 30 days):

```bash
find logs/ -name "*.gz" -mtime +30 -delete
```

## Troubleshooting

**No logs appearing:**
1. Check containers are running: `docker-compose ps`
2. Verify network traffic is being captured
3. Check permissions: `ls -la logs/`

**Logs not shipping to Elasticsearch:**
1. Check Filebeat logs: `docker-compose logs filebeat`
2. Verify paths in filebeat-config.yml match this directory
3. Ensure Elasticsearch is accessible

---

**Note:** Log files are gitignored for security and size reasons.
