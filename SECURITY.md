# Security Policy

## 🔒 Security Overview

This Network Intrusion Detection System is designed for security monitoring and threat detection. While the project itself aims to improve security posture, the deployment and configuration must be secured properly.

---

## 📋 Supported Versions

Security updates are provided for the following versions:

| Version | Supported          | Status |
| ------- | ------------------ | ------ |
| 1.2.x   | ✅ Yes             | Current |
| 1.1.x   | ✅ Yes             | Maintenance |
| 1.0.x   | ⚠️ Limited Support | Legacy |
| < 1.0   | ❌ No              | Deprecated |

**Recommendation:** Always use the latest stable version for the best security posture.

---

## 🐛 Reporting a Vulnerability

### **Do NOT** Create Public Issues for Security Vulnerabilities

If you discover a security vulnerability in this project, please report it responsibly:

**🔴 Critical/High Severity:**
1. **Email:** [Create a security advisory on GitHub](https://github.com/Raoof128/NIDZS/security/advisories/new)
2. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if known)
   - Your contact information

**🟡 Medium/Low Severity:**
- Create a private issue or email with details
- Wait for acknowledgment before public disclosure

**Response Timeline:**
- **Acknowledgment:** Within 48 hours
- **Initial Assessment:** Within 1 week
- **Fix/Patch:** Depends on severity (critical: 1-7 days, high: 1-2 weeks)
- **Public Disclosure:** After patch is available

---

## 🛡️ Security Best Practices

### For Production Deployment

#### 1. **Change Default Credentials**

**❌ Default (INSECURE):**
```yaml
ELASTIC_PASSWORD=changeme
```

**✅ Secure:**
```yaml
ELASTIC_PASSWORD=Y0ur-V3ry-Str0ng-P@ssw0rd-H3r3
```

**Generate Strong Passwords:**
```bash
openssl rand -base64 32
```

#### 2. **Enable TLS/SSL**

**Elasticsearch:**
```yaml
# docker-compose.yml
elasticsearch:
  environment:
    - xpack.security.transport.ssl.enabled=true
    - xpack.security.http.ssl.enabled=true
```

**Kibana:**
```yaml
# elasticsearch-kibana/kibana.yml
server.ssl.enabled: true
server.ssl.certificate: /path/to/cert.crt
server.ssl.key: /path/to/cert.key
```

**Suricata:**
```yaml
# configs/suricata-config/suricata.yaml
outputs:
  - eve-log:
      tls:
        enabled: yes
```

#### 3. **Network Isolation**

**Restrict External Access:**
```yaml
# docker-compose.yml
services:
  elasticsearch:
    ports:
      - "127.0.0.1:9200:9200"  # Bind to localhost only

  kibana:
    ports:
      - "127.0.0.1:5601:5601"  # Bind to localhost only
```

**Use Firewall Rules:**
```bash
# UFW example
sudo ufw allow from 192.168.1.0/24 to any port 5601
sudo ufw deny 5601
```

#### 4. **Implement Access Control**

**Elasticsearch Roles:**
```bash
# Create read-only role
curl -X POST "localhost:9200/_security/role/readonly" \
  -u elastic:PASSWORD \
  -H 'Content-Type: application/json' \
  -d '{
    "indices": [
      {
        "names": [ "zeek-*", "suricata-*" ],
        "privileges": [ "read", "view_index_metadata" ]
      }
    ]
  }'

# Create user with readonly role
curl -X POST "localhost:9200/_security/user/analyst" \
  -u elastic:PASSWORD \
  -H 'Content-Type: application/json' \
  -d '{
    "password": "analyst_password",
    "roles": [ "readonly" ],
    "full_name": "SOC Analyst"
  }'
```

#### 5. **Secure Docker Configuration**

**Run as Non-Root User:**
```yaml
# docker-compose.yml
services:
  zeek:
    user: "1000:1000"  # Non-root UID:GID
```

**Limit Container Resources:**
```yaml
services:
  elasticsearch:
    deploy:
      resources:
        limits:
          cpus: '4.0'
          memory: 8G
```

**Read-Only Filesystems (where possible):**
```yaml
services:
  zeek:
    volumes:
      - ./configs/zeek-config:/configs:ro  # Read-only mount
```

#### 6. **Log Security Events**

**Enable Audit Logging:**
```yaml
# elasticsearch.yml
xpack.security.audit.enabled: true
```

**Monitor Access:**
```kql
# Kibana query for failed login attempts
event.dataset:elasticsearch.audit
AND event.action:authentication_failed
```

#### 7. **Secrets Management**

**❌ Never Commit Secrets:**
```bash
# .gitignore should include:
.env
secrets/
*.key
*.pem
```

**✅ Use Environment Variables:**
```bash
# .env file (not committed)
ELASTIC_PASSWORD=secure_password
ES_JAVA_OPTS=-Xms4g -Xmx4g
```

**✅ Or Use Secrets Management Tools:**
- Docker Secrets
- HashiCorp Vault
- AWS Secrets Manager
- Azure Key Vault

#### 8. **Regular Updates**

**Keep Components Updated:**
```bash
# Update Docker images
docker-compose pull

# Rebuild containers
docker-compose up -d --build

# Update Suricata rules
docker-compose exec suricata suricata-update
```

**Subscribe to Security Advisories:**
- [Elasticsearch Security Announcements](https://www.elastic.co/community/security)
- [Zeek Security Mailing List](https://zeek.org/community/)
- [Suricata OISF](https://suricata.io/category/releases/)

---

## 🔍 Security Checklist

### Pre-Production Deployment

- [ ] All default passwords changed
- [ ] TLS/SSL enabled for all services
- [ ] Services bound to localhost or internal network only
- [ ] Firewall rules configured
- [ ] Role-based access control (RBAC) implemented
- [ ] Secrets stored securely (not in code)
- [ ] All services running as non-root users
- [ ] Resource limits configured
- [ ] Audit logging enabled
- [ ] Regular backup strategy in place
- [ ] Monitoring and alerting configured
- [ ] Security patches applied

### Ongoing Operations

- [ ] Review access logs weekly
- [ ] Update components monthly
- [ ] Review firewall rules quarterly
- [ ] Rotate passwords quarterly
- [ ] Audit user permissions monthly
- [ ] Test backups monthly
- [ ] Review security advisories weekly

---

## 🚨 Known Security Considerations

### 1. **Default Credentials**

**Issue:** Default Elasticsearch password is `changeme`

**Risk:** High - Unauthorized access to SIEM data

**Mitigation:** Change immediately in production (see [Change Default Credentials](#1-change-default-credentials))

### 2. **Unencrypted Traffic**

**Issue:** Default deployment uses HTTP (not HTTPS)

**Risk:** Medium - Man-in-the-middle attacks, credential exposure

**Mitigation:** Enable TLS/SSL for production (see [Enable TLS/SSL](#2-enable-tlsssl))

### 3. **Exposed Ports**

**Issue:** Default binds to 0.0.0.0 (all interfaces)

**Risk:** High - External unauthorized access

**Mitigation:** Bind to localhost or use firewall rules (see [Network Isolation](#3-network-isolation))

### 4. **Docker Socket Exposure**

**Issue:** Containers have access to Docker socket

**Risk:** Medium - Container escape possible

**Mitigation:** Avoid mounting Docker socket unless necessary

### 5. **Sensitive Log Data**

**Issue:** Logs may contain PII or sensitive information

**Risk:** Medium - Privacy violations, compliance issues

**Mitigation:**
- Implement data masking in Logstash/Filebeat
- Set appropriate log retention policies
- Encrypt data at rest

---

## 🔐 Security Features

### Built-in Security

✅ **Elasticsearch Security Features:**
- Authentication (username/password)
- Role-based access control (RBAC)
- Audit logging
- Field-level security
- Document-level security

✅ **Zeek Security:**
- Protocol anomaly detection
- Certificate validation
- File extraction and analysis
- Script-based detections

✅ **Suricata Security:**
- Signature-based detection
- Protocol analysis
- File extraction
- TLS inspection

---

## 📝 Vulnerability Disclosure Policy

### Scope

**In Scope:**
- Authentication bypass
- Unauthorized data access
- Code execution vulnerabilities
- Docker container escape
- Sensitive information disclosure
- Denial of Service (if easily exploitable)

**Out of Scope:**
- Social engineering
- Physical attacks
- DoS requiring significant resources
- Vulnerabilities in third-party dependencies (report to upstream)
- Issues in development/test environments clearly marked as such

### Safe Harbor

Security researchers who:
- Act in good faith
- Avoid privacy violations
- Avoid service disruption
- Report findings responsibly
- Follow this disclosure policy

Will be:
- Acknowledged in release notes (if desired)
- Protected from legal action
- Given credit for their discovery

---

## 🏆 Hall of Fame

Security researchers who have responsibly disclosed vulnerabilities:

*No vulnerabilities reported yet*

<!-- Format:
- **YYYY-MM-DD** - [Researcher Name](link) - Brief description
-->

---

## 📞 Contact

**Security Team:**
- GitHub Security Advisories: [Create Advisory](https://github.com/Raoof128/NIDZS/security/advisories/new)
- GitHub Issues (public, non-security): [Create Issue](https://github.com/Raoof128/NIDZS/issues/new)

**Expected Response Time:**
- Initial Acknowledgment: 48 hours
- Status Update: 1 week
- Resolution: Depends on severity

---

## 📚 Additional Resources

### Security Guides

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [Elasticsearch Security Documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/security-settings.html)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

### Compliance

For organizations requiring compliance:
- **GDPR:** Implement data retention, encryption, access controls
- **HIPAA:** Enable audit logging, encryption at rest/transit
- **PCI-DSS:** Segment networks, encrypt sensitive data, monitor access
- **SOC 2:** Implement access controls, logging, incident response

---

## ⚖️ Disclaimer

This project is provided "as is" for educational and demonstration purposes. While security best practices are encouraged, users are responsible for properly securing their deployments. The maintainers are not liable for security incidents resulting from improper configuration or deployment.

**For Production Use:**
- Perform security hardening
- Conduct security assessments
- Implement defense-in-depth
- Follow your organization's security policies
- Consult with security professionals

---

**Last Updated:** 2024-11-15
**Version:** 1.2.0
**Security Status:** Actively Maintained
