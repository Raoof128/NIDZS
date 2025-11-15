# Suricata IDS/IPS Container
# Based on official Suricata image with custom rules

FROM jasonish/suricata:7.0

LABEL maintainer="Raouf <raouf@network-ids>"
LABEL description="Suricata IDS with custom signature detection rules"

# Install additional tools
USER root
RUN apt-get update && apt-get install -y \
    tcpreplay \
    tcpdump \
    net-tools \
    iproute2 \
    curl \
    vim \
    python3 \
    python3-pip \
    suricata-update \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p /var/log/suricata \
             /etc/suricata/rules \
             /pcaps \
             /var/lib/suricata/update

# Set permissions
RUN chown -R suricata:suricata /var/log/suricata \
                                /etc/suricata/rules \
                                /var/lib/suricata

# Update Suricata rules
RUN suricata-update update-sources && \
    suricata-update enable-source et/open && \
    suricata-update enable-source oisf/trafficid && \
    suricata-update

# Copy custom configuration
COPY suricata.yaml /etc/suricata/suricata.yaml
COPY classification.config /etc/suricata/classification.config
COPY threshold.config /etc/suricata/threshold.config

# Set ownership
RUN chown -R suricata:suricata /etc/suricata

# Switch to suricata user
USER suricata

# Set working directory
WORKDIR /var/log/suricata

# Environment variables
ENV SURICATA_INTERFACE="any"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD suricatasc -c "uptime" || exit 1

# Default command
CMD ["/usr/bin/suricata", "-c", "/etc/suricata/suricata.yaml", "-i", "any"]
