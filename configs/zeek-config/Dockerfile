# Zeek Network Security Monitor Container
# Based on official Zeek image with custom detection scripts

FROM zeek/zeek:6.0.0

LABEL maintainer="Raouf <raouf@network-ids>"
LABEL description="Zeek IDS with custom protocol analysis scripts"

# Install additional tools
USER root
RUN apt-get update && apt-get install -y \
    tcpreplay \
    tcpdump \
    net-tools \
    iproute2 \
    curl \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p /opt/zeek/logs/current \
             /opt/zeek/share/zeek/site/custom \
             /opt/zeek/etc \
             /pcaps

# Set permissions
RUN chown -R zeek:zeek /opt/zeek/logs \
                        /opt/zeek/share/zeek/site/custom

# Copy configuration files
COPY local.zeek /opt/zeek/share/zeek/site/
COPY node.cfg /opt/zeek/etc/
COPY networks.cfg /opt/zeek/etc/
COPY zeekctl.cfg /opt/zeek/etc/

# Set ownership
RUN chown -R zeek:zeek /opt/zeek/etc

# Switch to zeek user
USER zeek

# Set working directory
WORKDIR /opt/zeek

# Environment variables
ENV PATH="/opt/zeek/bin:${PATH}"
ENV ZEEK_INTERFACE="any"

# Expose ports (if needed for remote management)
EXPOSE 47760-47780

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD zeekctl status || exit 1

# Default command - start Zeek
CMD ["zeekctl", "deploy"]
