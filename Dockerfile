FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install system dependencies for packet capture
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    iproute2 \
    iputils-ping \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy application files
COPY network_sniffer.py .
COPY network_sniffer_dashboard.html .
COPY setup.py .
COPY requirements.txt .
COPY README.md .
COPY NETWORK_SNIFFER_GUIDE.md .
COPY INSTALLATION.md .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt 2>/dev/null || true

# Make script executable
RUN chmod +x network_sniffer.py

# Create a non-root user (optional but recommended)
RUN useradd -m -s /bin/bash sniffer && \
    chown -R sniffer:sniffer /app || true

# Use root for packet capturing (required for raw sockets)
USER root

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 network_sniffer.py --help > /dev/null 2>&1 || exit 1

# Expose port if needed
EXPOSE 8080

# Run the packet sniffer
ENTRYPOINT ["python3"]
CMD ["network_sniffer.py"]

# Usage:
# docker build -t network-analyzer .
# docker run --net=host -it network-analyzer
# docker run --net=host -it network-analyzer python3 network_sniffer.py 100
