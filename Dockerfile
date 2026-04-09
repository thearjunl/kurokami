# Multi-stage build for KUROKAMI production deployment
FROM python:3.11-slim as builder

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    make \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim

# Install security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    nikto \
    whois \
    dnsutils \
    dnsenum \
    whatweb \
    curl \
    gobuster \
    smbclient \
    sslscan \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash kurokami

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=kurokami:kurokami . .

# Create data directories
RUN mkdir -p data/exports data/logs data/vector_store && \
    chown -R kurokami:kurokami data

# Switch to non-root user
USER kurokami

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV KUROKAMI_ENV=production

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "from core.database import init_db; init_db()" || exit 1

# Default command
CMD ["python", "-m", "core.cli"]
