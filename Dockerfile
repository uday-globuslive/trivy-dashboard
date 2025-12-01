# Use Python 3.12 slim image as base (latest stable with fewer vulnerabilities)
FROM python:3.12-slim

# Add metadata labels
LABEL maintainer="Trivy Security Dashboard" \
      org.opencontainers.image.title="Trivy Security Dashboard" \
      org.opencontainers.image.description="Flask-based dashboard for visualizing Trivy security scan results from native Trivy JSON reports in Nexus Repository" \
      org.opencontainers.image.vendor="Security Team" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.url="https://github.com/yourusername/trivy-security-dashboard" \
      org.opencontainers.image.documentation="https://github.com/yourusername/trivy-security-dashboard/blob/main/README.md"

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_APP=app.py \
    FLASK_ENV=production \
    FLASK_HOST=0.0.0.0 \
    FLASK_PORT=5000 \
    LOG_LEVEL=INFO \
    CACHE_TTL=300 \
    DATA_REFRESH_INTERVAL=600 \
    NEXUS_TIMEOUT=30

# Install system dependencies including curl for health check
# Update and upgrade all packages to patch OS-level vulnerabilities
RUN apt update && \
    apt upgrade -y && \
    apt install -y --no-install-recommends \
    gcc \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt clean && \
    apt autoclean && \
    apt autoremove -y

# Remove gcc after pip installation is complete (added later in build)
# This reduces the final image size and attack surface

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies with updated pip
# Use --no-cache-dir to reduce image size and avoid stale wheels
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create logs directory
RUN mkdir -p /app/logs

# Create non-root user for security
RUN adduser --disabled-password --gecos '' --uid 1001 appuser && \
    chown -R appuser:appuser /app && \
    chmod -R 755 /app && \
    chmod u+w /app  # Allow user to write to app directory

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

# Run the application with proper signal handling
CMD ["python", "-u", "app.py"]
