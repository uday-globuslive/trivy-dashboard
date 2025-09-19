# Docker Usage Guide

This guide covers Docker deployment options for the Trivy Security Dashboard.

## 🐳 Quick Start with Docker Hub

### Pull and Run
```bash
# Pull the latest stable image
docker pull yourusername/trivy-security-dashboard:latest

# Run with McCamish Nexus configuration
docker run -d \
  --name trivy-dashboard \
  -p 5000:5000 \
  -e NEXUS_URL=http://swdlvapp682.mccamish.com:8081 \
  -e NEXUS_USERNAME=your-username \
  -e NEXUS_PASSWORD=your-password \
  -e NEXUS_REPOSITORY=mccamish_sbom \
  -e NEXUS_GROUP_ID=com.mccamish \
  -e NEXUS_ARTIFACT_SUFFIX=.sbom \
  yourusername/trivy-security-dashboard:latest
```

### Access Dashboard
- Dashboard: http://localhost:5000
- Health Check: http://localhost:5000/api/health
- Debug Info: http://localhost:5000/debug/nexus

## ⚙️ Environment Configuration

### Required Variables
```bash
NEXUS_URL=http://your-nexus.company.com:8081    # Nexus Repository URL
NEXUS_USERNAME=your-username                     # Nexus authentication username
NEXUS_PASSWORD=your-password                     # Nexus authentication password
NEXUS_REPOSITORY=your-sbom-repository           # Repository containing SBOM files
```

### Generic Pattern Variables (customize for your setup)
```bash
# For Jenkins upload pattern: groupId/artifactId/version/filename
NEXUS_GROUP_ID=com.mccamish                     # Maven groupId
NEXUS_ARTIFACT_SUFFIX=.sbom                     # Suffix for artifactId
NEXUS_VERSION_PREFIX=1.0.0-                     # Version prefix before timestamp
NEXUS_ASSET_EXTENSION=json                      # File extension for SBOM files
```

### Optional Configuration
```bash
# Application Settings
FLASK_DEBUG=false                               # Enable debug mode
LOG_LEVEL=INFO                                 # Logging level (DEBUG, INFO, WARNING, ERROR)
CACHE_TTL=300                                  # Cache time-to-live in seconds
DATA_REFRESH_INTERVAL=600                      # Background refresh interval in seconds

# Performance Settings
NEXUS_TIMEOUT=30                               # Nexus API timeout in seconds
MAX_SCANS_PER_PROJECT=50                       # Maximum scans to keep per project
```

## 🐙 Docker Compose Deployment

### Complete Stack
```yaml
version: '3.8'

services:
  trivy-dashboard:
    image: yourusername/trivy-security-dashboard:latest
    container_name: trivy-dashboard
    ports:
      - "5000:5000"
    environment:
      # Nexus Configuration
      - NEXUS_URL=http://nexus:8081
      - NEXUS_USERNAME=admin
      - NEXUS_PASSWORD=admin123
      - NEXUS_REPOSITORY=trivy-reports
      
      # Generic Pattern (customize for your setup)
      - NEXUS_GROUP_ID=com.example
      - NEXUS_ARTIFACT_SUFFIX=.sbom
      - NEXUS_VERSION_PREFIX=1.0.0-
      - NEXUS_ASSET_EXTENSION=json
      
      # Application Settings
      - FLASK_ENV=production
      - LOG_LEVEL=INFO
      - CACHE_TTL=300
      - DATA_REFRESH_INTERVAL=600
    volumes:
      - ./logs:/app/logs
    restart: unless-stopped
    depends_on:
      - nexus
    networks:
      - trivy-network

  # Optional: Include Nexus if you don't have one
  nexus:
    image: sonatype/nexus3:latest
    container_name: nexus-repository
    ports:
      - "8081:8081"
    volumes:
      - nexus-data:/nexus-data
    environment:
      - INSTALL4J_ADD_VM_PARAMS=-Xms1g -Xmx1g
    restart: unless-stopped
    networks:
      - trivy-network

networks:
  trivy-network:
    driver: bridge

volumes:
  nexus-data:
    driver: local
```

### Start Services
```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f trivy-dashboard

# Stop services
docker-compose down
```

## 🔍 Troubleshooting

### Debug Connection Issues
```bash
# Check debug endpoint
curl http://localhost:5000/debug/nexus

# View container logs
docker logs trivy-dashboard

# Check health status
curl http://localhost:5000/api/health
```

### Common Issues

#### No SBOM Files Found
```bash
# Verify Nexus configuration
docker exec trivy-dashboard env | grep NEXUS

# Check if repository exists and contains files
curl -u username:password "http://nexus:8081/service/rest/v1/repositories"
```

#### Connection Refused
```bash
# Check if Nexus is accessible from container
docker exec trivy-dashboard curl -I http://your-nexus:8081

# Verify network connectivity
docker network ls
docker network inspect <network_name>
```

#### Permission Denied
```bash
# Check authentication
curl -u username:password "http://nexus:8081/service/rest/v1/status"

# Verify credentials in environment
docker exec trivy-dashboard env | grep -E "(NEXUS_USERNAME|NEXUS_PASSWORD)"
```

## 🚀 Production Deployment

### With Reverse Proxy (Nginx)
```nginx
server {
    listen 80;
    server_name trivy-dashboard.company.com;
    
    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### With SSL/TLS
```bash
# Generate SSL certificate (Let's Encrypt example)
certbot --nginx -d trivy-dashboard.company.com

# Update Docker run command
docker run -d \
  --name trivy-dashboard \
  -p 127.0.0.1:5000:5000 \
  --env-file .env \
  --restart unless-stopped \
  yourusername/trivy-security-dashboard:latest
```

### Resource Limits
```bash
# Run with resource constraints
docker run -d \
  --name trivy-dashboard \
  -p 5000:5000 \
  --memory=512m \
  --cpus=1.0 \
  --env-file .env \
  --restart unless-stopped \
  yourusername/trivy-security-dashboard:latest
```

## 📊 Monitoring

### Health Checks
```bash
# Built-in health check
curl http://localhost:5000/api/health

# Docker health status
docker inspect --format='{{.State.Health.Status}}' trivy-dashboard
```

### Metrics Collection
```bash
# Container stats
docker stats trivy-dashboard

# Application logs
docker logs -f trivy-dashboard --tail 100
```

### Alerts
Set up monitoring for:
- Container health status
- Nexus connectivity
- Dashboard response time
- Error rates in logs

## 🔄 Updates

### Update to Latest Version
```bash
# Stop current container
docker stop trivy-dashboard
docker rm trivy-dashboard

# Pull latest image
docker pull yourusername/trivy-security-dashboard:latest

# Start with same configuration
docker run -d \
  --name trivy-dashboard \
  -p 5000:5000 \
  --env-file .env \
  --restart unless-stopped \
  yourusername/trivy-security-dashboard:latest
```

### Using Docker Compose
```bash
# Update and restart
docker-compose pull
docker-compose up -d
```

This Docker setup provides a robust, scalable deployment option for the Trivy Security Dashboard with full configuration flexibility.
