# Trivy Security Dashboard

A comprehensive Flask-based dashboard for visualizing Trivy security scan results from Trivy JSON and CycloneDX SBOM files stored in Nexus/JFrog Repository.

**Status**: Production Ready ✅  
**Last Updated**: January 2, 2026

---

## 📋 Table of Contents

1. [Overview](#-overview)
2. [Features](#-features)
3. [Quick Start](#-quick-start)
4. [Configuration](#-configuration)
5. [Docker Deployment](#-docker-deployment)
6. [Architecture](#-architecture)
7. [Risk Assessment](#-risk-assessment--metrics)
8. [API Endpoints](#-api-endpoints)
9. [Reports & Export](#-reports--export)
10. [Troubleshooting](#-troubleshooting)
11. [Additional Resources](#-additional-resources)

---

## 🎯 Overview

This dashboard provides real-time security insights by:
- Fetching Trivy JSON and CycloneDX SBOM files from Nexus/JFrog Repository
- Parsing vulnerability data from multiple projects and scans
- Displaying interactive charts and analytics with risk assessment
- Automatic Trivy + CycloneDX merging for comprehensive SBOM coverage
- No separate database required - data is fetched directly from repository

### Key Capabilities

| Feature | Description |
|---------|-------------|
| **Dual Repository Support** | Works with both Nexus and JFrog Artifactory |
| **Dual Format Support** | Parses both Trivy JSON and CycloneDX SBOM formats |
| **Automatic Merging** | Combines Trivy vulnerabilities with CycloneDX components/licenses |
| **Risk Scoring** | Weighted severity-based risk calculation (0-100%) |
| **Multi-Project Analytics** | Cross-project vulnerability comparison |
| **Real-time Refresh** | Force refresh button with threading-based updates |
| **Export Options** | PDF and CSV reports, SPDX SBOM export |

---

## 📊 Features

### Security Analysis
- **Vulnerability Trends**: Track vulnerabilities over time with severity breakdown
- **Risk Assessment**: Weighted severity scoring with critical, high, medium, low classification
- **Component Analysis**: Inventory tracking, dependencies, and license information
- **Compliance Reports**: Security posture across all applications
- **Interactive Risk Modal**: Click ℹ️ icon to understand risk calculations

### SBOM Capabilities
- **Automatic SBOM Type Detection**: Identifies component-only vs vulnerability-enhanced SBOMs
- **Hybrid SBOM Merging**: Automatically combines Trivy + CycloneDX data
- **Enhancement Recommendations**: Suggests Trivy commands to add vulnerability data
- **SPDX Export**: Generate SPDX-compliant SBOM exports

### Dashboard Views
- **Main Dashboard** (`/`): Security overview, trending vulnerabilities, critical alerts
- **Projects List** (`/projects`): All projects with risk indicators
- **Project Details** (`/project/<name>`): Security trends, risk assessment, scan history
- **Scan Details** (`/scan/<id>`): Vulnerability list, component details, SBOM info
- **Component Analysis** (`/component_analysis`): Cross-project component search

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
cd trivy-dashboard
pip install -r requirements.txt
```

### 2. Configure Repository Connection
```bash
# Copy environment template
cp .env.example .env

# Edit .env with your settings (see Configuration section)
```

### 3. Run Dashboard
```bash
python app.py
```

### 4. Access Dashboard
Open browser to `http://localhost:5000`

---

## ⚙️ Configuration

### Repository Type Selection

The dashboard supports both Nexus and JFrog. Set `ARTIFACTORY_TYPE` in `.env`:

```bash
# Choose 'nexus' or 'jfrog'
ARTIFACTORY_TYPE=jfrog
```

### Nexus Configuration (when ARTIFACTORY_TYPE=nexus)

```bash
NEXUS_URL=http://your-nexus:8081
NEXUS_USERNAME=your-username
NEXUS_PASSWORD=your-password
NEXUS_REPOSITORY=your-repo-name
NEXUS_GROUP_ID=com.yourcompany
NEXUS_ARTIFACT_SUFFIX=-trivy-report
NEXUS_VERSION_PREFIX=1.0.0-
NEXUS_ASSET_EXTENSION=json
NEXUS_TIMEOUT=30
```

### JFrog Configuration (when ARTIFACTORY_TYPE=jfrog)

```bash
JFROG_URL=https://your-jfrog.jfrog.io
JFROG_USERNAME=your-username
JFROG_PASSWORD=your-api-key-or-password
JFROG_REPOSITORY=your-repo-name
JFROG_GROUP_ID=com.yourcompany
JFROG_ARTIFACT_SUFFIX=-trivy-report
JFROG_VERSION_PREFIX=1.0.0-
JFROG_ASSET_EXTENSION=json
JFROG_TIMEOUT=30
```

### Flask Configuration (Optional)

```bash
FLASK_ENV=development
FLASK_DEBUG=true
FLASK_HOST=0.0.0.0
FLASK_PORT=5000
SECRET_KEY=your-secret-key

# Dashboard Settings
CACHE_TTL=300
REFRESH_INTERVAL=600
MAX_SCANS_PER_PROJECT=50
LOG_LEVEL=INFO
```

### Environment Variables Reference

| Variable | Description | Required |
|----------|-------------|----------|
| `ARTIFACTORY_TYPE` | Repository type: `nexus` or `jfrog` | ✅ Yes |
| `*_URL` | Repository server URL | ✅ Yes |
| `*_USERNAME` | Authentication username | ✅ Yes |
| `*_PASSWORD` | Authentication password/token | ✅ Yes |
| `*_REPOSITORY` | Repository name | ✅ Yes |
| `*_GROUP_ID` | Maven groupId pattern | ✅ Yes |
| `*_ARTIFACT_SUFFIX` | Artifact suffix (e.g., `-trivy-report`) | ✅ Yes |
| `FLASK_PORT` | Dashboard port (default: 5000) | ❌ No |
| `CACHE_TTL` | Cache time-to-live in seconds | ❌ No |
| `LOG_LEVEL` | Logging level (DEBUG, INFO, etc.) | ❌ No |

---

## 🐳 Docker Deployment

### Docker Run

```bash
docker run -d \
  --name trivy-dashboard \
  -p 5000:5000 \
  -e ARTIFACTORY_TYPE=jfrog \
  -e JFROG_URL=https://your-jfrog.jfrog.io \
  -e JFROG_USERNAME=your-username \
  -e JFROG_PASSWORD=your-password \
  -e JFROG_REPOSITORY=your-repo \
  -e JFROG_GROUP_ID=com.yourcompany \
  -e JFROG_ARTIFACT_SUFFIX=-trivy-report \
  --restart unless-stopped \
  trivy-dashboard:latest
```

### With memory restrictions
```
docker run -d --name trivydashboard -p 5000:5000 --env-file data/.env   --memory=512m --memory-swap=40g localhost/trivydashboard:1.0
```

### Docker Compose

```yaml
version: '3.8'

services:
  trivy-dashboard:
    build: .
    container_name: trivy-dashboard
    ports:
      - "5000:5000"
    env_file:
      - .env
    volumes:
      - ./logs:/app/logs
    restart: unless-stopped
```

```bash
# Run with docker-compose
docker-compose up -d
```

### Build Custom Image

```bash
docker build -t trivy-dashboard:local .
docker run -d --name trivy-dashboard -p 5000:5000 --env-file .env trivy-dashboard:local
```

---

## 🏗️ Architecture

```
trivy-dashboard/
├── app.py                      # Main Flask application
├── config.py                   # Configuration management
├── requirements.txt            # Python dependencies
├── services/
│   ├── nexus_client.py         # Nexus API integration
│   ├── jfrog_client.py         # JFrog API integration
│   ├── trivy_parser.py         # Trivy report parsing
│   ├── cyclonedx_parser.py     # CycloneDX parsing
│   ├── hybrid_sbom_parser.py   # Trivy + CycloneDX merging
│   └── analytics.py            # Security analytics & metrics
├── templates/                  # HTML templates (Jinja2)
├── static/                     # CSS, JS assets
├── utils/                      # Helper functions
├── jenkins/                    # Jenkins pipeline files
└── scripts/                    # Conversion utilities
```

### Data Flow

```
┌─────────────────────────────┐
│  Nexus/JFrog Repository     │ ← Stores Trivy + CycloneDX reports
└────────────┬────────────────┘
             │
    ┌────────▼────────────────────────┐
    │  Repository Client              │
    │  (NexusClient / JFrogClient)    │
    └────────┬────────────────────────┘
             │
    ┌────────▼────────────────────────┐
    │  Hybrid SBOM Parser             │
    │  - Merges Trivy + CycloneDX     │
    │  - Enriches with license data   │
    └────────┬────────────────────────┘
             │
    ┌────────▼────────────────────────┐
    │  Analytics & Risk Scoring       │
    └────────┬────────────────────────┘
             │
    ┌────────▼────────────────────────┐
    │  Flask Dashboard                │
    │  - Web UI / API / Reports       │
    └─────────────────────────────────┘
```

---

## 📊 Risk Assessment & Metrics

### Severity Weights

| Severity | Weight |
|----------|--------|
| Critical | 10 points |
| High | 7 points |
| Medium | 4 points |
| Low | 1 point |

### Risk Score Formula

```
Risk Score % = (Total Weighted Score ÷ Max Possible Score) × 100

Where:
• Total Weighted Score = (Critical × 10) + (High × 7) + (Medium × 4) + (Low × 1)
• Max Possible Score = Total Vulnerabilities × 10
```

### Risk Levels

| Level | Range | Action |
|-------|-------|--------|
| 🔴 CRITICAL | 80-100% | Immediate attention required |
| 🟠 HIGH | 60-79% | Priority remediation needed |
| 🟡 MEDIUM | 40-59% | Moderate security concern |
| 🟢 LOW | 20-39% | Minor security issues |
| 🔵 MINIMAL | 0-19% | Acceptable risk |

---

## 📡 API Endpoints

### Web Pages

| Endpoint | Description |
|----------|-------------|
| `/` | Main dashboard |
| `/projects` | All projects list |
| `/project/<name>` | Project details |
| `/scan/<id>` | Scan details |
| `/component_analysis` | Component search |

### REST API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/projects` | GET | List all projects |
| `/api/project/<name>/scans` | GET | Project scans |
| `/api/scan/<id>/vulnerabilities` | GET | Scan vulnerabilities |
| `/api/dashboard/summary` | GET | Dashboard metrics |
| `/api/health` | GET | Health check |
| `/refresh` | POST | Trigger data refresh |

### Health Check

```bash
curl http://localhost:5000/api/health
```

---

## 📄 Reports & Export

### PDF Report

Generate PDF report of all projects with vulnerability summary:

```bash
# Default timezone (IST)
curl -O http://localhost:5000/api/report/projects/pdf

# With specific timezone
curl -O "http://localhost:5000/api/report/projects/pdf?timezone=America/New_York"
```

### CSV Report

Generate CSV report for spreadsheet analysis:

```bash
# Default timezone (IST)
curl -O http://localhost:5000/api/report/projects/csv

# With specific timezone
curl -O "http://localhost:5000/api/report/projects/csv?timezone=UTC"
```

### Common Timezone Values

| Region | Value |
|--------|-------|
| India (IST) | `Asia/Kolkata` |
| US Eastern | `America/New_York` |
| US Pacific | `America/Los_Angeles` |
| UK | `Europe/London` |
| UTC | `UTC` |

### SBOM Export

Export merged SBOM in SPDX JSON format:

```bash
curl http://localhost:5000/scan/{scan_id}/sbom/export -o sbom.json
```

---

## 🔍 Troubleshooting

### Common Issues

#### Repository Connection Failed
```
Error: Connection refused
```
**Solution:**
- Verify repository URL is accessible
- Check credentials in `.env` file
- Test network connectivity

#### No Data Showing
**Solution:**
- Verify Trivy/CycloneDX files exist in repository
- Check `*_GROUP_ID` matches your artifacts
- Enable debug logging: `LOG_LEVEL=DEBUG`

#### Risk Score Not Updating
**Solution:**
- Click "Refresh Data" in Settings menu
- Verify scan timestamps are recent
- Check background thread in logs

### Debug Mode

```bash
# Enable debug logging
export FLASK_DEBUG=true
export LOG_LEVEL=DEBUG
python app.py
```

### Debug Endpoints

```bash
curl http://localhost:5000/debug/nexus    # Repository connection test
curl http://localhost:5000/api/health     # Health check
```

---

## 📚 Additional Resources

### Jenkins Integration

For automated security report generation via Jenkins pipeline, see:
- [jenkins/README.md](jenkins/README.md) - Jenkins pipeline documentation

### SBOM Conversion Scripts

For converting CycloneDX SBOM files to Trivy report format, see:
- [scripts/README.md](scripts/README.md) - Conversion utilities documentation

---

## 📦 Dependencies

### Core
- Flask 2.3.3 - Web framework
- Requests 2.31.0 - HTTP client
- Pandas 2.0.3 - Data analysis
- pytz - Timezone support
- ReportLab - PDF generation

### Frontend
- Bootstrap 5.3.0 - UI framework
- Chart.js 4.4.0 - Interactive charts
- Font Awesome 6.4.0 - Icons

See `requirements.txt` for complete list.

---

## 📄 License

This project is licensed under MIT License.

---

## 🤝 Support

For issues or questions:
1. Check Troubleshooting section above
2. Enable debug logging
3. Review logs in `logs/` directory
4. Create GitHub issue with debug output

---

**Happy scanning! 🛡️**
