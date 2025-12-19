# Trivy Security Dashboard

A comprehensive Flask-based dashboard for visualizing Trivy security scan results from CycloneDX files stored in Nexus Repository.

**Status**: Production Ready ✅  
**Last Updated**: November 15, 2025

---

## 📋 Table of Contents

1. [Overview](#-overview)
2. [Features](#-features)
3. [Quick Start](#-quick-start)
4. [Setup Guide](#-complete-setup-guide)
5. [Docker Deployment](#-docker-deployment)
6. [Architecture](#-architecture)
7. [Configuration](#-configuration)
8. [Risk Assessment](#-risk-assessment--metrics)
9. [Dashboard Views](#-dashboard-views)
10. [API Endpoints](#-api-endpoints)
11. [Troubleshooting](#-troubleshooting)
12. [Advanced Topics](#-advanced-topics)

---

## 🎯 Overview

This dashboard provides real-time security insights by:
- Fetching CycloneDX SBOM files from Nexus Repository
- Parsing vulnerability data from multiple projects and scans
- Displaying interactive charts and analytics with risk assessment
- Automatic Trivy + CycloneDX merging for comprehensive SBOM coverage
- No separate database required - data is fetched directly from Nexus

### Key Capabilities

✅ **Dual Format Support**: Works with both CycloneDX and Trivy report formats  
✅ **Automatic Merging**: Combines Trivy vulnerabilities with CycloneDX components/licenses  
✅ **Risk Scoring**: Weighted severity-based risk calculation (0-100%)  
✅ **Multi-Project Analytics**: Cross-project vulnerability comparison  
✅ **Real-time Refresh**: Force refresh button with threading-based updates  
✅ **Export Options**: Download scans and merged SBOMs  

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
- **Mixed SBOM Support**: Handles both basic component data and full vulnerability information
- **SPDX Export**: Generate SPDX-compliant SBOM exports

### Dashboard Features
- **Application Level Views**: Project metrics, build history, quality gates
- **Pipeline Level Views**: Build history, scan performance, remediation tracking
- **Multi-Scan Analytics**: Cross-project comparison, dependency analysis, KPIs
- **Real-time Updates**: Force refresh with immediate data fetch from Nexus
- **Responsive Design**: Desktop, tablet, and mobile optimization

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
cd trivy-dashboard
pip install -r requirements.txt
```

### 2. Configure Nexus Connection
```bash
# Copy environment template
cp .env.example .env

# Edit .env with your settings:
# NEXUS_URL=http://your-nexus.company.com:8081
# NEXUS_USERNAME=your-username
# NEXUS_PASSWORD=your-password
# NEXUS_REPOSITORY=your-sbom-repo
```

### 3. Run Dashboard
```bash
python app.py
```

### 4. Access Dashboard
Open browser to `http://localhost:5000`

---

## 🔧 Complete Setup Guide

### Prerequisites

Before starting, ensure you have:

1. **Python 3.8+** installed
   ```powershell
   python --version
   ```
   
2. **Git** (if not already installed)

3. **Network Access** to Nexus Repository

4. **Nexus Credentials** for the repository account

### Step 1: Environment Setup

#### 1.1 Navigate to Dashboard Directory
```powershell
cd "c:\Users\vmadmin\Desktop\trivy-dashboard"
```

#### 1.2 Create Python Virtual Environment
```powershell
# Create virtual environment
python -m venv venv

# Activate (PowerShell)
.\venv\Scripts\Activate.ps1

# Or for Command Prompt
# .\venv\Scripts\activate.bat
```

#### 1.3 Install Dependencies
```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

**Expected packages:**
- Flask==2.3.3
- Flask-CORS==4.0.0
- requests==2.31.0
- pandas==2.0.3
- plotly==5.17.0
- pytz==2024.1 (timezone support)
- cyclonedx-python-lib==4.1.0

### Step 2: Configuration Setup

#### 2.1 Create Environment Configuration
```powershell
copy .env.example .env
```

#### 2.2 Edit Configuration File

```bash
# Nexus Repository Configuration (REQUIRED)
NEXUS_URL=http://your-nexus:8081
NEXUS_USERNAME=your-username
NEXUS_PASSWORD=your-password
NEXUS_REPOSITORY=your-repo-name

# Project Configuration (REQUIRED)
NEXUS_GROUP_ID=com.yourcompany
NEXUS_ARTIFACT_SUFFIX=.sbom
NEXUS_VERSION_PREFIX=1.0.0-
NEXUS_ASSET_EXTENSION=json

# Flask Configuration (optional)
FLASK_ENV=development
FLASK_DEBUG=true
SECRET_KEY=your-secret-key

# Dashboard Configuration (optional)
CACHE_TTL=300                    # Cache for 5 minutes
DATA_REFRESH_INTERVAL=600        # Refresh every 10 minutes
MAX_SCAN_HISTORY=100             # Keep last 100 scans

# Logging Configuration
LOG_LEVEL=INFO
LOG_FILE=logs/dashboard.log
```

### Step 3: Run Dashboard

```powershell
# Activate virtual environment (if not already active)
.\venv\Scripts\Activate.ps1

# Run application
python app.py
```

Expected output:
```
🚀 Starting Trivy Security Dashboard
🔗 Nexus URL: http://your-nexus:8081
📊 Dashboard will be available at http://localhost:5000
Running on http://127.0.0.1:5000
```

### Step 4: Access Dashboard

1. Open browser to `http://localhost:5000`
2. View projects on Projects page
3. Click on project to see scans
4. Click on scan to view vulnerabilities
5. Click ℹ️ icon to understand risk calculations

---

## 🐳 Docker Deployment

### Docker Run (Simple)

```bash
docker run -d \
  --name trivy-dashboard \
  -p 5000:5000 \
  -e NEXUS_URL=http://your-nexus:8081 \
  -e NEXUS_USERNAME=admin \
  -e NEXUS_PASSWORD=password \
  -e NEXUS_REPOSITORY=your-repo \
  -e NEXUS_GROUP_ID=com.yourcompany \
  -e NEXUS_ARTIFACT_SUFFIX=.sbom \
  -e NEXUS_VERSION_PREFIX=1.0.0- \
  -e NEXUS_ASSET_EXTENSION=json \
  --restart unless-stopped \
  yourusername/trivy-security-dashboard:latest
```

### Docker Compose (Recommended)

```bash
git clone https://github.com/yourusername/trivy-security-dashboard
cd trivy-security-dashboard
cp .env.example .env
# Edit .env with your settings
docker-compose up -d
```

### Build Custom Image

```bash
# Build local image
docker build -t trivy-dashboard:local .

# Run locally
docker run -d \
  --name trivy-dashboard \
  -p 5000:5000 \
  --env-file .env \
  --restart unless-stopped \
  trivy-dashboard:local
```

### Docker Hub Setup

1. **Create Docker Hub Account**: [hub.docker.com](https://hub.docker.com)
2. **Create Repository**: `trivy-security-dashboard`
3. **Generate Access Token**:
   - Go to Account Settings → Security
   - Click "New Access Token"
   - Copy token (save securely)
4. **Configure GitHub Secrets**:
   - Add `DOCKERHUB_USERNAME`
   - Add `DOCKERHUB_TOKEN`
5. **Push and Tag**:
   - Push to `main` → creates `latest` tag
   - Push to `develop` → creates `develop` tag
   - Create tag `v1.2.3` → creates semantic version tags

### Image Tags

| Branch/Tag | Docker Tags |
|-----------|-------------|
| Push to `main` | `latest`, `main` |
| Push to `develop` | `develop` |
| Tag `v1.2.3` | `v1.2.3`, `1.2.3`, `1.2`, `1` |
| Pull request | Build only (no push) |

---

## 🏗️ Architecture

```
trivy-dashboard/
├── app.py                      # Main Flask application (1118 lines)
├── config.py                   # Configuration management
├── requirements.txt            # Python dependencies
│
├── services/                   # Backend services
│   ├── nexus_client.py        # Nexus API integration
│   ├── trivy_parser.py        # Trivy report parsing (451 lines)
│   ├── cyclonedx_parser.py    # CycloneDX parsing
│   ├── hybrid_sbom_parser.py  # Trivy + CycloneDX merging (700+ lines)
│   └── analytics.py           # Security analytics & metrics
│
├── templates/                  # HTML templates (Jinja2)
│   ├── base.html              # Base template with Bootstrap 5
│   ├── dashboard.html         # Main dashboard view
│   ├── projects.html          # Projects list view
│   ├── project.html           # Project details with risk modal
│   ├── scan.html              # Scan details with risk modal
│   ├── sbom_details.html      # SBOM analysis
│   └── error.html             # Error pages
│
├── static/                     # Static assets
│   ├── css/
│   │   └── dashboard.css      # Custom styling
│   └── js/
│       ├── charts.js          # Chart.js configurations
│       └── analytics.js       # Dashboard analytics
│
└── utils/                      # Utility functions
    ├── cache.py               # Caching mechanism
    └── helpers.py             # Helper functions & risk scoring
```

### Data Flow

```
┌─────────────────┐
│  Nexus Repo     │ ← Stores CycloneDX + Trivy reports
└────────┬────────┘
         │
    ┌────▼──────────────────────┐
    │  NexusClient              │
    │  - Lists artifacts        │
    │  - Downloads SBOMs        │
    └────┬──────────────────────┘
         │
    ┌────▼──────────────────────────────────┐
    │  Hybrid SBOM Parser                   │
    │  - Merges Trivy + CycloneDX          │
    │  - Enriches with license data         │
    │  - Generates SPDX structure           │
    └────┬─────────────────────────────────┘
         │
    ┌────▼──────────────┐
    │  Analytics       │
    │  - Risk scoring  │
    │  - Metrics       │
    │  - Trends        │
    └────┬──────────────┘
         │
    ┌────▼────────────────────────┐
    │  Flask Routing              │
    │  - Renders templates        │
    │  - Caches results           │
    │  - Exposes APIs             │
    └────┬─────────────────────────┘
         │
    ┌────▼──────────┐
    │  Dashboard    │
    │  - Charts     │
    │  - Tables     │
    │  - Modals     │
    └───────────────┘
```

---

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Example | Required |
|----------|-------------|---------|----------|
| `NEXUS_URL` | Nexus server URL | `http://nexus:8081` | ✅ Yes |
| `NEXUS_USERNAME` | Nexus username | `admin` | ✅ Yes |
| `NEXUS_PASSWORD` | Nexus password | `password123` | ✅ Yes |
| `NEXUS_REPOSITORY` | Repository name | `sbom-repo` | ✅ Yes |
| `NEXUS_GROUP_ID` | Maven groupId | `com.company` | ✅ Yes |
| `NEXUS_ARTIFACT_SUFFIX` | Artifact suffix | `.sbom` | ✅ Yes |
| `NEXUS_VERSION_PREFIX` | Version prefix | `1.0.0-` | ✅ Yes |
| `NEXUS_ASSET_EXTENSION` | File extension | `json` | ✅ Yes |
| `FLASK_ENV` | Flask environment | `development` | ❌ No |
| `FLASK_DEBUG` | Enable debug mode | `true` | ❌ No |
| `CACHE_TTL` | Cache time-to-live (sec) | `300` | ❌ No |
| `DATA_REFRESH_INTERVAL` | Refresh interval (sec) | `600` | ❌ No |
| `LOG_LEVEL` | Logging level | `INFO` | ❌ No |

### Automatic Discovery

The dashboard automatically discovers and processes:

- **CycloneDX Files**: Pattern `{groupId}/{artifactId}/{version}/`
- **Trivy Reports**: Named `{filename}-trivy-report.json`
- **Project Metadata**: Extracted from SBOM and Nexus properties
- **Scan History**: Based on build numbers and timestamps
- **Vulnerability Data**: Parsed from both Trivy and CycloneDX sources

---

## 📊 Risk Assessment & Metrics

### Risk Calculation Methodology

The dashboard uses **weighted severity scoring** for risk assessment:

#### Severity Weights
```
Critical (C) = 10 points
High (H)     = 7 points  
Medium (M)   = 4 points
Low (L)      = 1 point
```

#### Formula
```
Risk Score % = (Total Weighted Score ÷ Max Possible Score) × 100

Where:
• Total Weighted Score = (C × 10) + (H × 7) + (M × 4) + (L × 1)
• Max Possible Score = Total Vulnerabilities × 10
```

#### Example
```
Latest Scan: 1 Critical, 49 High, 73 Medium, 15 Low

Total Weighted = (1 × 10) + (49 × 7) + (73 × 4) + (15 × 1) = 660
Total Vulnerabilities = 138
Max Possible Score = 138 × 10 = 1380
Risk Score = (660 / 1380) × 100 = 47.83%
```

### Risk Levels

| Level | Range | Color | Action |
|-------|-------|-------|--------|
| 🔴 **CRITICAL** | 80-100% | Red | Immediate attention required |
| 🟠 **HIGH** | 60-79% | Orange | Priority remediation needed |
| 🟡 **MEDIUM** | 40-59% | Yellow | Moderate security concern |
| 🟢 **LOW** | 20-39% | Green | Minor security issues |
| 🔵 **MINIMAL** | 0-19% | Blue | Acceptable risk |

### Interactive Risk Modal

**New Feature**: Click the ℹ️ icon next to "Risk Assessment" or risk score to see:
- Complete risk calculation formula
- Severity weight breakdown
- Risk level classifications
- Detailed methodology explanation

Available on:
- Project details page (Risk Assessment card)
- Scan details page (Risk Score field)

### Data Points Tracked

- **Vulnerability Density**: Vulnerabilities per component
- **Mean Time to Remediation (MTTR)**: Average fix time
- **Security Debt**: Total vulnerability exposure
- **Risk Velocity**: Rate of risk change
- **Remediation Progress**: Closed vs open vulnerabilities
- **Component Age**: Last update timestamp tracking

---

## 📈 Dashboard Views

### Main Dashboard (`/`)
- Security overview across all projects
- Trending vulnerability counts by severity
- Critical alerts and notifications
- Risk score distribution
- Quick access to problem areas

### Projects List (`/projects`)
- All projects with risk indicators
- Project risk scores with visual progress bars
- Latest scan timestamps
- Scan count per project
- Click to view project details

### Project Details (`/project/<name>`)
- **Security Trends**: Vulnerability trends over time
- **Risk Assessment**: 
  - Current risk score with ℹ️ info modal
  - Risk level badge (Critical/High/Medium/Low)
  - Vulnerability breakdown by severity
- **Scan History**: Recent scans with timestamps and build numbers
- **Component Analysis**: Inventory and dependencies

### Scan Details (`/scan/<id>`)
- **Scan Information**:
  - Project name and build number
  - Scan timestamp (from Trivy CreatedAt)
  - Component count
  - Risk Score with ℹ️ info modal
- **Vulnerability Details**: CVE list with severity, CVSS, fix info
- **Component Details**: Component metadata and licensing
- **SBOM Information**: Source file and metadata

### Component Analysis (`/component_analysis`)
- Cross-project component search
- License inventory
- Version tracking
- Vulnerability correlation

---

## 📡 API Endpoints

### Dashboard Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main dashboard |
| `/projects` | GET | All projects list |
| `/project/<name>` | GET | Project details |
| `/scan/<id>` | GET | Scan details |
| `/component_analysis` | GET | Component search |

### API Endpoints

| Endpoint | Method | Returns | Description |
|----------|--------|---------|-------------|
| `/api/projects` | GET | JSON | List all projects |
| `/api/project/<name>/scans` | GET | JSON | Project scans |
| `/api/scan/<id>/vulnerabilities` | GET | JSON | Scan vulnerabilities |
| `/api/dashboard/summary` | GET | JSON | Dashboard metrics |
| `/api/health` | GET | JSON | Health check |
| `/refresh` | POST | JSON | Trigger data refresh |

### Health Check

```bash
curl http://localhost:5000/api/health
```

Response:
```json
{
  "status": "healthy",
  "timestamp": "2025-11-15T22:20:52",
  "projects": 1,
  "scans": 5
}
```

### PDF Report Export

Generate a PDF report of all projects with vulnerability summary, branch/environment counts, and risk scores. Perfect for sharing with stakeholders who don't have dashboard access.

**Endpoint:** `GET /api/report/projects/pdf`

**Query Parameters:**
| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `timezone` | No | `Asia/Kolkata` | Timezone for date display (IANA timezone format) |

**Usage Examples:**

```bash
# Default timezone (IST - Asia/Kolkata)
curl -O http://localhost:5000/api/report/projects/pdf

# Specific timezone examples
curl -O "http://localhost:5000/api/report/projects/pdf?timezone=Asia/Kolkata"
curl -O "http://localhost:5000/api/report/projects/pdf?timezone=America/New_York"
curl -O "http://localhost:5000/api/report/projects/pdf?timezone=Europe/London"
curl -O "http://localhost:5000/api/report/projects/pdf?timezone=UTC"
```

**Browser Access:**
Simply open any of these URLs in your browser to download the PDF:
- `http://localhost:5000/api/report/projects/pdf`
- `http://localhost:5000/api/report/projects/pdf?timezone=Asia/Kolkata`
- `http://localhost:5000/api/report/projects/pdf?timezone=America/New_York`
- `http://localhost:5000/api/report/projects/pdf?timezone=UTC`

**PDF Report Contents:**
- **Header**: Report title with generation timestamp in specified timezone
- **Summary Box**: Total projects, Critical, High, Medium, Low vulnerability counts
- **Projects Table** (with sub-rows for each branch/environment):
  - **Project Main Row** (bold, highlighted background):
    - Project Name with branch count in parentheses e.g., `ProjectA (2)`
    - Aggregated Risk Score (color-coded: red ≥80%, orange ≥40%, green <40%)
    - Total Critical, High, Medium, Low vulnerability counts
    - Latest Scan Date across all branches
  - **Branch/Environment Sub-rows** (indented with ↳):
    - Branch/Environment name
    - Per-branch Risk Score
    - Per-branch Critical, High, Medium, Low counts
    - Latest scan date for that specific branch
- **Footer**: Data timestamp

**Common Timezone Values:**
| Region | Timezone Value |
|--------|----------------|
| India (IST) | `Asia/Kolkata` |
| US Eastern | `America/New_York` |
| US Pacific | `America/Los_Angeles` |
| UK | `Europe/London` |
| Central Europe | `Europe/Berlin` |
| Japan | `Asia/Tokyo` |
| Australia | `Australia/Sydney` |
| UTC | `UTC` |

---

## 🔄 Background Refresh

### Force Refresh Feature

The dashboard includes a **Force Refresh** button that immediately fetches new data from Nexus:

- **Location**: Settings menu (top right)
- **Behavior**: Wakes background thread instantly
- **Normal Refresh**: Continues on scheduled interval (default: 10 minutes)
- **Implementation**: Threading.Event-based signaling

### Timestamp Handling

- **CreatedAt Field**: Used for scan date (from Trivy report)
- **Timezone Support**: Automatically converts UTC to local timezone
- **Nanosecond Precision**: Handles high-precision timestamps
- **Fallback**: Uses current time if CreatedAt unavailable

---

## 🔍 Troubleshooting

### Common Issues

#### 1. Nexus Connection Failed
```
Error: Connection refused to http://nexus:8081
```

**Solution:**
- Verify Nexus URL is accessible: `curl http://nexus:8081`
- Check firewall rules
- Verify credentials in .env file
- Test network connectivity to Nexus server

#### 2. No Data Showing
```
Dashboard displays but no projects visible
```

**Solution:**
- Verify CycloneDX files exist in Nexus repository
- Check `NEXUS_GROUP_ID` matches your artifacts
- Verify `NEXUS_REPOSITORY` name is correct
- Enable debug logging: `export LOG_LEVEL=DEBUG`

#### 3. Risk Score Not Updating
```
Risk scores appear outdated
```

**Solution:**
- Click "Refresh Data" button in Settings
- Verify scan timestamps are recent
- Check background thread is running (see logs)
- Ensure vulnerability counts are being parsed

#### 4. Templates Not Loading
```
CSS/JS not loading - page looks broken
```

**Solution:**
- Verify static files are in `/static` folder
- Check file permissions
- Disable browser cache (Ctrl+Shift+Delete)
- Check browser console for 404 errors

### Debug Mode

Enable comprehensive logging:

```bash
# PowerShell
$env:FLASK_DEBUG = "true"
$env:LOG_LEVEL = "DEBUG"
python app.py

# Linux/Mac
export FLASK_DEBUG=true
export LOG_LEVEL=DEBUG
python app.py
```

### Debug Endpoints

```bash
# Nexus connection test
curl http://localhost:5000/debug/nexus

# View configuration
curl http://localhost:5000/debug/config

# Check data refresh status
curl http://localhost:5000/debug/status
```

---

## 📚 Advanced Topics

### Hybrid SBOM Merging

The dashboard automatically merges Trivy and CycloneDX data:

**How it works:**
1. Finds `{filename}-trivy-report.json` in Nexus
2. Automatically fetches `{filename}.json` (CycloneDX)
3. Merges vulnerability + component + license data
4. Generates unified SBOM with ~70% SPDX coverage

**Result:**
- CVE details from Trivy
- License information from CycloneDX
- Supplier and copyright metadata
- Complete vulnerability tracking

### SBOM Export

Export merged SBOM in SPDX JSON format:

```bash
curl http://localhost:5000/scan/{scan_id}/sbom/export -o sbom.json
```

### Custom Metrics

Extend risk calculation in `services/analytics.py`:

```python
def calculate_custom_metric(sbom_data):
    # Your custom calculation
    return metric_value
```

### Theme Customization

Modify `static/css/dashboard.css`:

```css
:root {
    --primary-color: #007bff;
    --danger-color: #dc3545;
    /* ... other variables */
}
```

### Adding New Charts

Add configurations to `static/js/charts.js`:

```javascript
const customChart = {
    type: 'bar',
    data: processedData,
    options: chartOptions
};
```

---

## 🚀 Production Deployment

### High Availability Setup

```
Load Balancer (Nginx/HAProxy)
    ↓
[Dashboard 1] [Dashboard 2] [Dashboard 3]
    ↓
Nexus Repository (Shared)
```

### SSL/TLS Configuration

Use reverse proxy (Nginx):

```nginx
server {
    listen 443 ssl http2;
    server_name dashboard.company.com;
    
    ssl_certificate /etc/ssl/certs/cert.pem;
    ssl_certificate_key /etc/ssl/private/key.pem;
    
    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Monitoring

Enable health checks:

```bash
# Kubernetes liveness probe
http://dashboard:5000/api/health

# Expected response time: <100ms
# Expected status: 200 OK
```

### Performance Tuning

- **Cache TTL**: Increase for stable data (default: 300s)
- **Refresh Interval**: Increase to reduce Nexus load (default: 600s)
- **Max Scan History**: Reduce for better performance (default: 100)

---

## 📝 Recent Updates

### November 15, 2025

✅ **Risk Calculation Modal**: Interactive info icon explaining risk calculations  
✅ **Bootstrap 5 Compatibility**: Fixed modal syntax for Bootstrap 5.3  
✅ **Scan Date Fix**: Now uses CreatedAt from Trivy reports exclusively  
✅ **Timezone Support**: Automatic UTC-to-local conversion with pytz  
✅ **Force Refresh Feature**: Threading-based immediate data fetch  
✅ **Latest Scan Determination**: Uses Trivy CreatedAt instead of upload date  

### Key Commits

```
d165a54 - Add Risk Calculation Info Modal documentation
4677dac - Fix: Update modal syntax for Bootstrap 5 compatibility
2611abb - Fix: Use CreatedAt timestamp from Trivy report
```

---

## 📦 Dependencies

### Core
- **Flask** 2.3.3 - Web framework
- **Requests** 2.31.0 - HTTP client
- **Pandas** 2.0.3 - Data analysis

### Frontend
- **Bootstrap** 5.3.0 - UI framework
- **Chart.js** 4.4.0 - Interactive charts
- **Font Awesome** 6.4.0 - Icons

### SBOM & Security
- **CycloneDX** 4.1.0 - SBOM parsing
- **pytz** 2024.1 - Timezone support

See `requirements.txt` for complete list.

---

## 📄 License

This project is licensed under MIT License. See LICENSE file for details.

---

## 🤝 Support

For issues or questions:
1. Check [Troubleshooting](#-troubleshooting) section
2. Enable debug logging
3. Review logs in `logs/` directory
4. Create GitHub issue with debug output

---

## 🎯 Next Steps

1. **Install**: Follow [Quick Start](#-quick-start) or [Setup Guide](#-complete-setup-guide)
2. **Configure**: Update `.env` with your Nexus details
3. **Deploy**: Run locally or use Docker
4. **Access**: Open dashboard at `http://localhost:5000`
5. **Explore**: Click projects and scans to view details
6. **Learn**: Use ℹ️ modals to understand calculations

---

**Happy scanning! 🛡️**
