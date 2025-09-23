# 🚀 Complete Setup Guide for Trivy Security Dashboard

This guide provides step-by-step instructions to run the Trivy Security Dashboard Flask website directly on your Windows machine.

## 📋 Prerequisites

Before starting, ensure you have:

1. **Python 3.8+** installed
   ```powershell
   python --version
   ```
   
2. **Git** (if not already installed)

3. **Network Access** to Nexus Repository (`swdlvapp682:8081`)

4. **Nexus Credentials** for the `sv-sbom` user account

## 🔧 Step 1: Environment Setup

### 1.1 Navigate to Dashboard Directory
```powershell
cd "c:\Users\vmadmin\Desktop\trivy\modular_code\dashboard"
```

### 1.2 Create Python Virtual Environment
```powershell
# Create virtual environment
python -m venv venv

# Activate virtual environment (Windows PowerShell)
.\venv\Scripts\Activate.ps1

# Alternative for Command Prompt
# .\venv\Scripts\activate.bat
```

### 1.3 Install Dependencies
```powershell
# Upgrade pip first
python -m pip install --upgrade pip

# Install required packages
pip install -r requirements.txt
```

**Expected packages installed:**
- Flask==2.3.3
- Flask-CORS==4.0.0
- requests==2.31.0
- pandas==2.0.3
- plotly==5.17.0
- cyclonedx-python-lib==4.1.0
- And other dependencies...

## ⚙️ Step 2: Configuration Setup

### 2.1 Create Environment Configuration
```powershell
# Copy the example environment file
copy .env.example .env
```

### 2.2 Edit Configuration File

Open the `.env` file in your preferred text editor:
```powershell
notepad .env
```

Update the following **REQUIRED** settings:

```bash
# Nexus Repository Configuration (REQUIRED)
NEXUS_URL=http://swdlvapp682:8081
NEXUS_USERNAME=sv-sbom
NEXUS_PASSWORD=your-actual-password-here    # ⚠️ GET THIS FROM YOUR ADMIN
NEXUS_REPOSITORY=mccamish_sbom

# McCamish-specific configuration (already configured correctly)
NEXUS_GROUP_ID=com.mccamish
NEXUS_ARTIFACT_SUFFIX=.sbom
NEXUS_VERSION_PREFIX=1.0.0-
NEXUS_ASSET_EXTENSION=json

# Flask Configuration (optional - defaults work for development)
FLASK_ENV=development
FLASK_DEBUG=true
SECRET_KEY=your-secret-key-for-development

# Dashboard Configuration (optional)
CACHE_TTL=300                             # Cache for 5 minutes
DATA_REFRESH_INTERVAL=600                 # Refresh data every 10 minutes
MAX_SCAN_HISTORY=100                      # Keep last 100 scans per project

# Logging Configuration
LOG_LEVEL=INFO
LOG_FILE=logs/dashboard.log
```

### 2.3 Required Credentials

You **MUST** obtain these credentials:

| Setting | Value | How to Get |
|---------|-------|------------|
| `NEXUS_USERNAME` | `sv-sbom` | Already configured |
| `NEXUS_PASSWORD` | `???` | **Contact your system administrator** |
| `NEXUS_URL` | `http://swdlvapp682:8081` | Already configured |
| `NEXUS_REPOSITORY` | `mccamish_sbom` | Already configured |

## 🔍 Step 3: Verify Network Connectivity

### 3.1 Test Nexus Server Accessibility
```powershell
# Test network connection
Test-NetConnection -ComputerName swdlvapp682 -Port 8081

# Test HTTP endpoint (if curl is available)
curl http://swdlvapp682:8081/service/rest/v1/status
```

### 3.2 Test Authentication (once you have password)
```powershell
# Test with credentials (replace YOUR_PASSWORD)
curl -u sv-sbom:YOUR_PASSWORD http://swdlvapp682:8081/service/rest/v1/status
```

**Expected Response:** JSON with Nexus status information

## 🚀 Step 4: Run the Dashboard

### 4.1 Quick Setup (Automated)
Try the automated setup script first:
```powershell
# Make sure virtual environment is activated
.\venv\Scripts\Activate.ps1

# Run setup script
python setup.py
```

### 4.2 Manual Setup
If automated setup doesn't work:
```powershell
# Ensure virtual environment is activated
.\venv\Scripts\Activate.ps1

# Create logs directory
mkdir logs -ErrorAction SilentlyContinue

# Run the Flask application
python app.py
```

### 4.3 Expected Startup Output
```
🚀 Starting Trivy Security Dashboard
🔗 Nexus URL: http://swdlvapp682:8081
📊 Repository: mccamish_sbom
🏷️ Group ID: com.mccamish
📄 Artifact Suffix: .sbom
📊 Dashboard will be available at http://localhost:5000
🔧 Debug endpoint: http://localhost:5000/debug/nexus
🔗 Testing Nexus connection...
✅ Nexus connection successful
📥 Background data refresh started...
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:5000
 * Running on http://localhost:5000
```

## 🌐 Step 5: Access the Dashboard

Once the application starts successfully, access these URLs in your browser:

| URL | Purpose |
|-----|---------|
| http://localhost:5000 | **Main Dashboard** - Security overview |
| http://localhost:5000/projects | **Projects View** - List all projects |
| http://localhost:5000/components | **Component Analysis** - SBOM analysis |
| http://localhost:5000/api/health | **Health Check** - System status |
| http://localhost:5000/debug/nexus | **Debug Information** - Connection details |

### 5.1 First Time Access
1. **Main Dashboard**: Should show project counts and security metrics
2. **Debug Page**: Visit this first to verify Nexus connection and SBOM discovery
3. **Projects Page**: Lists all discovered projects with risk scores

## 🔍 Step 6: Troubleshooting

### 6.1 Debug Nexus Connection
**Always start here:** http://localhost:5000/debug/nexus

This page shows:
- ✅ Nexus connection status
- 📦 Number of SBOM files found
- 🔧 Configuration verification
- 📊 SBOM type analysis (component-only vs vulnerability-enhanced)
- 💡 Enhancement suggestions

### 6.2 Common Issues & Solutions

#### ❌ "Missing required configuration"
```powershell
# Check your .env file exists and has all required values
type .env | findstr NEXUS
```

**Solution**: Ensure all NEXUS_* variables are set in `.env`

#### ❌ "Nexus connection test failed"
```powershell
# Test network connectivity
Test-NetConnection -ComputerName swdlvapp682 -Port 8081

# Test with credentials
curl -u sv-sbom:your-password http://swdlvapp682:8081/service/rest/v1/status
```

**Solutions**:
- Verify password is correct
- Check VPN connection if required
- Confirm Nexus server is running
- Check firewall/proxy settings

#### ❌ "No SBOM files found"
Visit debug page to see search results. Common causes:
- Jenkins pipelines haven't uploaded SBOM files yet
- Wrong repository name (`mccamish_sbom`)
- Files don't match expected pattern: `com/mccamish/{project}.sbom/1.0.0-{timestamp}/`

#### ❌ Python/Pip Installation Errors
```powershell
# Deactivate and recreate virtual environment
deactivate
Remove-Item -Recurse -Force venv
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

#### ❌ "Permission denied" or Authentication Errors
- Double-check the `sv-sbom` password
- Verify user has read access to `mccamish_sbom` repository
- Contact Nexus administrator

### 6.3 Viewing Logs
```powershell
# View application logs
type logs\dashboard.log

# View real-time logs (if running)
Get-Content logs\dashboard.log -Wait
```

## 📊 Step 7: Verify Data Loading

### 7.1 Check SBOM Discovery
1. **Visit Debug Page**: http://localhost:5000/debug/nexus
2. **Look for**: `"files_found"` count > 0
3. **Check**: `"sbom_analysis"` section shows SBOM types

### 7.2 Monitor Background Loading
The dashboard loads data in background threads:

**Console Logs to Watch For:**
```
🔄 Starting background data refresh...
📦 Found X SBOM files in Nexus
✅ Data refresh complete. Projects: X, Scans: Y
```

**Dashboard Indicators:**
- Main dashboard shows project counts > 0
- Projects page lists your applications
- Loading indicators disappear

### 7.3 SBOM Types and Recommendations
The dashboard supports two types of SBOM files:

| Type | Description | Dashboard Capability |
|------|-------------|----------------------|
| **Component-only** | Basic dependency list | Component inventory, license analysis |
| **Vulnerability-enhanced** | Includes security data | Full security analytics, risk scoring |

**If you see "component-only" SBOMs:**
- Dashboard will show components but limited security data
- Consider generating vulnerability-enhanced SBOMs with Trivy
- Check debug page for Trivy command suggestions

## 🔐 Step 8: Production Configuration

For production deployment, update `.env` with:

```bash
# Production Settings
FLASK_ENV=production
FLASK_DEBUG=false
SECRET_KEY=a-very-secure-random-secret-key-minimum-32-characters
LOG_LEVEL=WARNING
SECURE_HEADERS=true
CSRF_ENABLED=true

# Performance Settings
CACHE_TTL=1800                    # 30 minutes for production
DATA_REFRESH_INTERVAL=3600        # 1 hour refresh interval
NEXUS_TIMEOUT=60                  # Longer timeout for production
```

## 📝 Quick Start Command Summary

```powershell
# Complete setup from scratch
cd "c:\Users\vmadmin\Desktop\trivy\modular_code\dashboard"
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env

# Edit .env with your Nexus password
notepad .env

# Run the dashboard
python app.py

# Access dashboard
# Open browser to: http://localhost:5000
```

## 🎯 Expected Results

Once properly configured, your dashboard will:

✅ **Connect** to McCamish Nexus Repository (`swdlvapp682:8081`)  
✅ **Discover** SBOM files in the `mccamish_sbom` repository  
✅ **Parse** CycloneDX files and extract vulnerability data  
✅ **Display** interactive charts and security metrics  
✅ **Provide** project-level and scan-level security views  
✅ **Auto-refresh** data every 10 minutes in the background  
✅ **Show** risk scores, trends, and compliance metrics  

## 🆘 Getting Help

### Debug Checklist
- [ ] Python 3.8+ installed and virtual environment activated
- [ ] All dependencies installed (`pip install -r requirements.txt`)
- [ ] `.env` file created with correct Nexus credentials
- [ ] Network connectivity to `swdlvapp682:8081` confirmed
- [ ] Nexus authentication working (test with curl)
- [ ] Debug page shows SBOM files discovered
- [ ] Application logs show successful data refresh

### Contact Information
- **System Administrator**: For Nexus credentials and access
- **Jenkins Team**: For SBOM upload pipeline issues
- **DevOps Team**: For network/firewall access

### Useful Commands for Support
```powershell
# System information
python --version
pip list | findstr -i "flask requests pandas"

# Network test
Test-NetConnection -ComputerName swdlvapp682 -Port 8081

# Configuration check
type .env | findstr NEXUS

# Application logs
type logs\dashboard.log | Select-Object -Last 50
```

## 🎉 Success Indicators

Your setup is successful when you see:

1. **Console Output**: `✅ Nexus connection successful`
2. **Debug Page**: Shows discovered SBOM files
3. **Main Dashboard**: Displays project counts and metrics
4. **Projects Page**: Lists your applications with risk scores
5. **Background Logs**: Regular data refresh messages

---

**🎯 Main Requirement**: The critical requirement is obtaining the correct password for the `sv-sbom` Nexus user account and ensuring network access to the Nexus server at `swdlvapp682:8081`.

Once these prerequisites are met, the dashboard should run smoothly and provide comprehensive security insights from your CycloneDX SBOM files!