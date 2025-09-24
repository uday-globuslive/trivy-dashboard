# Debug Scripts Documentation

This folder contains various debug and test scripts for the Trivy Security Dashboard. These scripts help with troubleshooting, testing, and understanding the dashboard's functionality.

## Prerequisites

Before running any debug scripts:

1. **Activate the virtual environment:**
   ```powershell
   .\venv\Scripts\Activate.ps1
   ```

2. **Ensure the Flask server is running:**
   ```powershell
   python app.py
   ```
   Dashboard should be accessible at: http://localhost:5000

3. **Install required dependencies (if not already installed):**
   ```powershell
   pip install requests python-dotenv flask flask-cors
   ```

## Scripts Overview

### 📊 **debug_nexus.py**
**Purpose:** Debugs Nexus Repository connection and SBOM file discovery

**What it does:**
- Tests connection to Nexus Repository
- Lists all discovered SBOM files
- Shows file metadata (project names, versions, timestamps)
- Validates Nexus API endpoints

**How to run:**
```powershell
cd debug_scripts
python debug_nexus.py
```

**Use when:**
- Nexus connection issues
- SBOM files not appearing in dashboard
- Verifying Nexus repository configuration

---

### 🔍 **debug_sbom_content.py**
**Purpose:** Analyzes SBOM file content and structure

**What it does:**
- Downloads and parses SBOM files from Nexus
- Shows vulnerability counts per file
- Displays component information
- Validates CycloneDX format compliance

**How to run:**
```powershell
cd debug_scripts
python debug_sbom_content.py
```

**Use when:**
- SBOM parsing errors
- Incorrect vulnerability counts
- Understanding SBOM file structure

---

### 🎯 **debug_mart_vulnerabilities.py**
**Purpose:** Specifically analyzes Mart project vulnerability calculations

**What it does:**
- Compares Trivy scan results with dashboard data
- Shows detailed vulnerability breakdown
- Identifies discrepancies in counting logic
- Traces vulnerability aggregation process

**How to run:**
```powershell
cd debug_scripts
python debug_mart_vulnerabilities.py
```

**Use when:**
- Dashboard shows incorrect vulnerability counts
- Trivy results don't match dashboard
- Debugging aggregation logic

---

### 📈 **debug_scan_count.py**
**Purpose:** Investigates scan counting and project aggregation

**What it does:**
- Checks Nexus files vs dashboard project data
- Compares expected vs actual scan counts
- Shows individual scan IDs and metadata
- Validates project-to-scan relationships

**How to run:**
```powershell
cd debug_scripts
python debug_scan_count.py
```

**Use when:**
- Projects showing wrong number of scans
- Scans not appearing in project view
- Data aggregation issues

---

### ✅ **test_dashboard_fix.py**
**Purpose:** Tests dashboard functionality after fixes

**What it does:**
- Verifies all dashboard endpoints
- Tests vulnerability counting logic
- Validates project and scan pages
- Confirms data refresh functionality

**How to run:**
```powershell
cd debug_scripts
python test_dashboard_fix.py
```

**Use when:**
- After implementing fixes
- Regression testing
- Verifying dashboard health

---

### 🔧 **test_config.py**
**Purpose:** Tests configuration loading and environment variables

**What it does:**
- Validates .env file configuration
- Tests Nexus URL and repository settings
- Verifies authentication parameters
- Checks configuration consistency

**How to run:**
```powershell
cd debug_scripts
python test_config.py
```

**Use when:**
- Configuration issues
- Environment setup problems
- Verifying settings after changes

---

### 📋 **test_config_values.py**
**Purpose:** Displays current configuration values and validates setup

**What it does:**
- Shows all loaded environment variables
- Tests configuration parameter validity
- Checks for missing required settings
- Validates configuration format

**How to run:**
```powershell
cd debug_scripts
python test_config_values.py
```

**Use when:**
- Debugging configuration problems
- Verifying environment variable loading
- Checking parameter values

---

### 🖥️ **test_mccamish_config.ps1 / test_mccamish_config.sh**
**Purpose:** Cross-platform configuration testing scripts

**What it does:**
- Tests configuration on Windows (PowerShell) and Linux/Mac (Bash)
- Validates environment variable loading
- Checks Nexus connectivity from different platforms
- Verifies cross-platform compatibility

**How to run:**
```powershell
# Windows PowerShell
cd debug_scripts
.\test_mccamish_config.ps1

# Linux/Mac Bash
cd debug_scripts
./test_mccamish_config.sh
```

**Use when:**
- Multi-platform deployment testing
- Environment-specific issues
- Cross-platform configuration validation

## Common Debug Scenarios

### 🚨 **Scenario 1: No projects showing**
1. Run `debug_nexus.py` to check Nexus connection
2. Run `debug_sbom_content.py` to verify SBOM files exist
3. Check Flask logs for errors

### 🚨 **Scenario 2: Wrong vulnerability counts**
1. Run `debug_mart_vulnerabilities.py` for specific analysis
2. Check if latest scan logic is working correctly
3. Compare with actual Trivy output

### 🚨 **Scenario 3: Missing scans**
1. Run `debug_scan_count.py` to investigate
2. Check SBOM file naming conventions
3. Verify timestamp parsing

### 🚨 **Scenario 4: After making changes**
1. Run `test_dashboard_fix.py` for comprehensive testing
2. Check all endpoints are responding
3. Verify data consistency

## Output Interpretation

### ✅ **Success Indicators:**
- HTTP 200 status codes
- Matching vulnerability counts
- All projects and scans visible
- No error messages in logs

### ❌ **Error Indicators:**
- HTTP 404/500 status codes
- Mismatched counts between Trivy and dashboard
- Empty project lists
- Connection timeout errors

## Troubleshooting Tips

1. **Nexus Connection Issues:**
   - Check network connectivity to `http://10.11.53.12:8081`
   - Verify repository name: `mccamish_sbom`
   - Ensure SBOM files exist in Nexus

2. **SBOM Parsing Errors:**
   - Validate CycloneDX JSON format
   - Check for malformed timestamps
   - Verify required fields exist

3. **Dashboard Not Updating:**
   - Refresh data: `http://localhost:5000/refresh`
   - Check background thread status
   - Restart Flask application

## Environment Variables

The scripts use these environment variables (loaded from `.env` file):

```env
NEXUS_URL=http://10.11.53.12:8081
NEXUS_REPOSITORY=mccamish_sbom
NEXUS_GROUP_ID=com.mccamish
SBOM_SUFFIX=.sbom
```

## Security Note

These debug scripts are for development and troubleshooting only. Do not run in production environments as they may expose sensitive information in logs.

## Getting Help

If debug scripts reveal issues:

1. **Check Flask application logs** for detailed error messages
2. **Verify Nexus Repository** contains the expected SBOM files
3. **Test Nexus API** manually using browser or curl
4. **Restart services** if needed (Flask app, Nexus Repository)

## Script Maintenance

When modifying the main dashboard application:

1. **Update debug scripts** if API endpoints change
2. **Add new debug scripts** for new features
3. **Update this README** with new troubleshooting scenarios
4. **Test all scripts** after major changes

---

*Last updated: September 24, 2025*
*Dashboard Version: 1.0.0*