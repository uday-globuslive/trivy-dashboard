# Getting License Information with Trivy JSON Reports

## Problem
- You have Trivy JSON reports in Nexus (vulnerability-focused)
- Trivy doesn't include license information
- You need license details for compliance

## Solution Options

### Option 1: Generate CycloneDX SBOM Alongside Trivy Scans ⭐ **RECOMMENDED**

**What:** Generate both formats from the same scan
**Tool:** CycloneDX (supports license detection)
**Where to store:** Same Nexus repository

#### Setup Steps:

1. **For Maven Projects:**
   ```bash
   # Add to pom.xml
   <plugin>
     <groupId>org.cyclonedx</groupId>
     <artifactId>cyclonedx-maven-plugin</artifactId>
     <version>2.7.10</version>
   </plugin>
   
   # Run in CI/CD
   mvn cyclonedx:makeBom
   
   # Output: target/bom.xml (CycloneDX format with licenses)
   ```

2. **For Container Images:**
   ```bash
   # Use Syft for SBOM generation
   syft packages <image> -o spdx-json > sbom.spdx.json
   syft packages <image> -o cyclonedx-json > sbom.cyclonedx.json
   
   # OR use trivy with SBOM output
   trivy image --format cyclonedx --output sbom.json <image>
   ```

3. **Upload to Nexus:**
   ```bash
   # Store both in same directory:
   /repo/project/version/
      ├── app-1.0.0-trivy-report.json     (vulnerabilities)
      ├── app-1.0.0-sbom.cyclonedx.json   (licenses + components)
      └── app-1.0.0-sbom.spdx.json        (full SPDX format)
   ```

#### Dashboard Enhancement:
```python
# Update nexus_client.py to fetch both files
def fetch_sbom_files(self):
    trivy_files = self.search_trivy_reports()      # Current
    cyclonedx_files = self.search_cyclonedx_sboms() # NEW
    spdx_files = self.search_spdx_sboms()          # NEW
    
    return {
        'trivy': trivy_files,
        'cyclonedx': cyclonedx_files,
        'spdx': spdx_files
    }
```

---

### Option 2: Use Trivy with License Detection Plugin

**What:** Trivy can detect licenses if properly configured
**Limitation:** Limited license detection, not comprehensive

```bash
# Scan with license detection
trivy fs --severity HIGH,CRITICAL \
         --format json \
         --output report.json \
         /path/to/project

# Note: License info still minimal compared to CycloneDX
```

---

### Option 3: Parallel Scanning - Recommended CI/CD Setup ⭐ **BEST PRACTICE**

**Concept:** Run both Trivy and License scanner in parallel

#### GitHub Actions Example:
```yaml
name: Security Scanning

on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      # Run Trivy for vulnerabilities
      - name: Run Trivy Scan
        run: |
          trivy fs --format json --output trivy-report.json .
          
      # Run CycloneDX for full SBOM (includes licenses)
      - name: Generate CycloneDX SBOM
        run: |
          mvn cyclonedx:makeBom
          cp target/bom.json cyclonedx-sbom.json
          
      # Upload both to Nexus
      - name: Upload to Nexus
        run: |
          curl -v -u $NEXUS_USER:$NEXUS_PASS \
               --upload-file trivy-report.json \
               $NEXUS_URL/repo/project/1.0-trivy-report.json
          
          curl -v -u $NEXUS_USER:$NEXUS_PASS \
               --upload-file cyclonedx-sbom.json \
               $NEXUS_URL/repo/project/1.0-sbom.cyclonedx.json
```

---

### Option 4: Add License Detection to Dashboard

**What:** Fetch both Trivy and CycloneDX files, merge data
**Complexity:** Medium
**Benefit:** Single unified view

#### Implementation:

```python
# services/cyclonedx_parser.py (NEW)
class CycloneDXParser:
    def parse_cyclonedx_sbom(self, cyclonedx_content):
        """Extract license information from CycloneDX SBOM"""
        components = cyclonedx_content.get('components', [])
        
        licenses_by_package = {}
        for component in components:
            pkg_name = component.get('name')
            licenses = component.get('licenses', [])
            
            license_list = []
            for license_obj in licenses:
                if 'license' in license_obj:
                    license_list.append(license_obj['license']['name'])
                elif 'expression' in license_obj:
                    license_list.append(license_obj['expression'])
            
            licenses_by_package[pkg_name] = license_list
        
        return licenses_by_package

# In vulnerability_details.html
def get_vulnerability_with_license(scan_id, vuln_id):
    """Get vulnerability AND license info"""
    vuln = get_vulnerability(scan_id, vuln_id)  # From Trivy
    
    # Load CycloneDX if available
    cyclonedx = fetch_cyclonedx_sbom(scan_id)
    if cyclonedx:
        licenses = cyclonedx.get_licenses_for_package(vuln['package_name'])
        vuln['licenses'] = licenses
    
    return vuln
```

---

## Comparison: Implementation Complexity vs Coverage

| Option | Complexity | License Info | Timeline | Recommendation |
|--------|-----------|--------------|----------|---|
| **Option 1: CycloneDX Parallel** | Medium | ✅ Complete | 2-3 days | ⭐ **BEST** |
| **Option 2: Trivy with License Plugin** | Low | ⚠️ Limited | 1 day | Quick fix only |
| **Option 3: CI/CD Pipeline Update** | Medium | ✅ Complete | 1-2 days | **PRODUCTION** |
| **Option 4: Dashboard Enhancement** | High | ✅ Complete | 3-5 days | Ultimate solution |

---

## Quick Implementation Guide

### Step 1: Enable CycloneDX Generation (Immediate)

**For Maven projects:**
```xml
<!-- pom.xml -->
<build>
  <plugins>
    <plugin>
      <groupId>org.cyclonedx</groupId>
      <artifactId>cyclonedx-maven-plugin</artifactId>
      <version>2.7.10</version>
      <executions>
        <execution>
          <phase>package</phase>
          <goals>
            <goal>makeBom</goal>
          </goals>
        </execution>
      </executions>
    </plugin>
  </plugins>
</build>
```

Run: `mvn clean package` → generates `target/bom.json`

**For Docker/Container images:**
```bash
# Install Syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Generate SBOM
syft packages <image> -o cyclonedx-json > sbom.cyclonedx.json
```

### Step 2: Upload Both Files to Nexus

```bash
#!/bin/bash
# upload-sbom.sh

NEXUS_URL="http://your-nexus:8081"
NEXUS_REPO="your-repository"
ARTIFACT_PATH="com/example/myapp/1.0.0"

# Upload Trivy report
curl -v -u admin:password \
     --upload-file trivy-report.json \
     "$NEXUS_URL/repository/$NEXUS_REPO/$ARTIFACT_PATH/myapp-1.0.0-trivy-report.json"

# Upload CycloneDX SBOM
curl -v -u admin:password \
     --upload-file bom.json \
     "$NEXUS_URL/repository/$NEXUS_REPO/$ARTIFACT_PATH/myapp-1.0.0-sbom.cyclonedx.json"
```

### Step 3: Update Dashboard to Show Licenses

Once both files are in Nexus, update the dashboard:

```python
# app.py
@app.route('/scan/<scan_id>/vulnerability/<vuln_id>')
def vulnerability_detail(scan_id, vuln_id):
    scan = app_data['scans'][scan_id]
    
    # Get vulnerability from Trivy
    vulnerability = find_vulnerability(scan, vuln_id)
    
    # Try to get license info from CycloneDX
    licenses = fetch_licenses_from_sbom(scan, vulnerability['properties']['package_name'])
    vulnerability['licenses'] = licenses
    
    return render_template('vulnerability_details.html',
        scan=scan,
        vulnerability=vulnerability
    )
```

### Step 4: Display License in Template

```html
<!-- vulnerability_details.html - Add to package card -->
{% if vulnerability.licenses %}
<div class="card mb-3">
    <div class="card-header">
        <h6 class="mb-0"><i class="fas fa-certificate me-2"></i>License Information</h6>
    </div>
    <div class="card-body">
        <div class="d-flex flex-wrap gap-2">
            {% for license in vulnerability.licenses %}
            <span class="badge bg-info">{{ license }}</span>
            {% endfor %}
        </div>
        <small class="text-muted d-block mt-2">
            <i class="fas fa-info-circle me-1"></i>
            From CycloneDX SBOM
        </small>
    </div>
</div>
{% endif %}
```

---

## Data Flow: Trivy + CycloneDX Combined

```
Source Code / Container Image
    ├─ Trivy Scan
    │  └─ trivy-report.json (vulnerabilities)
    │     - CVE IDs
    │     - CVSS scores
    │     - Affected packages
    │     - Fix versions
    │
    └─ CycloneDX SBOM
       └─ sbom.cyclonedx.json (components + licenses)
          - Package names & versions
          - License names (MIT, Apache, GPL, etc.)
          - Dependencies
          - Component information

    ↓ Upload both to Nexus ↓

Dashboard
    └─ Vulnerability Details Page
       - CVE & Severity (from Trivy)
       - Package & Version (from Trivy)
       - Fix Version (from Trivy)
       - License Info (from CycloneDX)
       - All combined in one view
```

---

## Recommendation

**Best approach for your use case:**

1. **Short-term (This week):** 
   - Add CycloneDX plugin to your build
   - Upload both Trivy and CycloneDX files to Nexus
   - This works with current dashboard

2. **Medium-term (Next sprint):**
   - Update dashboard to fetch and display CycloneDX
   - Show licenses on vulnerability details page
   - Merge Trivy + CycloneDX data in unified view

3. **Long-term:**
   - Build license compliance dashboard
   - Automated license violation alerts
   - License usage reports

---

## Files to Modify/Create

| Action | File | Effort |
|--------|------|--------|
| Create | `services/cyclonedx_parser.py` | Low |
| Modify | `app.py` (add license route) | Low |
| Modify | `vulnerability_details.html` (add license card) | Low |
| Modify | `nexus_client.py` (fetch CycloneDX files) | Medium |

Would you like me to implement the dashboard enhancement to fetch and display license information from CycloneDX SBOMs?
