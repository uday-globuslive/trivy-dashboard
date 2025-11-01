# Naming Convention for SBOM Files in Nexus

## Clarification on File Organization

Your Nexus repository has a **simple and elegant naming convention**:

### File Organization

```
Same Folder:
├─ projectname.sbom-version-trivy-report.json     (Trivy vulnerability data)
└─ projectname.sbom-version.json                  (CycloneDX component/license data)
```

### Example

```
Folder: /com/mccamish/AGP_Stellar_SSO.sbom-1.0.0/

Files:
├─ AGP_Stellar_SSO.sbom-1.0.0-trivy-report.json
│  └─ Contains: CVE vulnerabilities, severity, affected versions
│
└─ AGP_Stellar_SSO.sbom-1.0.0.json
   └─ Contains: Components, licenses, dependencies, supplier info
```

---

## How the Parser Works Now

### 1. File Discovery

When dashboard loads Trivy reports, it automatically gets the path:
```
Path from Nexus:
com/mccamish/AGP_Stellar_SSO.sbom-1.0.0/AGP_Stellar_SSO.sbom-1.0.0-trivy-report.json
```

### 2. Automatic CycloneDX Lookup

The parser **automatically derives** the CycloneDX path by removing `-trivy-report` suffix:

```python
trivy_path = "com/mccamish/AGP_Stellar_SSO.sbom-1.0.0/AGP_Stellar_SSO.sbom-1.0.0-trivy-report.json"

# Parser automatically converts to:
cyclonedx_path = "com/mccamish/AGP_Stellar_SSO.sbom-1.0.0/AGP_Stellar_SSO.sbom-1.0.0.json"
```

### 3. Implementation

In `services/nexus_client.py`:

```python
def download_cyclonedx_sbom(self, trivy_path):
    """
    Download CycloneDX SBOM file from Nexus
    
    Takes Trivy path and derives CycloneDX path by removing "-trivy-report" suffix
    
    Example:
        Input:  com/mccamish/proj.sbom-v1/proj.sbom-v1-trivy-report.json
        Output: com/mccamish/proj.sbom-v1/proj.sbom-v1.json
    """
    # Remove "-trivy-report" from the path
    cyclonedx_path = trivy_path.replace('-trivy-report.json', '.json')
    
    # Construct URL and download
    download_url = f"{self.nexus_url}/repository/{self.repository}/{cyclonedx_path}"
    response = self.session.get(download_url, timeout=30)
    return response.json()
```

---

## Data Flow

```
Dashboard Load:
1. Discovers Trivy file: AGP_Stellar_SSO.sbom-1.0.0-trivy-report.json
   ↓
2. Stores path in scan metadata: trivy_report_path = "com/mccamish/..."
   ↓
3. User clicks on vulnerability detail
   ↓
4. App automatically looks for:
   - Trivy: AGP_Stellar_SSO.sbom-1.0.0-trivy-report.json  ✓ Found
   - SBOM:  AGP_Stellar_SSO.sbom-1.0.0.json              ✓ Found (derived)
   ↓
5. Merges both into single SPDX-like view
   ↓
6. Displays with license + vulnerability info
```

---

## Integration Points

### A. Vulnerability Details Page
- When you visit a vulnerability detail, it automatically:
  1. Fetches Trivy data using stored path
  2. Derives and fetches CycloneDX path
  3. Merges data
  4. Shows combined info in template

### B. SBOM Export
- When you export SBOM:
  1. Uses stored trivy_report_path
  2. Derives CycloneDX path
  3. Fetches both files
  4. Exports merged SPDX JSON

### C. No Manual Path Configuration Needed
- Everything is automatic!
- Just store the Trivy file path
- CycloneDX path is automatically derived

---

## Code Changes

### `app.py` - Enhanced vulnerability_detail route
```python
@app.route('/scan/<scan_id>/vulnerability/<vuln_id>')
def vulnerability_detail(scan_id, vuln_id):
    scan = app_data['scans'][scan_id]
    trivy_report_path = scan.get('trivy_report_path')  # Stored path
    
    # Fetch Trivy
    trivy_content = nexus_client.download_trivy_report(trivy_report_path)
    
    # Fetch CycloneDX (path automatically derived)
    cyclonedx_content = nexus_client.download_cyclonedx_sbom(trivy_report_path)
    
    # Merge
    parser = HybridSBOMParser(trivy_content, cyclonedx_content)
    # ... rest of logic
```

### `app.py` - Scan data includes path
```python
# When loading scan data from Trivy file:
scan_data = {
    'id': scan_id,
    'project': project_name,
    'build_number': trivy_file['build_number'],
    'timestamp': trivy_file['timestamp'],
    'trivy_report_path': trivy_file['path'],  # ← NEW: Store the actual path
    'vulnerabilities': parsed_data['vulnerabilities'],
    'components': parsed_data['components'],
    'metadata': parsed_data['metadata']
}
```

### `services/nexus_client.py` - Simplified CycloneDX download
```python
def download_cyclonedx_sbom(self, trivy_path):
    """
    Download CycloneDX from same folder as Trivy
    
    Automatically derives path by removing '-trivy-report' suffix
    """
    cyclonedx_path = trivy_path.replace('-trivy-report.json', '.json')
    download_url = f"{self.nexus_url}/repository/{self.repository}/{cyclonedx_path}"
    response = self.session.get(download_url, timeout=30)
    return response.json()
```

---

## Benefits of This Approach

✅ **Simple**: No complex path patterns to configure  
✅ **Automatic**: CycloneDX path derived from Trivy path  
✅ **Flexible**: Works with any naming pattern as long as Trivy has `-trivy-report` suffix  
✅ **Robust**: Gracefully handles missing CycloneDX files  
✅ **Zero Configuration**: Everything automatic  

---

## Example Workflow

### Scenario: Your actual files in Nexus

```
/com/mccamish/AGP_Stellar_SSO.sbom-1.0.0/
  ├─ AGP_Stellar_SSO.sbom-1.0.0-trivy-report.json
  └─ AGP_Stellar_SSO.sbom-1.0.0.json
```

### Dashboard Load Process

1. **Nexus discovery finds:**
   ```
   Trivy file: com/mccamish/AGP_Stellar_SSO.sbom-1.0.0/AGP_Stellar_SSO.sbom-1.0.0-trivy-report.json
   ```

2. **Scan data stored with path:**
   ```python
   {
     'id': 'AGP_Stellar_SSO_1.0.0',
     'trivy_report_path': 'com/mccamish/AGP_Stellar_SSO.sbom-1.0.0/AGP_Stellar_SSO.sbom-1.0.0-trivy-report.json',
     'vulnerabilities': [...],
     ...
   }
   ```

3. **User clicks vulnerability detail:**
   ```
   URL: /scan/AGP_Stellar_SSO_1.0.0/vulnerability/CVE-2023-1234
   ```

4. **App automatically:**
   - Downloads Trivy from stored path ✓
   - Derives SBOM path: `com/mccamish/AGP_Stellar_SSO.sbom-1.0.0/AGP_Stellar_SSO.sbom-1.0.0.json`
   - Downloads SBOM ✓
   - Merges both ✓
   - Shows combined vulnerability page ✓

---

## Troubleshooting

### If CycloneDX not found

**Why**: File not in same folder or different naming pattern

**Check**:
1. Is the file in the same folder as Trivy report?
2. Does it end with `.json` (not `-trivy-report.json`)?

**Solution**:
- Dashboard still works! It shows Trivy data alone
- CycloneDX is optional - system gracefully degrades

### If you need different naming pattern

You can modify `download_cyclonedx_sbom()` method:

```python
# Current (works for your files):
cyclonedx_path = trivy_path.replace('-trivy-report.json', '.json')

# If you use different pattern:
cyclonedx_path = trivy_path.replace('-trivy-report', '-sbom.cyclonedx')
```

---

## Summary

Your naming convention is now **fully integrated** into the dashboard:

1. ✅ Trivy files: `*-trivy-report.json`
2. ✅ CycloneDX files: Same name without `-trivy-report`
3. ✅ Automatic derivation: No manual configuration
4. ✅ Merged display: Security + License info together
5. ✅ Export capability: SPDX JSON download

**Everything is automatic!** Just upload your files with the correct naming and the dashboard handles the rest.
