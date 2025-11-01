# SBOM Details from Trivy Report JSON - Enhancement Guide

## Overview

The Trivy Security Dashboard now displays comprehensive SBOM (Software Bill of Materials) details directly from native Trivy JSON report files. All the information that was previously only available in CycloneDX SBOM files is now extracted and displayed from the Trivy reports.

## Data Extracted from Trivy Reports

### 1. **Package Information**
From each vulnerability in the Trivy report:
- **Package Name** (`PkgName`): The affected package name
- **Installed Version** (`InstalledVersion`): Current version in the scan target
- **Fixed Version** (`FixedVersion`): Available patched version(s)
- **Package URL (PURL)** (`PkgIdentifier.PURL`): Standard package identifier format
- **Package Path** (`PkgPath`): Location in the target system/container

### 2. **Vulnerability Details**
- **CVE ID** (`VulnerabilityID`): CVE identifier
- **Title** (`Title`): Vulnerability title/name
- **Description** (`Description`): Detailed vulnerability description
- **Severity** (`Severity`): CRITICAL, HIGH, MEDIUM, LOW
- **CVSS Scores** (`CVSS`): V2 and V3 scores from multiple sources (NVD, GitHub, RedHat, etc.)
- **CVSS Vectors** (`CVSS.*.V3Vector`/`V2Vector`): CVSS calculation vectors

### 3. **Weakness Information**
- **CWE IDs** (`CweIDs`): Common Weakness Enumeration references
- Links to CWE definitions for understanding vulnerability types

### 4. **Timeline & Tracking**
- **Published Date** (`PublishedDate`): When the vulnerability was published
- **Last Modified Date** (`LastModifiedDate`): Latest update information
- **Layer/Component Info** (`Layer.Digest`): For container scans, the specific layer

### 5. **Source & References**
- **Data Source** (`DataSource`): Where the vulnerability data came from
- **References** (`References`): Links to advisories, patches, and additional information
- **Primary URL** (`PrimaryURL`): Direct link to vulnerability details

### 6. **Target Information**
- **Target/Component** (`Target`): What was scanned (filesystem, container image, etc.)
- **Affected Resources** (`affects`): Specific targets where vulnerability was found

## New Features

### 1. Enhanced Vulnerability Details Page
**Route:** `/scan/<scan_id>/vulnerability/<vuln_id>`

Displays comprehensive vulnerability information including:
- CVE header with severity badge
- Full description and recommendations
- CVSS scores with multiple sources
- CWE information with links
- Package details (name, versions, PURL)
- Affected targets and components
- Publication and update timeline
- References and advisory links

### 2. SBOM Data Display Sections

#### Package Card
Shows all SBOM-related package information:
```
Name: org.apache.commons:commons-lang3
Installed: 3.14.0
Fixed: 3.18.0
Path: CacheManager/pom.xml
Layer: sha256:abc123...
```

#### Affected Targets
Lists all targets/components affected by the vulnerability:
```
Target: CacheManager/pom.xml
Version: 3.14.0

Target: WebApp/pom.xml
Version: 3.14.0
```

#### Data Source
Shows where the vulnerability information came from:
```
Source: GitHub Security Advisory Maven (GHSA)
```

## File Structure

### Modified Files
1. **`trivy_parser.py`**
   - Enhanced to extract `Title`, `PURL`, `Severity Source`, and `Primary URL`
   - Added these fields to the `properties` section for vulnerability objects

2. **`scan.html`**
   - Updated vulnerability table links to point to new detail page
   - CVE IDs now link to `/scan/<id>/vulnerability/<cve>` instead of external NVD

3. **`app.py`**
   - Added new route: `/scan/<scan_id>/vulnerability/<vuln_id>`
   - Handles rendering vulnerability detail page with full SBOM information

### New Files
1. **`templates/vulnerability_details.html`**
   - Complete vulnerability details page
   - Displays all SBOM and Trivy report data
   - Organized in logical sections:
     - Vulnerability information
     - CVSS scores and metrics
     - Package details from Trivy report
     - Affected targets
     - CWE information
     - Timeline
     - Data sources and references

## Usage

### Accessing Vulnerability Details

1. **From Dashboard:**
   - Navigate to Projects → Select a project
   - View scan details
   - Click on a CVE ID in the vulnerabilities table

2. **Direct URL:**
   ```
   http://localhost:5001/scan/scan_id/vulnerability/CVE-2025-12345
   ```

### Example Vulnerability Entry

```python
{
    'id': 'CVE-2025-48989',
    'title': 'tomcat: http/2 "MadeYouReset" DoS attack through HTTP/2 control frames',
    'severity': 'HIGH',
    'description': 'Improper Resource Shutdown or Release vulnerability...',
    'properties': {
        'package_name': 'org.apache.tomcat.embed:tomcat-embed-core',
        'installed_version': '11.0.9',
        'fixed_version': '11.0.10, 10.1.44, 9.0.108',
        'purl': 'pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@11.0.9',
        'package_path': 'CacheManager/pom.xml',
        'severity_source': 'ghsa',
        'primary_url': 'https://avd.aquasec.com/nvd/cve-2025-48989'
    },
    'ratings': [
        {
            'method': 'CVSSv3',
            'score': 7.5,
            'severity': 'HIGH',
            'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'
        }
    ],
    'cwes': [404],
    'advisories': [
        {'title': 'Reference', 'url': 'https://github.com/apache/tomcat/...'},
        ...
    ],
    'published': datetime(2025, 7, 11),
    'updated': datetime(2025, 7, 15)
}
```

## Benefits

1. **Single Source of Truth**: All SBOM and vulnerability data from Trivy reports
2. **No Format Conversion**: Direct display of Trivy report data
3. **Comprehensive Details**: Full context including CVSS scores, CWE info, and timeline
4. **Better UX**: Organized display with logical grouping of related information
5. **Standards Compliance**: Uses PURL for package identification
6. **Multiple Score Sources**: Shows CVSS scores from various vendors (NVD, GitHub, RedHat, etc.)

## Data Flow

```
Trivy JSON Report File
    ↓
Nexus Repository (stored as -trivy-report.json)
    ↓
nexus_client.py (downloads files)
    ↓
trivy_parser.py (extracts data)
    ↓
app_data['vulnerabilities'] (indexed by CVE ID)
    ↓
vulnerability_details.html (displayed to user)
```

## Backward Compatibility

- Existing scan list view unchanged
- New detailed view is accessible via links
- All previous data is preserved
- No breaking changes to APIs

## Future Enhancements

1. Export vulnerability details as PDF/JSON
2. Comparison between scan timeline for same package
3. Automated remediation suggestions based on fixed versions
4. Integration with patch management systems
5. Custom severity scoring based on environment
