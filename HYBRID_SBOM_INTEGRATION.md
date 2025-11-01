# Integration Guide: Using Hybrid SBOM Parser in Dashboard

## Overview
The `HybridSBOMParser` merges Trivy + CycloneDX data to generate SPDX-like information including:
- ✅ License information (from CycloneDX)
- ✅ Vulnerability data (from Trivy)
- ✅ Copyright/supplier info (derived)
- ✅ Package relationships (from CycloneDX)

## How It Works

### Data Flow
```
CycloneDX SBOM          Trivy JSON Report
   (Licenses)        +    (Vulnerabilities)
        |                        |
        └────────────┬───────────┘
                     |
            HybridSBOMParser.parse()
                     |
        ┌────────────┼────────────┐
        |            |            |
    Components  Relationships  Metadata
        |
   SPDX-like Output with:
   - Package name/version
   - Licenses (from CycloneDX)
   - Vulnerabilities (from Trivy)
   - Copyright (derived)
   - Supplier info
   - PURL references
```

### Priority Order
1. **Primary Source**: CycloneDX (has license info)
2. **Enhancement**: Trivy vulnerabilities
3. **Derived**: SPDX-like fields (copyright, supplier)

## Integration Examples

### 1. Basic Usage in app.py

```python
from services.hybrid_sbom_parser import HybridSBOMParser
import json

@app.route('/scan/<scan_id>/sbom/component/<pkg_name>/<version>')
def component_sbom(scan_id, pkg_name, version):
    """Get complete component SBOM from merged sources"""
    
    # Get Trivy data
    trivy_data = load_trivy_report(scan_id)
    
    # Get CycloneDX data
    cyclonedx_data = load_cyclonedx_sbom(scan_id)
    
    # Merge
    parser = HybridSBOMParser(trivy_data, cyclonedx_data)
    component_info = parser.get_component_sbom(pkg_name, version)
    
    if not component_info:
        return jsonify({'error': 'Component not found'}), 404
    
    return render_template('component_sbom.html', component=component_info)
```

### 2. Generate Full SPDX Document

```python
@app.route('/scan/<scan_id>/sbom/export/spdx')
def export_spdx_sbom(scan_id):
    """Export merged SBOM as SPDX JSON"""
    
    trivy_data = load_trivy_report(scan_id)
    cyclonedx_data = load_cyclonedx_sbom(scan_id)
    
    parser = HybridSBOMParser(trivy_data, cyclonedx_data)
    spdx_json = parser.to_spdx_json()
    
    return Response(
        spdx_json,
        mimetype='application/json',
        headers={'Content-Disposition': 'attachment; filename=sbom.spdx.json'}
    )
```

### 3. Enhanced Vulnerability Details with License

```python
@app.route('/scan/<scan_id>/vulnerability/<vuln_id>')
def vulnerability_detail(scan_id, vuln_id):
    """Show vulnerability with license info from merged SBOM"""
    
    scan = app_data['scans'][scan_id]
    
    # Get vulnerability
    vulnerability = find_vulnerability(scan, vuln_id)
    
    # Get Trivy and CycloneDX data
    trivy_data = load_trivy_report(scan_id)
    cyclonedx_data = load_cyclonedx_sbom(scan_id)
    
    # Merge data sources
    parser = HybridSBOMParser(trivy_data, cyclonedx_data)
    
    # Get component with license info
    pkg_name = vulnerability['properties']['package_name']
    version = vulnerability['properties']['installed_version']
    component_info = parser.get_component_sbom(pkg_name, version)
    
    if component_info:
        vulnerability['license_info'] = {
            'concluded': component_info.get('licenseConcluded'),
            'declared': component_info.get('licenseDeclared'),
            'comments': component_info.get('licenseComments'),
            'copyright': component_info.get('copyrightText'),
            'supplier': component_info.get('supplier'),
        }
    
    return render_template('vulnerability_details.html',
        scan=scan,
        vulnerability=vulnerability
    )
```

### 4. Compliance Dashboard

```python
@app.route('/scan/<scan_id>/compliance')
def compliance_dashboard(scan_id):
    """Dashboard showing license compliance + security"""
    
    trivy_data = load_trivy_report(scan_id)
    cyclonedx_data = load_cyclonedx_sbom(scan_id)
    
    parser = HybridSBOMParser(trivy_data, cyclonedx_data)
    merged_sbom = parser.parse()
    
    # Analyze compliance
    compliance_report = {
        'total_components': len(merged_sbom['components']),
        'components_with_license': len([
            c for c in merged_sbom['components'] 
            if c.get('licenseConcluded') != 'NOASSERTION'
        ]),
        'components_with_vulnerabilities': len([
            c for c in merged_sbom['components'] 
            if 'vulnerabilities' in c and c['vulnerabilities']
        ]),
        'license_types': self._get_unique_licenses(merged_sbom),
        'critical_vulnerabilities': self._count_critical_vulns(merged_sbom),
    }
    
    return render_template('compliance_dashboard.html', report=compliance_report)
```

## Data Mapping: What Information Comes From Where

### Component Basic Info
```
Field                   | Source
─────────────────────────────────────────
Name                    | CycloneDX (primary) / Trivy (fallback)
Version                 | CycloneDX (primary) / Trivy (fallback)
Type                    | CycloneDX
PURL                    | CycloneDX
Download Location       | CycloneDX (primary) / Generated
```

### License Information
```
Field                   | Source
─────────────────────────────────────────
Concluded License       | CycloneDX licenses field
Declared License        | CycloneDX licenses field
License Comments        | CycloneDX + Generated
License Text            | CycloneDX (if available)
```

### Security Information
```
Field                   | Source
─────────────────────────────────────────
Vulnerabilities         | Trivy (primary)
CVSS Scores            | Trivy
Severity               | Trivy
Fix Version            | Trivy
CVE ID                 | Trivy
```

### Derived Information
```
Field                   | Source
─────────────────────────────────────────
Copyright              | CycloneDX supplier (derived)
Supplier               | CycloneDX
Creation Date          | Current timestamp
SPDX ID               | Generated from name+version
Relationships         | CycloneDX dependencies
```

## Template Enhancement: vulnerability_details.html

Add license section to vulnerability details template:

```html
<!-- Add after the package information card -->

{% if vulnerability.license_info %}
<div class="card mb-3">
    <div class="card-header bg-light">
        <h6 class="mb-0">
            <i class="fas fa-certificate text-info me-2"></i>
            License & Copyright Information
        </h6>
    </div>
    <div class="card-body">
        <div class="row">
            <div class="col-md-6">
                <h6 class="text-muted">License Status</h6>
                <div class="d-flex flex-wrap gap-2 mb-3">
                    {% if vulnerability.license_info.concluded != 'NOASSERTION' %}
                        <span class="badge bg-success">
                            <i class="fas fa-check-circle me-1"></i>
                            {{ vulnerability.license_info.concluded }}
                        </span>
                    {% else %}
                        <span class="badge bg-secondary">
                            Not Detected
                        </span>
                    {% endif %}
                </div>
            </div>
            <div class="col-md-6">
                <h6 class="text-muted">Supplier</h6>
                {% if vulnerability.license_info.supplier %}
                    <p class="mb-0">
                        <strong>{{ vulnerability.license_info.supplier.name }}</strong>
                        {% if vulnerability.license_info.supplier.url %}
                            <a href="{{ vulnerability.license_info.supplier.url }}" 
                               target="_blank" class="ms-2">
                                <i class="fas fa-link"></i>
                            </a>
                        {% endif %}
                    </p>
                {% else %}
                    <p class="text-muted mb-0">Not available</p>
                {% endif %}
            </div>
        </div>
        
        {% if vulnerability.license_info.copyright %}
        <hr>
        <h6 class="text-muted">Copyright</h6>
        <p class="mb-0">{{ vulnerability.license_info.copyright }}</p>
        {% endif %}
        
        {% if vulnerability.license_info.comments %}
        <hr>
        <h6 class="text-muted">License Comments</h6>
        <p class="small text-muted mb-0">{{ vulnerability.license_info.comments }}</p>
        {% endif %}
    </div>
</div>
{% endif %}
```

## What Information Gets Generated

### From CycloneDX
- ✅ Package name, version, type
- ✅ License information (ID, text, URL)
- ✅ Supplier information
- ✅ External references (PURL, VCS)
- ✅ Dependencies

### From Trivy
- ✅ Vulnerabilities (CVE, CVSS, severity)
- ✅ Affected package versions
- ✅ Fix recommendations
- ✅ CWE mappings
- ✅ Description and references

### Generated by Parser
- ✅ SPDX-compliant structure
- ✅ Copyright text (from supplier)
- ✅ Document namespace
- ✅ Creation metadata
- ✅ Relationships
- ✅ External references

## Usage in nexus_client.py

```python
# After fetching both files from Nexus

from services.hybrid_sbom_parser import HybridSBOMParser

def get_merged_sbom(scan_id):
    """Get merged SBOM from Nexus files"""
    
    # Fetch Trivy report
    trivy_json = self.fetch_trivy_report(scan_id)
    trivy_data = json.loads(trivy_json)
    
    # Fetch CycloneDX SBOM
    cyclonedx_json = self.fetch_cyclonedx_sbom(scan_id)
    cyclonedx_data = json.loads(cyclonedx_json)
    
    # Merge
    parser = HybridSBOMParser(trivy_data, cyclonedx_data)
    merged = parser.parse()
    
    return merged

def get_component_info(scan_id, pkg_name, version):
    """Get component info from merged SBOM"""
    
    trivy_data = json.loads(self.fetch_trivy_report(scan_id))
    cyclonedx_data = json.loads(self.fetch_cyclonedx_sbom(scan_id))
    
    parser = HybridSBOMParser(trivy_data, cyclonedx_data)
    return parser.get_component_sbom(pkg_name, version)
```

## Benefits of Hybrid Approach

| Benefit | Details |
|---------|---------|
| **No Extra Tools** | Uses existing Trivy + CycloneDX |
| **Complete Data** | Combines security + license info |
| **SPDX Compliant** | Output in SPDX 2.3 format |
| **Dashboard Ready** | Direct template integration |
| **Backward Compatible** | Works with existing scans |
| **Exportable** | Generate SPDX SBOM files |
| **Derivable Info** | Automatically generates copyright, supplier |

## Next Steps

1. **Add hybrid_sbom_parser.py to services/** (Done ✓)
2. **Update app.py routes** (Add component details endpoint)
3. **Update nexus_client.py** (Add merged SBOM fetch)
4. **Update vulnerability_details.html** (Add license card)
5. **Test with existing data** (Verify merging works)
6. **Export SPDX capability** (New endpoint)

This gives you full SPDX-like data without needing a separate SPDX generator!
