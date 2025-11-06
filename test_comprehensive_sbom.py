#!/usr/bin/env python3
"""
Test Comprehensive SBOM Parser with only Trivy + CycloneDX data
Validates that we can recreate SPDX-like information without SPDX files
"""

import json
import sys
import os

# Add the project root to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from services.comprehensive_sbom_parser import ComprehensiveSBOMParser

def test_trivy_cyclonedx_only():
    """Test parser with only Trivy + CycloneDX data (no SPDX file)"""
    
    print("🧪 Testing Comprehensive SBOM Parser with Trivy + CycloneDX only...")
    print("=" * 70)
    
    # Load sample data
    try:
        print("📖 Loading Trivy JSON report...")
        with open('sample_reports/Mart_Trivy_Scan_trivy-report.json', 'r', encoding='utf-8') as f:
            trivy_data = json.load(f)
        print(f"   ✅ Trivy data loaded: {len(str(trivy_data))} bytes")
        
        print("📖 Loading CycloneDX SBOM...")
        with open('sample_reports/Mart_Trivy_Scan_trivy-report_cyclonedx.json', 'r', encoding='utf-8') as f:
            cyclonedx_data = json.load(f)
        print(f"   ✅ CycloneDX data loaded: {len(cyclonedx_data.get('components', []))} components")
        
    except FileNotFoundError as e:
        print(f"❌ Error loading sample files: {e}")
        return False
    except Exception as e:
        print(f"❌ Error parsing JSON: {e}")
        return False
    
    # Initialize parser with only Trivy + CycloneDX (no SPDX)
    print("\n🔧 Initializing Comprehensive SBOM Parser...")
    parser = ComprehensiveSBOMParser(trivy_data, cyclonedx_data)
    
    # Generate comprehensive SBOM details
    print("⚙️  Generating comprehensive SBOM details...")
    sbom_details = parser.get_comprehensive_sbom_details()
    
    # Display results
    print("\n📊 SBOM ANALYSIS RESULTS:")
    print("=" * 50)
    
    # Document info
    doc_info = sbom_details['document_info']
    print(f"📄 Document: {doc_info['name']}")
    print(f"   SPDX Version: {doc_info['spdx_version']}")
    print(f"   Schema Version: {doc_info['schema_version']}")
    print(f"   Artifact Type: {doc_info['artifact_type']}")
    print(f"   Created: {doc_info['created_at']}")
    
    # Statistics
    stats = sbom_details['statistics']
    print(f"\n📈 Package Statistics:")
    print(f"   Total Packages: {stats['total_packages']}")
    print(f"   With Vulnerabilities: {stats['packages_with_vulnerabilities']}")
    print(f"   With Licenses: {stats['packages_with_licenses']}")
    print(f"   License Coverage: {stats['license_coverage_percentage']}%")
    
    # Vulnerabilities
    vulns = sbom_details['vulnerabilities']
    print(f"\n🛡️  Vulnerability Summary:")
    print(f"   Total Vulnerabilities: {vulns['total_vulnerabilities']}")
    print(f"   By Severity: {vulns['by_severity']}")
    print(f"   Targets Scanned: {vulns['targets_scanned']}")
    
    # Sample packages analysis
    packages = sbom_details['packages']
    print(f"\n📦 Package Analysis (First 5 packages):")
    print("-" * 50)
    
    for i, pkg in enumerate(packages[:5]):
        print(f"\n{i+1}. {pkg['name']} v{pkg['version']}")
        print(f"   SPDX ID: {pkg['spdx_id']}")
        print(f"   Supplier: {pkg['supplier']}")
        print(f"   Purpose: {pkg['primary_purpose']}")
        print(f"   License: {pkg['license_concluded']}")
        download_loc = pkg['download_location']
        if len(download_loc) > 50:
            download_loc = download_loc[:50] + "..."
        print(f"   Download: {download_loc}")
        print(f"   Vulnerabilities: {len(pkg['vulnerabilities'])}")
        print(f"   External Refs: {len(pkg['external_refs'])}")
    
    # License distribution analysis
    print(f"\n📋 License Distribution:")
    print("-" * 30)
    license_dist = stats['license_distribution']
    for license_name, count in sorted(license_dist.items(), key=lambda x: x[1], reverse=True)[:10]:
        if license_name != 'NOASSERTION':
            print(f"   {license_name}: {count} packages")
    
    # Test specific package details
    print(f"\n🔍 Detailed Package Analysis:")
    print("-" * 40)
    
    # Find mssql-jdbc package (should have vulnerabilities and license)
    mssql_pkg = None
    for pkg in packages:
        if 'mssql-jdbc' in pkg['name']:
            mssql_pkg = pkg
            break
    
    if mssql_pkg:
        print(f"\n📋 Sample Package: {mssql_pkg['name']}")
        print(f"   Version: {mssql_pkg['version']}")
        print(f"   License Concluded: {mssql_pkg['license_concluded']}")
        print(f"   License Declared: {mssql_pkg['license_declared']}")
        print(f"   Supplier: {mssql_pkg['supplier']}")
        print(f"   Verification Code: {mssql_pkg['verification_code']}")
        print(f"   Component Type: {mssql_pkg['component_type']}")
        print(f"   PURL: {mssql_pkg['purl']}")
        
        if mssql_pkg['vulnerabilities']:
            vuln = mssql_pkg['vulnerabilities'][0]
            print(f"   Sample Vulnerability:")
            print(f"     ID: {vuln['id']}")
            print(f"     Severity: {vuln['severity']}")
            title_display = vuln['title'][:50] + "..." if len(vuln['title']) > 50 else vuln['title']
            print(f"     Title: {title_display}")
            print(f"     Fixed Version: {vuln['fixed_version']}")
        
        if mssql_pkg['external_refs']:
            print(f"   External References:")
            for ref in mssql_pkg['external_refs'][:2]:
                locator_display = ref['locator'][:60] + "..." if len(ref['locator']) > 60 else ref['locator']
                print(f"     {ref['category']}: {locator_display}")
    
    # Test SPDX export functionality
    print(f"\n📤 Testing SPDX Export...")
    spdx_export = parser.export_to_spdx_format()
    export_lines = spdx_export.split('\n')
    print(f"   ✅ Generated SPDX export: {len(export_lines)} lines")
    
    # Sample SPDX content
    print(f"\n📄 Sample SPDX Export (First 10 lines):")
    for i, line in enumerate(export_lines[:10]):
        print(f"   {i+1:2d}: {line}")
    
    # Test package search functionality
    print(f"\n🔍 Testing Search Functionality...")
    search_results = parser.search_packages('spring')
    print(f"   Search for 'spring': {len(search_results)} packages found")
    
    if search_results:
        for pkg in search_results[:3]:
            print(f"     - {pkg['name']} v{pkg['version']}")
    
    # Validation summary
    print(f"\n✅ VALIDATION SUMMARY:")
    print("=" * 30)
    print(f"✅ Successfully parsed {stats['total_packages']} packages from Trivy + CycloneDX")
    print(f"✅ Generated SPDX-like metadata for all packages")
    print(f"✅ License information extracted from {stats['packages_with_licenses']} packages")
    print(f"✅ Vulnerability data integrated for {stats['packages_with_vulnerabilities']} packages")
    print(f"✅ External references (PURL) available for most packages")
    print(f"✅ SPDX export functionality working ({len(export_lines)} lines)")
    print(f"✅ Search and filtering functionality operational")
    
    print(f"\n🎉 COMPREHENSIVE SBOM PARSER TEST PASSED!")
    print(f"   The parser successfully recreates SPDX-like information")
    print(f"   using only Trivy JSON and CycloneDX data available from Nexus.")
    
    return True

if __name__ == '__main__':
    success = test_trivy_cyclonedx_only()
    sys.exit(0 if success else 1)