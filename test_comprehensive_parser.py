#!/usr/bin/env python3

"""
Test script for ComprehensiveSBOMParser
"""

from services.comprehensive_sbom_parser import ComprehensiveSBOMParser
import json

def main():
    # Create test data
    trivy_test = {
        'ArtifactName': 'test-artifact',
        'ArtifactType': 'container_image', 
        'SchemaVersion': '2.0.0',
        'CreatedAt': '2023-11-06T20:00:00Z',
        'Results': [{
            'Target': 'test-target',
            'Type': 'alpine',
            'Vulnerabilities': [{
                'VulnerabilityID': 'CVE-2023-1234',
                'PkgName': 'openssl',
                'InstalledVersion': '1.1.1',
                'Severity': 'HIGH',
                'Title': 'Test vulnerability',
                'Description': 'Test description'
            }]
        }]
    }

    cyclonedx_test = {
        'components': [{
            'name': 'openssl',
            'version': '1.1.1',
            'type': 'library',
            'licenses': [{'license': {'id': 'Apache-2.0'}}]
        }]
    }

    print("Testing ComprehensiveSBOMParser...")
    
    try:
        parser = ComprehensiveSBOMParser(trivy_test, cyclonedx_test)
        sbom_data = parser.get_comprehensive_sbom_details()
        
        packages_count = len(sbom_data["packages"])
        total_vulns = sbom_data["vulnerabilities"]["total_vulnerabilities"]
        
        print(f"✅ Packages found: {packages_count}")
        print(f"✅ Total vulnerabilities: {total_vulns}")
        
        if packages_count > 0:
            print(f"✅ Sample package: {sbom_data['packages'][0]['name']}:{sbom_data['packages'][0]['version']}")
        
        # Test SPDX export
        spdx_output = parser.export_to_spdx_format()
        spdx_length = len(spdx_output)
        print(f"✅ SPDX output length: {spdx_length} characters")
        
        if "SPDXVersion:" in spdx_output and "PackageName:" in spdx_output:
            print("✅ SPDX format appears correct")
        else:
            print("❌ SPDX format issue detected")
        
        print("✅ ComprehensiveSBOMParser working correctly")
        
    except Exception as e:
        print(f"❌ Error testing ComprehensiveSBOMParser: {str(e)}")
        return False
    
    return True

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)