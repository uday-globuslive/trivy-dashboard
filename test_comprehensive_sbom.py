"""
Test script to demonstrate comprehensive SBOM parsing with sample data
"""

import json
import sys
import os

# Add the parent directory to the path to import our services
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.comprehensive_sbom_parser import ComprehensiveSBOMParser

def test_comprehensive_sbom():
    """Test the comprehensive SBOM parser with sample data"""
    
    # Load sample data
    sample_dir = "sample_reports"
    
    print("🔍 Loading sample Trivy report...")
    with open(f"{sample_dir}/Mart_Trivy_Scan_trivy-report.json", "r", encoding='utf-8') as f:
        trivy_data = json.load(f)
    
    print("🔍 Loading sample CycloneDX report...")
    with open(f"{sample_dir}/Mart_Trivy_Scan_trivy-report_cyclonedx.json", "r", encoding='utf-8') as f:
        cyclonedx_data = json.load(f)
    
    print("📊 Parsing comprehensive SBOM details...")
    parser = ComprehensiveSBOMParser(trivy_data, cyclonedx_data)
    sbom_details = parser.get_comprehensive_sbom_details()
    
    # Print summary
    print(f"\n✅ SBOM Details Generated Successfully!")
    print(f"📦 Document Name: {sbom_details['document_info']['name']}")
    print(f"📊 Total Packages: {sbom_details['statistics']['total_packages']}")
    print(f"🔴 Packages with Vulnerabilities: {sbom_details['statistics']['packages_with_vulnerabilities']}")
    print(f"📄 License Coverage: {sbom_details['statistics']['license_coverage_percentage']}%")
    
    print(f"\n🛡️ Vulnerability Summary:")
    for severity, count in sbom_details['vulnerabilities']['by_severity'].items():
        if count > 0:
            print(f"  {severity}: {count}")
    
    print(f"\n📋 Sample Packages:")
    for i, pkg in enumerate(sbom_details['packages'][:5]):  # Show first 5
        print(f"  {i+1}. {pkg['name']} v{pkg['version']}")
        print(f"     License: {pkg['license_concluded']}")
        print(f"     Vulnerabilities: {len(pkg['vulnerabilities'])}")
        print(f"     SPDX ID: {pkg['spdx_id']}")
    
    print(f"\n🔗 Package Relationships: {len(sbom_details['relationships'])}")
    
    # Test SPDX export
    print(f"\n📤 Generating SPDX export...")
    spdx_content = parser.export_to_spdx_format()
    
    # Save SPDX export
    with open("sample_reports/generated_comprehensive_sbom.spdx", "w") as f:
        f.write(spdx_content)
    
    print(f"✅ SPDX export saved to: sample_reports/generated_comprehensive_sbom.spdx")
    print(f"📏 SPDX file size: {len(spdx_content)} characters")
    
    # Test package search
    print(f"\n🔍 Testing package search...")
    search_results = parser.search_packages("junit")
    print(f"Found {len(search_results)} packages matching 'junit'")
    
    return sbom_details

if __name__ == "__main__":
    try:
        sbom_details = test_comprehensive_sbom()
        print(f"\n🎉 Test completed successfully!")
    except Exception as e:
        print(f"\n❌ Test failed: {str(e)}")
        import traceback
        traceback.print_exc()