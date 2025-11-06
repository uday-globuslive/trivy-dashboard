"""
Test script to verify SPDX export functionality
"""

import json
import sys
import os

# Add the parent directory to the path to import our services
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.comprehensive_sbom_parser import ComprehensiveSBOMParser

def test_spdx_export():
    """Test the SPDX export functionality"""
    
    # Load sample data
    sample_dir = "sample_reports"
    
    print("🔍 Loading sample Trivy report...")
    with open(f"{sample_dir}/Mart_Trivy_Scan_trivy-report.json", "r", encoding='utf-8') as f:
        trivy_data = json.load(f)
    
    print("🔍 Loading sample CycloneDX report...")
    with open(f"{sample_dir}/Mart_Trivy_Scan_trivy-report_cyclonedx.json", "r", encoding='utf-8') as f:
        cyclonedx_data = json.load(f)
    
    print("📊 Creating ComprehensiveSBOMParser...")
    parser = ComprehensiveSBOMParser(trivy_data, cyclonedx_data)
    
    print("📤 Testing SPDX text export...")
    spdx_text = parser.export_to_spdx_format()
    
    # Save to file
    export_file = "test_export.spdx"
    with open(export_file, "w", encoding='utf-8') as f:
        f.write(spdx_text)
    
    print(f"✅ SPDX export successful!")
    print(f"📄 File: {export_file}")
    print(f"📏 Size: {len(spdx_text)} characters")
    print(f"📊 Lines: {spdx_text.count(chr(10))} lines")
    
    # Show first few lines
    lines = spdx_text.split('\n')
    print(f"\n🔍 First 10 lines:")
    for i, line in enumerate(lines[:10]):
        print(f"  {i+1:2}. {line}")
    
    # Test JSON export too
    print(f"\n📤 Testing JSON export...")
    sbom_data = parser.get_comprehensive_sbom_details()
    json_export = json.dumps(sbom_data, indent=2, default=str)
    
    json_file = "test_export.json"
    with open(json_file, "w", encoding='utf-8') as f:
        f.write(json_export)
    
    print(f"✅ JSON export successful!")
    print(f"📄 File: {json_file}")
    print(f"📏 Size: {len(json_export)} characters")
    print(f"📦 Packages: {len(sbom_data['packages'])}")
    
    return True

if __name__ == "__main__":
    try:
        success = test_spdx_export()
        if success:
            print(f"\n🎉 Export functionality test completed successfully!")
        else:
            print(f"\n❌ Export test failed!")
    except Exception as e:
        print(f"\n❌ Test failed: {str(e)}")
        import traceback
        traceback.print_exc()