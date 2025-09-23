#!/usr/bin/env python3
"""
Simple debug script to check SBOM content and project name extraction
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config import Config
from services.nexus_client import NexusClient
from services.cyclonedx_parser import CycloneDXParser
import json

def main():
    print("🔧 Debug: SBOM Content and Project Name Extraction")
    print("=" * 60)
    
    # Initialize services
    nexus_client = NexusClient(Config.NEXUS_URL, Config.NEXUS_USERNAME, Config.NEXUS_PASSWORD, Config.NEXUS_REPOSITORY)
    parser = CycloneDXParser()
    
    # Get SBOM files
    sbom_files = nexus_client.list_sbom_files(limit=5)
    
    if not sbom_files:
        print("❌ No SBOM files found!")
        return
        
    print(f"📦 Found {len(sbom_files)} SBOM files")
    
    for i, sbom_file in enumerate(sbom_files):
        print(f"\n📄 Processing SBOM {i+1}: {sbom_file['filename']}")
        print(f"   Project (from filename): {sbom_file['project']}")
        print(f"   Version: {sbom_file['version']}")
        print(f"   Path: {sbom_file['path']}")
        
        try:
            # Download SBOM content
            sbom_content = nexus_client.download_sbom(sbom_file['path'])
            print(f"   📥 Downloaded successfully ({len(json.dumps(sbom_content))} bytes)")
            
            # Show raw SBOM structure
            print("   📋 Raw SBOM structure:")
            print(f"      bomFormat: {sbom_content.get('bomFormat', 'missing')}")
            print(f"      specVersion: {sbom_content.get('specVersion', 'missing')}")
            print(f"      metadata: {sbom_content.get('metadata', {}).keys()}")
            
            # Check metadata component
            metadata = sbom_content.get('metadata', {})
            component = metadata.get('component', {})
            print(f"      metadata.component: {component}")
            print(f"      metadata.component.name: {component.get('name', 'MISSING')}")
            
            # Parse with our parser
            parsed_data = parser.parse_cyclonedx(sbom_content)
            print(f"   🔍 Parsed project name: '{parsed_data['metadata']['project']}'")
            print(f"   📊 Components: {len(parsed_data['components'])}")
            print(f"   🔒 Vulnerabilities: {len(parsed_data['vulnerabilities'])}")
            
            # Show some sample components if available
            if parsed_data['components']:
                print(f"   📦 Sample components:")
                for j, comp in enumerate(parsed_data['components'][:3]):
                    print(f"      {j+1}. {comp.get('name', 'unnamed')} ({comp.get('type', 'unknown')})")
            
        except Exception as e:
            print(f"   ❌ Error processing SBOM: {str(e)}")
            import traceback
            print(f"   🔍 Full error: {traceback.format_exc()}")

if __name__ == "__main__":
    main()