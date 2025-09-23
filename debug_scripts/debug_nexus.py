#!/usr/bin/env python3
"""
Debug script to test Nexus connection and SBOM file discovery
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config import Config
from services.nexus_client import NexusClient
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    print("🔧 Debug: Nexus Connection and SBOM Discovery")
    print("=" * 60)
    
    # Print configuration
    print(f"📋 Configuration:")
    print(f"  NEXUS_URL: {Config.NEXUS_URL}")
    print(f"  NEXUS_REPOSITORY: {Config.NEXUS_REPOSITORY}")
    print(f"  NEXUS_USERNAME: {Config.NEXUS_USERNAME}")
    print(f"  NEXUS_GROUP_ID: {Config.NEXUS_GROUP_ID}")
    print(f"  NEXUS_ARTIFACT_SUFFIX: {Config.NEXUS_ARTIFACT_SUFFIX}")
    print(f"  NEXUS_ASSET_EXTENSION: {Config.NEXUS_ASSET_EXTENSION}")
    print()
    
    # Initialize client
    nexus_client = NexusClient(Config.NEXUS_URL, Config.NEXUS_USERNAME, Config.NEXUS_PASSWORD, Config.NEXUS_REPOSITORY)
    
    # Test connection
    print("🔗 Testing Nexus connection...")
    if nexus_client.test_connection():
        print("✅ Connection successful!")
    else:
        print("❌ Connection failed!")
        return
    
    print()
    
    # Test generic search first
    print("🔍 Testing generic asset search...")
    try:
        search_url = f"{Config.NEXUS_URL}/service/rest/v1/search/assets"
        params = {
            'repository': Config.NEXUS_REPOSITORY,
            'group': Config.NEXUS_GROUP_ID
        }
        
        response = nexus_client.session.get(search_url, params=params, timeout=30)
        response.raise_for_status()
        
        search_results = response.json()
        items = search_results.get('items', [])
        
        print(f"📦 Found {len(items)} total assets in {Config.NEXUS_GROUP_ID}")
        
        if items:
            print("📋 All assets found:")
            json_files = []
            sbom_files = []
            for i, asset in enumerate(items):
                asset_path = asset.get('path', 'unknown')
                print(f"  {i+1}. {asset_path}")
                print(f"     Size: {asset.get('fileSize', 0)} bytes")
                print(f"     Modified: {asset.get('lastModified', 'unknown')}")
                
                # Check for JSON files
                if asset_path.endswith('.json'):
                    json_files.append(asset_path)
                
                # Check for SBOM-related files
                if '.sbom' in asset_path:
                    sbom_files.append(asset_path)
                    
                print()
            
            print(f"📄 JSON files found: {len(json_files)}")
            for json_file in json_files:
                print(f"   - {json_file}")
            
            print(f"📦 SBOM-related files found: {len(sbom_files)}")
            for sbom_file in sbom_files:
                print(f"   - {sbom_file}")
        print()
        
    except Exception as e:
        print(f"❌ Generic search failed: {str(e)}")
        return
    
    # Test SBOM file discovery
    print("🔍 Testing SBOM file discovery...")
    sbom_files = nexus_client.list_sbom_files(limit=10)
    
    print(f"📦 Found {len(sbom_files)} SBOM files")
    
    if sbom_files:
        print("📋 SBOM files found:")
        for i, sbom in enumerate(sbom_files):
            print(f"  {i+1}. Project: {sbom['project']}")
            print(f"     Version: {sbom['version']}")
            print(f"     Path: {sbom['asset_path']}")
            print(f"     Download URL: {sbom['path']}")
            print()
    else:
        print("❌ No SBOM files found!")
        print("💡 This could be due to:")
        print("   - File naming pattern mismatch")
        print("   - Different repository structure")
        print("   - Files not uploaded to expected location")
    
    # Test downloading one file if available
    if sbom_files:
        print("📥 Testing download of first SBOM file...")
        try:
            sbom_content = nexus_client.download_sbom(sbom_files[0]['path'])
            print("✅ Download successful!")
            print(f"📊 SBOM format: {sbom_content.get('bomFormat', 'unknown')}")
            print(f"📊 Spec version: {sbom_content.get('specVersion', 'unknown')}")
            print(f"📊 Components: {len(sbom_content.get('components', []))}")
            print(f"📊 Vulnerabilities: {len(sbom_content.get('vulnerabilities', []))}")
        except Exception as e:
            print(f"❌ Download failed: {str(e)}")

if __name__ == "__main__":
    main()