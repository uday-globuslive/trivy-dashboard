#!/usr/bin/env python3
"""
Investigate SBOM vulnerability data sources
"""

import json
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.nexus_client import NexusClient
from services.cyclonedx_parser import CycloneDXParser

def investigate_vulnerability_sources():
    """Investigate where vulnerability data is coming from"""
    
    print("🔍 Investigating SBOM vulnerability data sources...")
    print("=" * 60)
    
    # Get SBOM files
    nexus = NexusClient(
        nexus_url="http://10.11.53.12:8081",
        username="",  # Assuming no auth needed
        password="",
        repository="mccamish_sbom"
    )
    sbom_files = nexus.list_sbom_files()
    
    if not sbom_files:
        print("❌ No SBOM files found")
        return
    
    print(f"📄 Found {len(sbom_files)} SBOM files")
    
    # Examine each SBOM file
    for i, file_info in enumerate(sbom_files[:3]):  # Check first 3 files
        filename = file_info['filename']
        print(f"\n📁 File {i+1}: {filename}")
        print("-" * 40)
        
        # Download content
        sbom_content = nexus.download_sbom(file_info['path'])
        
        if not sbom_content:
            print("❌ Could not download SBOM content")
            continue
        
        # Analyze structure
        print("📊 SBOM Structure:")
        print(f"   - bomFormat: {sbom_content.get('bomFormat', 'Not found')}")
        print(f"   - specVersion: {sbom_content.get('specVersion', 'Not found')}")
        print(f"   - components: {len(sbom_content.get('components', []))}")
        print(f"   - vulnerabilities: {len(sbom_content.get('vulnerabilities', []))}")
        print(f"   - dependencies: {len(sbom_content.get('dependencies', []))}")
        
        # List all top-level keys
        print(f"\n🔑 All top-level keys:")
        for key in sorted(sbom_content.keys()):
            value = sbom_content[key]
            if isinstance(value, list):
                print(f"   - {key}: [{len(value)} items]")
            elif isinstance(value, dict):
                print(f"   - {key}: {{dict with {len(value)} keys}}")
            else:
                print(f"   - {key}: {type(value).__name__}")
        
        # Check for vulnerabilities
        if 'vulnerabilities' in sbom_content:
            vulns = sbom_content['vulnerabilities']
            print(f"\n🚨 Vulnerabilities section: {len(vulns)} entries")
            
            if vulns:
                print("   Sample vulnerability structure:")
                first_vuln = vulns[0]
                for key in sorted(first_vuln.keys()):
                    print(f"     - {key}: {type(first_vuln[key]).__name__}")
        else:
            print("\n❌ No 'vulnerabilities' section found")
        
        # Check components for vulnerability data
        components = sbom_content.get('components', [])
        if components:
            print(f"\n📦 Component analysis (first component):")
            first_comp = components[0]
            comp_keys = sorted(first_comp.keys())
            print(f"   Keys: {', '.join(comp_keys)}")
            
            # Look for vulnerability-related fields
            vuln_related = ['vulnerabilities', 'security', 'cve', 'advisories', 'risks']
            found_vuln_fields = [k for k in comp_keys if any(v in k.lower() for v in vuln_related)]
            if found_vuln_fields:
                print(f"   Vulnerability-related fields: {found_vuln_fields}")
            else:
                print("   No vulnerability-related fields found in components")
        
        # Show metadata for context
        metadata = sbom_content.get('metadata', {})
        if metadata:
            print(f"\n📋 Metadata:")
            component = metadata.get('component', {})
            print(f"   - Project: {component.get('name', 'Unknown')}")
            print(f"   - Version: {component.get('version', 'Unknown')}")
            print(f"   - Timestamp: {metadata.get('timestamp', 'Unknown')}")
    
    print("\n" + "=" * 60)
    print("🤔 Analysis Summary:")
    print("1. Checking if SBOM files contain vulnerability sections")
    print("2. Looking for alternative vulnerability data sources")
    print("3. Understanding how dashboard shows vulnerability counts")

if __name__ == "__main__":
    investigate_vulnerability_sources()