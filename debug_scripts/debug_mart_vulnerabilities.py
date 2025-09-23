#!/usr/bin/env python3
"""
Debug script to analyze Mart project vulnerability counts
"""

import json
import logging
from services.nexus_client import NexusClient
from services.cyclonedx_parser import CycloneDXParser
from services.analytics import SecurityAnalytics
from config import Config

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    # Initialize services with config
    nexus_client = NexusClient(
        nexus_url=Config.NEXUS_URL,
        username=Config.NEXUS_USERNAME,
        password=Config.NEXUS_PASSWORD,
        repository=Config.NEXUS_REPOSITORY
    )
    parser = CycloneDXParser()
    analytics = SecurityAnalytics()
    
    print("🔍 Analyzing Mart_Trivy_Scan vulnerability counts...")
    print("=" * 60)
    
    # Get SBOM files
    sbom_files = nexus_client.list_sbom_files()
    
    # Find Mart project files
    mart_files = [f for f in sbom_files if 'Mart' in f['project']]
    
    print(f"📁 Found {len(mart_files)} SBOM files for Mart project:")
    for i, file in enumerate(mart_files, 1):
        print(f"   {i}. {file['project']} - {file['build_number']} - {file['timestamp']}")
    
    print("\n" + "=" * 60)
    
    # Analyze each file
    total_critical = 0
    total_high = 0
    total_medium = 0
    total_low = 0
    
    all_vuln_ids = set()
    
    for i, file in enumerate(mart_files, 1):
        print(f"\n📋 Analysis of file {i}: {file['project']} - {file['build_number']}")
        print("-" * 40)
        
        # Download and parse SBOM
        sbom_content = nexus_client.download_sbom(file['path'])
        parsed_data = parser.parse_cyclonedx(sbom_content)
        
        # Count vulnerabilities
        vuln_counts = analytics.count_vulnerabilities_by_severity(parsed_data['vulnerabilities'])
        
        print(f"   Critical: {vuln_counts['critical']}")
        print(f"   High:     {vuln_counts['high']}")
        print(f"   Medium:   {vuln_counts['medium']}")
        print(f"   Low:      {vuln_counts['low']}")
        print(f"   Total:    {vuln_counts['total']}")
        
        # Add to totals (this is what the dashboard is doing wrong!)
        total_critical += vuln_counts['critical']
        total_high += vuln_counts['high']
        total_medium += vuln_counts['medium']
        total_low += vuln_counts['low']
        
        # Track unique vulnerability IDs
        file_vuln_ids = set(v['id'] for v in parsed_data['vulnerabilities'])
        all_vuln_ids.update(file_vuln_ids)
        
        print(f"   Unique vuln IDs in this file: {len(file_vuln_ids)}")
        
        # Show sample vulnerabilities by severity
        vulns_by_severity = analytics.group_vulnerabilities_by_severity(parsed_data['vulnerabilities'])
        
        for severity in ['critical', 'high', 'medium', 'low']:
            if vulns_by_severity[severity]:
                print(f"   Sample {severity.upper()} vulnerabilities:")
                for vuln in vulns_by_severity[severity][:3]:  # Show first 3
                    print(f"     - {vuln['id']}: {vuln.get('description', 'No description')[:100]}...")
    
    print("\n" + "=" * 60)
    print("🧮 DASHBOARD CALCULATION (INCORRECT - Accumulating across scans):")
    print(f"   Critical: {total_critical}")
    print(f"   High:     {total_high}")
    print(f"   Medium:   {total_medium}")
    print(f"   Low:      {total_low}")
    print(f"   Total:    {total_critical + total_high + total_medium + total_low}")
    
    print("\n📊 CORRECT CALCULATION (Latest scan only):")
    if mart_files:
        # Get the latest file
        latest_file = max(mart_files, key=lambda x: x['timestamp'])
        print(f"   Using latest scan: {latest_file['project']} - {latest_file['build_number']}")
        
        sbom_content = nexus_client.download_sbom(latest_file['path'])
        parsed_data = parser.parse_cyclonedx(sbom_content)
        vuln_counts = analytics.count_vulnerabilities_by_severity(parsed_data['vulnerabilities'])
        
        print(f"   Critical: {vuln_counts['critical']}")
        print(f"   High:     {vuln_counts['high']}")
        print(f"   Medium:   {vuln_counts['medium']}")
        print(f"   Low:      {vuln_counts['low']}")
        print(f"   Total:    {vuln_counts['total']}")
    
    print(f"\n🆔 Total unique vulnerability IDs across all scans: {len(all_vuln_ids)}")
    
    print("\n" + "=" * 60)
    print("🔍 VULNERABILITY DETAILS ANALYSIS:")
    
    if mart_files:
        latest_file = max(mart_files, key=lambda x: x['timestamp'])
        sbom_content = nexus_client.download_sbom(latest_file['path'])
        parsed_data = parser.parse_cyclonedx(sbom_content)
        
        # Group by severity and show details
        vulns_by_severity = analytics.group_vulnerabilities_by_severity(parsed_data['vulnerabilities'])
        
        for severity in ['critical', 'high', 'medium', 'low']:
            if vulns_by_severity[severity]:
                print(f"\n{severity.upper()} VULNERABILITIES ({len(vulns_by_severity[severity])}):")
                for vuln in vulns_by_severity[severity]:
                    score = vuln.get('score', 'N/A')
                    print(f"  - {vuln['id']} (Score: {score})")
                    if vuln.get('description'):
                        print(f"    {vuln['description'][:100]}...")

if __name__ == "__main__":
    main()