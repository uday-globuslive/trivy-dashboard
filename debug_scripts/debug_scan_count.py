#!/usr/bin/env python3

import requests
import json

def debug_scan_counts():
    """Debug why Test_Trivy_Scan shows only 1 scan instead of 2"""
    
    print("=== DEBUGGING SCAN COUNTS ===\n")
    
    # 1. Check what files Nexus finds
    print("1. Checking Nexus repository...")
    response = requests.get('http://localhost:5000/debug/nexus')
    if response.status_code == 200:
        data = response.json()
        print(f"Total SBOM files found: {data.get('total_files', 0)}")
        print()
        
        if 'sbom_files' in data:
            projects = {}
            for file in data['sbom_files']:
                project = file.get('project_name', 'Unknown')
                if project not in projects:
                    projects[project] = []
                projects[project].append(file)
            
            print("Files by project:")
            for project, files in projects.items():
                print(f"  {project}: {len(files)} files")
                for i, file in enumerate(files, 1):
                    print(f"    {i}. Version: {file.get('version', 'Unknown')}")
                    print(f"       Build: {file.get('build_number', 'Unknown')}")
                    print(f"       Timestamp: {file.get('timestamp', 'Unknown')}")
                    print(f"       URL: {file.get('download_url', 'Unknown')}")
                    print()
        print()
    else:
        print(f"Failed to get Nexus debug info: {response.status_code}")
        return
    
    # 2. Check dashboard's internal data
    print("2. Checking dashboard's internal project data...")
    response = requests.get('http://localhost:5000/api/projects')
    if response.status_code == 200:
        projects = response.json()
        for project in projects:
            if project['name'] == 'Test_Trivy_Scan':
                print(f"Test_Trivy_Scan dashboard data:")
                print(f"  Scans count: {len(project.get('scans', []))}")
                print(f"  Scan IDs: {project.get('scans', [])}")
                print(f"  Last scan: {project.get('last_scan', 'None')}")
                print(f"  Critical: {project.get('critical_count', 0)}")
                print(f"  High: {project.get('high_count', 0)}")
                print(f"  Medium: {project.get('medium_count', 0)}")
                print(f"  Low: {project.get('low_count', 0)}")
                print()
                break
        else:
            print("Test_Trivy_Scan not found in dashboard data")
    else:
        print(f"Failed to get projects API: {response.status_code}")
    
    # 3. Check individual scans data
    print("3. Checking all scans data...")
    response = requests.get('http://localhost:5000/api/scans')
    if response.status_code == 200:
        scans = response.json()
        test_scans = [scan for scan in scans if scan.get('project') == 'Test_Trivy_Scan']
        print(f"Test_Trivy_Scan scans in database: {len(test_scans)}")
        for i, scan in enumerate(test_scans, 1):
            print(f"  Scan {i}:")
            print(f"    ID: {scan.get('id', 'Unknown')}")
            print(f"    Version: {scan.get('version', 'Unknown')}")
            print(f"    Build: {scan.get('build_number', 'Unknown')}")
            print(f"    Timestamp: {scan.get('timestamp', 'Unknown')}")
            print(f"    Vulnerabilities: {len(scan.get('vulnerabilities', []))}")
            print()
    else:
        print(f"Failed to get scans API: {response.status_code}")

if __name__ == "__main__":
    debug_scan_counts()