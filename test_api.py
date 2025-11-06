#!/usr/bin/env python3

"""
Test script for SBOM analysis API endpoint
"""

import requests
import json
import time

def test_sbom_analysis_api():
    """Test the /api/sbom-analysis endpoint"""
    
    url = "http://localhost:5000/api/sbom-analysis"
    
    print("🧪 Testing SBOM Analysis API...")
    print(f"📍 URL: {url}")
    
    try:
        # Give server a moment to stabilize
        time.sleep(2)
        
        print("📡 Making API request...")
        response = requests.get(url, timeout=10)
        
        print(f"📊 Status Code: {response.status_code}")
        print(f"📊 Content Type: {response.headers.get('content-type', 'unknown')}")
        
        if response.status_code == 200:
            data = response.json()
            print("✅ API Response received successfully!")
            print(f"📊 Total Projects: {data.get('total_projects', 'N/A')}")
            print(f"📊 Projects with Vulnerabilities: {data.get('projects_with_vulnerabilities', 'N/A')}")
            print(f"📊 Component-only Projects: {data.get('projects_component_only', 'N/A')}")
            print(f"📊 Project Details Count: {len(data.get('projects_detail', []))}")
            print(f"📊 Recommendations Count: {len(data.get('recommendations', []))}")
            
            if data.get('projects_detail'):
                print("\n📋 Project Details:")
                for project in data['projects_detail']:
                    print(f"   - {project.get('name', 'Unknown')}: {project.get('sbom_type', 'Unknown')}")
            
            return True
            
        else:
            print(f"❌ API returned status {response.status_code}")
            print(f"❌ Response: {response.text}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("❌ Connection error - is the server running?")
        return False
    except requests.exceptions.Timeout:
        print("❌ Request timed out")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")
        return False

if __name__ == "__main__":
    success = test_sbom_analysis_api()
    exit(0 if success else 1)