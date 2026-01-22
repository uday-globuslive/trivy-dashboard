#!/usr/bin/env python3
"""
Export Trivy report data from JFrog Artifactory
This script downloads all Trivy report JSON files from JFrog and saves them locally
for later import into Nexus or other testing purposes.
"""

import os
import json
import logging
from pathlib import Path
from datetime import datetime
import requests
from requests.auth import HTTPBasicAuth

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration from environment
JFROG_URL = os.environ.get('JFROG_URL')
JFROG_USERNAME = os.environ.get('JFROG_USERNAME')
JFROG_PASSWORD = os.environ.get('JFROG_PASSWORD')
JFROG_REPOSITORY = os.environ.get('JFROG_REPOSITORY', 'sbom')

# Export configuration
EXPORT_DIR = os.environ.get('EXPORT_DIR', './jfrog_export')
EXPORT_MANIFEST = os.environ.get('EXPORT_MANIFEST', f'{EXPORT_DIR}/manifest.json')

def init_export_dir():
    """Initialize export directory"""
    Path(EXPORT_DIR).mkdir(parents=True, exist_ok=True)
    logger.info(f"📁 Export directory: {EXPORT_DIR}")

def search_trivy_files():
    """Search for all Trivy report files in JFrog"""
    if not all([JFROG_URL, JFROG_USERNAME, JFROG_PASSWORD]):
        logger.error("❌ Missing JFrog credentials in environment variables")
        return []
    
    logger.info(f"🔍 Searching for Trivy files in JFrog repository: {JFROG_REPOSITORY}")
    
    session = requests.Session()
    session.auth = HTTPBasicAuth(JFROG_USERNAME, JFROG_PASSWORD)
    
    try:
        # Use AQL to search for JSON files
        aql_query = {
            "repo": JFROG_REPOSITORY,
            "type": "file",
            "name": {"$match": "*.json"}
        }
        
        aql_string = f'items.find({json.dumps(aql_query)}).limit(10000)'
        search_url = f"{JFROG_URL}/artifactory/api/search/aql"
        
        response = session.post(
            search_url,
            data=aql_string,
            headers={'Content-Type': 'text/plain'},
            timeout=30
        )
        response.raise_for_status()
        
        search_results = response.json()
        items = search_results.get('results', [])
        logger.info(f"📦 Found {len(items)} JSON files in JFrog")
        
        return items
    except Exception as e:
        logger.error(f"❌ Error searching JFrog: {str(e)}")
        return []

def download_file(download_url, local_path):
    """Download a single file from JFrog"""
    session = requests.Session()
    session.auth = HTTPBasicAuth(JFROG_USERNAME, JFROG_PASSWORD)
    
    try:
        response = session.get(download_url, timeout=30)
        response.raise_for_status()
        
        # Create directories if needed
        Path(local_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Write with UTF-8 encoding to handle Unicode characters
        with open(local_path, 'w', encoding='utf-8') as f:
            f.write(response.text)
        
        return True
    except Exception as e:
        logger.warning(f"⚠️ Failed to download {download_url}: {str(e)}")
        return False

def export_trivy_files():
    """Export all Trivy files from JFrog"""
    init_export_dir()
    
    items = search_trivy_files()
    if not items:
        logger.error("❌ No files found to export")
        return
    
    manifest = {
        'export_date': datetime.now().isoformat(),
        'jfrog_url': JFROG_URL,
        'jfrog_repository': JFROG_REPOSITORY,
        'total_files': len(items),
        'files': []
    }
    
    downloaded_count = 0
    skipped_count = 0
    
    for i, item in enumerate(items, 1):
        try:
            asset_path = item.get('path', '')
            filename = item.get('name', '')
            
            # Skip non-JSON or checksum files
            if not filename.endswith('.json') or filename.endswith(('.sha1', '.sha256', '.sha512', '.md5')):
                skipped_count += 1
                continue
            
            # Construct download URL from repo and path (AQL doesn't provide downloadUrl)
            full_path = f"{asset_path.lstrip('/')}/{filename}".replace('//', '/')
            download_url = f"{JFROG_URL}/artifactory/{JFROG_REPOSITORY}/{full_path}"
            
            # Construct local path maintaining structure
            local_path = os.path.join(EXPORT_DIR, 'files', asset_path.lstrip('/'), filename)
            
            logger.info(f"[{i}/{len(items)}] 📥 Downloading: {asset_path}/{filename}")
            
            if download_file(download_url, local_path):
                manifest['files'].append({
                    'jfrog_path': full_path,
                    'local_path': local_path,
                    'filename': filename,
                    'size': item.get('size', 0),
                    'downloaded': True
                })
                downloaded_count += 1
            else:
                manifest['files'].append({
                    'jfrog_path': full_path,
                    'filename': filename,
                    'downloaded': False
                })
        except Exception as e:
            logger.error(f"❌ Error processing item {i}: {str(e)}")
            continue
    
    # Save manifest
    with open(EXPORT_MANIFEST, 'w') as f:
        json.dump(manifest, f, indent=2)
    
    logger.info(f"\n✅ Export complete!")
    logger.info(f"   Downloaded: {downloaded_count}")
    logger.info(f"   Skipped: {skipped_count}")
    logger.info(f"   Manifest saved: {EXPORT_MANIFEST}")
    logger.info(f"   Files location: {os.path.join(EXPORT_DIR, 'files')}")

if __name__ == '__main__':
    export_trivy_files()
