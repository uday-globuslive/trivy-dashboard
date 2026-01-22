#!/usr/bin/env python3
"""
Generate SHA1 checksums for all JSON files and upload them to Nexus
"""

import os
import json
import hashlib
import logging
from pathlib import Path
import requests
from requests.auth import HTTPBasicAuth

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Nexus configuration from environment
NEXUS_URL = os.environ.get('NEXUS_URL')
NEXUS_USERNAME = os.environ.get('NEXUS_USERNAME')
NEXUS_PASSWORD = os.environ.get('NEXUS_PASSWORD')
NEXUS_REPOSITORY = os.environ.get('NEXUS_REPOSITORY', 'erwindm_sbom')

# Import configuration
IMPORT_DIR = os.environ.get('IMPORT_DIR', './jfrog_export')
IMPORT_MANIFEST = os.environ.get('IMPORT_MANIFEST', f'{IMPORT_DIR}/manifest.json')
FILES_DIR = os.path.join(IMPORT_DIR, 'files')

def load_manifest():
    """Load manifest file"""
    if not os.path.exists(IMPORT_MANIFEST):
        logger.error(f"❌ Manifest not found: {IMPORT_MANIFEST}")
        return None
    
    try:
        with open(IMPORT_MANIFEST, 'r') as f:
            manifest = json.load(f)
        logger.info(f"📋 Manifest loaded: {manifest['total_files']} files")
        return manifest
    except Exception as e:
        logger.error(f"❌ Error loading manifest: {str(e)}")
        return None

def generate_sha1(file_path):
    """Generate SHA1 checksum for a file"""
    sha1 = hashlib.sha1()
    try:
        with open(file_path, 'rb') as f:
            sha1.update(f.read())
        return sha1.hexdigest()
    except Exception as e:
        logger.error(f"❌ Error generating checksum for {file_path}: {str(e)}")
        return None

def upload_checksum(sha1_content, nexus_path):
    """Upload checksum file to Nexus"""
    try:
        checksum_path = f"{nexus_path}.sha1"
        upload_url = f"{NEXUS_URL}/repository/{NEXUS_REPOSITORY}/{checksum_path.lstrip('/')}"
        
        if NEXUS_USERNAME and NEXUS_PASSWORD:
            session = requests.Session()
            session.auth = HTTPBasicAuth(NEXUS_USERNAME, NEXUS_PASSWORD)
            response = session.put(upload_url, data=sha1_content.encode(), timeout=60)
        else:
            response = requests.put(upload_url, data=sha1_content.encode(), timeout=60)
        
        if response.status_code in [201, 204]:
            return True
        else:
            logger.warning(f"⚠️ Upload failed {checksum_path}: {response.status_code}")
            return False
    except Exception as e:
        logger.warning(f"⚠️ Error uploading checksum {checksum_path}: {str(e)}")
        return False

def generate_and_upload_checksums():
    """Generate and upload SHA1 checksums for all files"""
    manifest = load_manifest()
    if not manifest:
        return
    
    uploaded_count = 0
    failed_count = 0
    
    for i, file_info in enumerate(manifest.get('files', []), 1):
        try:
            if not file_info.get('downloaded'):
                continue
            
            filename = file_info['filename']
            jfrog_path = file_info['jfrog_path']
            
            # Find local file
            local_path = None
            files_base = os.path.normpath(FILES_DIR)
            for root, dirs, files in os.walk(files_base):
                if filename in files:
                    local_path = os.path.join(root, filename)
                    break
            
            if not local_path or not os.path.exists(local_path):
                logger.warning(f"⚠️ File not found locally: {filename}")
                failed_count += 1
                continue
            
            # Generate SHA1
            sha1 = generate_sha1(local_path)
            if not sha1:
                failed_count += 1
                continue
            
            logger.info(f"[{i}/{len(manifest['files'])}] 📤 Uploading checksum: {jfrog_path}.sha1")
            
            if upload_checksum(sha1, jfrog_path):
                uploaded_count += 1
            else:
                failed_count += 1
                
        except Exception as e:
            logger.error(f"❌ Error processing file {i}: {str(e)}")
            failed_count += 1
            continue
    
    logger.info(f"\n✅ Checksum upload complete!")
    logger.info(f"   Uploaded: {uploaded_count}")
    logger.info(f"   Failed: {failed_count}")
    logger.info(f"   Total: {uploaded_count + failed_count}")

if __name__ == '__main__':
    generate_and_upload_checksums()
