#!/usr/bin/env python3
"""
Import/Upload Trivy report data to Nexus Repository
This script reads exported JFrog data and uploads it to a Nexus repository
for testing and integration purposes, with Maven-style hash files.
"""

import os
import json
import logging
import hashlib
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
NEXUS_REPOSITORY = os.environ.get('NEXUS_REPOSITORY', 'mccamish_sbom')

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

def create_nexus_repository():
    """Create a new raw repository in Nexus if it doesn't exist"""
    try:
        logger.info(f"🔧 Checking Nexus repository: {NEXUS_REPOSITORY}")
        
        # Check if repository exists (no auth required)
        check_url = f"{NEXUS_URL}/service/rest/v1/repositories/{NEXUS_REPOSITORY}"
        response = requests.get(check_url, timeout=30)
        
        if response.status_code == 200:
            logger.info(f"✅ Repository exists: {NEXUS_REPOSITORY}")
            return True
        
        # Try to create if we have credentials
        if not all([NEXUS_URL, NEXUS_USERNAME, NEXUS_PASSWORD]):
            logger.info(f"ℹ️  Repository {NEXUS_REPOSITORY} not found but no credentials to create")
            logger.info(f"ℹ️  Continuing with uploads (may fail if no permissions)")
            return True
        
        # Create new raw repository
        logger.info(f"📦 Creating new repository: {NEXUS_REPOSITORY}")
        
        create_url = f"{NEXUS_URL}/service/rest/v1/repositories/raw"
        
        repo_config = {
            "name": NEXUS_REPOSITORY,
            "online": True,
            "storage": {
                "blobStoreName": "default",
                "strictContentTypeValidation": False
            }
        }
        
        session = requests.Session()
        session.auth = HTTPBasicAuth(NEXUS_USERNAME, NEXUS_PASSWORD)
        
        response = session.post(
            create_url,
            json=repo_config,
            headers={'Content-Type': 'application/json'},
            timeout=30
        )
        
        if response.status_code in [201, 200]:
            logger.info(f"✅ Repository created successfully")
            return True
        elif response.status_code == 401:
            logger.info(f"⚠️  Authentication failed but continuing with uploads")
            return True
        else:
            logger.warning(f"⚠️  Failed to create repository: {response.status_code}")
            logger.info(f"ℹ️  Continuing with uploads anyway")
            return True
            
    except Exception as e:
        logger.warning(f"⚠️  Error checking repository: {str(e)}")
        logger.info(f"ℹ️  Continuing with uploads anyway")
        return True

def calculate_sha1(file_path):
    """Calculate SHA1 hash of a file"""
    sha1_hash = hashlib.sha1()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha1_hash.update(chunk)
    return sha1_hash.hexdigest()

def upload_file(local_path, nexus_path):
    """Upload a single file to Nexus"""
    try:
        upload_url = f"{NEXUS_URL}/repository/{NEXUS_REPOSITORY}/{nexus_path.lstrip('/')}"
        
        with open(local_path, 'rb') as f:
            file_content = f.read()
        
        # Try with authentication first if available
        if NEXUS_USERNAME and NEXUS_PASSWORD:
            session = requests.Session()
            session.auth = HTTPBasicAuth(NEXUS_USERNAME, NEXUS_PASSWORD)
            response = session.put(upload_url, data=file_content, timeout=60)
        else:
            # Try without authentication
            response = requests.put(upload_url, data=file_content, timeout=60)
        
        if response.status_code in [201, 204]:
            return True
        else:
            logger.warning(f"⚠️ Upload failed {nexus_path}: {response.status_code}")
            return False
    except Exception as e:
        logger.warning(f"⚠️ Error uploading {nexus_path}: {str(e)}")
        return False

def upload_file_with_hash(local_path, nexus_path):
    """Upload a file and its SHA1 hash to Nexus (Maven-style)"""
    # Upload main file
    if not upload_file(local_path, nexus_path):
        return False
    
    # Calculate and upload SHA1 hash
    try:
        sha1_hash = calculate_sha1(local_path)
        sha1_path = f"{nexus_path}.sha1"
        
        if NEXUS_USERNAME and NEXUS_PASSWORD:
            session = requests.Session()
            session.auth = HTTPBasicAuth(NEXUS_USERNAME, NEXUS_PASSWORD)
            upload_url = f"{NEXUS_URL}/repository/{NEXUS_REPOSITORY}/{sha1_path.lstrip('/')}"
            response = session.put(upload_url, data=sha1_hash.encode(), timeout=60)
        else:
            upload_url = f"{NEXUS_URL}/repository/{NEXUS_REPOSITORY}/{sha1_path.lstrip('/')}"
            response = requests.put(upload_url, data=sha1_hash.encode(), timeout=60)
        
        if response.status_code in [201, 204]:
            logger.debug(f"✅ Uploaded SHA1: {sha1_path}")
            return True
        else:
            logger.warning(f"⚠️ Failed to upload SHA1 {sha1_path}: {response.status_code}")
            return False
    except Exception as e:
        logger.warning(f"⚠️ Error uploading SHA1 for {nexus_path}: {str(e)}")
        return False

def upload_file_old(local_path, nexus_path):
    """Upload a single file to Nexus"""
    try:
        upload_url = f"{NEXUS_URL}/repository/{NEXUS_REPOSITORY}/{nexus_path.lstrip('/')}"
        
        with open(local_path, 'rb') as f:
            file_content = f.read()
        
        # Try with authentication first if available
        if NEXUS_USERNAME and NEXUS_PASSWORD:
            session = requests.Session()
            session.auth = HTTPBasicAuth(NEXUS_USERNAME, NEXUS_PASSWORD)
            response = session.put(upload_url, data=file_content, timeout=60)
        else:
            # Try without authentication
            response = requests.put(upload_url, data=file_content, timeout=60)
        
        if response.status_code in [201, 204]:
            return True
        else:
            logger.warning(f"⚠️ Upload failed {nexus_path}: {response.status_code}")
            return False
    except Exception as e:
        logger.warning(f"⚠️ Error uploading {nexus_path}: {str(e)}")
        return False

def import_trivy_files():
    """Import Trivy files to Nexus - scans filesystem and uploads with SHA1 hashes"""
    
    # Create repository
    if not create_nexus_repository():
        logger.error("❌ Failed to create/verify Nexus repository")
        return
    
    # Scan filesystem for all JSON files under jfrog_export/files
    files_base = os.path.normpath(FILES_DIR)
    if not os.path.exists(files_base):
        logger.error(f"❌ Files directory not found: {files_base}")
        return
    
    # Collect all JSON files with their paths
    json_files = []
    
    logger.info(f"🔍 Scanning for JSON files in: {files_base}")
    
    for root, dirs, files in os.walk(files_base):
        for file in files:
            # Skip hash files and non-JSON
            if file.endswith(('.sha1', '.sha256', '.sha512', '.md5')):
                continue
            if not file.endswith('.json'):
                continue
            
            local_path = os.path.join(root, file)
            
            # Calculate relative path from files_base for Nexus path
            # e.g., erwinDM/Mart/com/erwindm/... -> com/erwindm/...
            rel_path = os.path.relpath(local_path, files_base)
            
            # Skip the erwinDM/Mart prefix to get Maven structure
            # Convert to forward slashes for URL
            path_parts = rel_path.split(os.sep)
            
            # Find where 'com' starts in the path (Maven structure begins there)
            try:
                com_index = path_parts.index('com')
                nexus_path = '/'.join(path_parts[com_index:])
            except ValueError:
                # If no 'com' folder, use full relative path
                nexus_path = rel_path.replace(os.sep, '/')
            
            json_files.append({
                'local_path': local_path,
                'nexus_path': nexus_path,
                'filename': file
            })
    
    logger.info(f"📦 Found {len(json_files)} JSON files to upload")
    
    # Upload files
    uploaded_count = 0
    failed_count = 0
    
    for i, file_info in enumerate(json_files, 1):
        try:
            local_path = file_info['local_path']
            nexus_path = file_info['nexus_path']
            filename = file_info['filename']
            
            file_size = os.path.getsize(local_path)
            logger.info(f"[{i}/{len(json_files)}] 📤 Uploading: {nexus_path} ({file_size} bytes)")
            
            # Upload file with SHA1 hash
            if upload_file_with_hash(local_path, nexus_path):
                uploaded_count += 1
                logger.debug(f"✅ Successfully uploaded: {filename}")
            else:
                failed_count += 1
                
        except Exception as e:
            logger.error(f"❌ Error processing file {i}: {str(e)}")
            failed_count += 1
            continue
    
    logger.info(f"\n✅ Import complete!")
    logger.info(f"   Uploaded: {uploaded_count} files (with SHA1 hashes)")
    logger.info(f"   Failed: {failed_count} files")
    logger.info(f"   Total: {uploaded_count + failed_count} files")
    logger.info(f"   Total artifacts (files + hashes): {(uploaded_count * 2) + (failed_count)} items")
if __name__ == '__main__':
    import_trivy_files()
