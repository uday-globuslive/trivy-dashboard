"""
Nexus Repository Client for fetching CycloneDX SBOM files
"""

import requests
import logging
from urllib.parse import urljoin, quote
from datetime import datetime
import base64
import json
import re

logger = logging.getLogger(__name__)

class NexusClient:
    """Client for interacting with Nexus Repository Manager"""
    
    def __init__(self, nexus_url, username, password, repository):
        self.nexus_url = nexus_url.rstrip('/')
        self.username = username
        self.password = password
        self.repository = repository
        self.session = requests.Session()
        
        # Set up authentication
        auth_string = f"{username}:{password}"
        auth_bytes = auth_string.encode('ascii')
        auth_header = base64.b64encode(auth_bytes).decode('ascii')
        self.session.headers.update({
            'Authorization': f'Basic {auth_header}',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        
        logger.info(f"🔗 Initialized Nexus client for {nexus_url} (repository: {repository})")
    
    def test_connection(self):
        """Test connection to Nexus Repository"""
        try:
            response = self.session.get(f"{self.nexus_url}/service/rest/v1/status")
            response.raise_for_status()
            logger.info("✅ Nexus connection test successful")
            return True
        except Exception as e:
            logger.error(f"❌ Nexus connection test failed: {str(e)}")
            return False
    
    def list_sbom_files(self, limit=1000):
        """
        List all SBOM files (CycloneDX JSON) in the Nexus repository.
        
        Handles McCamish Nexus structure:
        - Repository: mccamish_sbom
        - Path: com/mccamish/{project}.sbom/{version}/{project}.sbom-{version}.json
        - Example: com/mccamish/AGP_Stellar_SSO.sbom/1.0.0-20250521034211/AGP_Stellar_SSO.sbom-1.0.0-20250521034211.json
        """
        from config import Config
        
        logger.info(f"📋 Listing SBOM files from repository: {self.repository}")
        logger.info(f"🔍 Searching for: groupId={Config.NEXUS_GROUP_ID}, suffix={Config.NEXUS_ARTIFACT_SUFFIX}, extension={Config.NEXUS_ASSET_EXTENSION}")
        logger.info(f"🌐 Nexus URL: {self.nexus_url}")
        
        sbom_files = []
        try:
            # Use assets search API for better filtering
            search_url = f"{self.nexus_url}/service/rest/v1/search/assets"
            params = {
                'repository': self.repository,
                'group': Config.NEXUS_GROUP_ID,
                'extension': Config.NEXUS_ASSET_EXTENSION
            }
            
            logger.info(f"🔍 Search URL: {search_url}")
            logger.info(f"📋 Search params: {params}")
            
            continuation_token = None
            processed_count = 0
            
            while processed_count < limit:
                if continuation_token:
                    params['continuationToken'] = continuation_token
                    
                response = self.session.get(search_url, params=params, timeout=30)
                response.raise_for_status()
                
                search_results = response.json()
                items = search_results.get('items', [])
                
                logger.info(f"📦 Found {len(items)} assets in this batch")
                
                if not items:
                    break
                
                for asset in items:
                    try:
                        # Parse asset path: com/mccamish/AGP_Stellar_SSO.sbom/1.0.0-20250521034211/AGP_Stellar_SSO.sbom-1.0.0-20250521034211.json
                        asset_path = asset.get('path', '')
                        download_url = asset.get('downloadUrl', '')
                        
                        logger.debug(f"🔍 Processing asset: {asset_path}")
                        
                        # Skip checksum files
                        if asset_path.endswith(('.json.sha1', '.json.sha256', '.json.sha512', '.json.md5')):
                            logger.debug(f"⏭️ Skipping checksum file: {asset_path}")
                            continue
                            
                        # Only process JSON files
                        if not asset_path.endswith('.json'):
                            logger.debug(f"⏭️ Skipping non-JSON file: {asset_path}")
                            continue
                        
                        # Parse Maven path structure: com/mccamish/{artifactId}/{version}/{filename}
                        path_parts = asset_path.split('/')
                        if len(path_parts) < 4:
                            logger.debug(f"⏭️ Skipping asset with insufficient path parts: {asset_path}")
                            continue
                            
                        # Extract components from path
                        group_parts = path_parts[:-3]  # ['com', 'mccamish']
                        artifact_id = path_parts[-3]   # e.g., 'AGP_Stellar_SSO.sbom'
                        version = path_parts[-2]       # e.g., '1.0.0-20250521034211'
                        filename = path_parts[-1]      # e.g., 'AGP_Stellar_SSO.sbom-1.0.0-20250521034211.json'
                        
                        logger.debug(f"📦 Parsed: artifact={artifact_id}, version={version}, filename={filename}")
                        
                        # Extract project name by removing suffix
                        project_name = artifact_id.replace(Config.NEXUS_ARTIFACT_SUFFIX, '') if Config.NEXUS_ARTIFACT_SUFFIX else artifact_id
                        
                        # Extract build number from version (timestamp part)
                        build_number = self._extract_build_number(version)
                        
                        # Get timestamp from Nexus metadata
                        timestamp = self._parse_timestamp(asset.get('lastModified', ''))
                        
                        # Construct proper download URL - use downloadUrl from API if available
                        final_download_url = download_url if download_url else f"{self.nexus_url}/repository/{self.repository}/{asset_path}"
                        
                        sbom_file = {
                            'path': final_download_url,
                            'project': project_name,
                            'build_number': build_number,
                            'timestamp': timestamp,
                            'size': asset.get('fileSize', 0),
                            'group_id': '/'.join(group_parts),  # 'com/mccamish'
                            'artifact_id': artifact_id,
                            'version': version,
                            'filename': filename,
                            'asset_path': asset_path
                        }
                        
                        logger.debug(f"✅ Added SBOM file: {project_name} - {version}")
                        sbom_files.append(sbom_file)
                        processed_count += 1
                        
                        if processed_count >= limit:
                            break
                            
                    except Exception as e:
                        logger.warning(f"⚠️ Error parsing asset {asset.get('path', 'unknown')}: {str(e)}")
                        continue
                
                # Check for continuation token
                continuation_token = search_results.get('continuationToken')
                if not continuation_token:
                    break
            
            logger.info(f"📦 Found {len(sbom_files)} SBOM files")
            
            # Log a few examples for debugging
            if sbom_files:
                logger.info("📋 Sample SBOM files found:")
                for i, sbom in enumerate(sbom_files[:3]):
                    logger.info(f"  {i+1}. {sbom['project']} - {sbom['version']} - {sbom['path']}")
            
            return sbom_files
            
        except Exception as e:
            logger.error(f"❌ Error listing SBOM files: {str(e)}")
            return []
    
    def download_sbom(self, sbom_path):
        """
        Download SBOM content from Nexus
        
        Args:
            sbom_path: Path or URL to the SBOM file
            
        Returns:
            dict: Parsed JSON content of the SBOM file
        """
        try:
            logger.debug(f"⬇️ Downloading SBOM: {sbom_path}")
            
            # Handle both full URLs and relative paths
            if sbom_path.startswith('http'):
                download_url = sbom_path
            else:
                # Construct proper repository URL for McCamish Nexus
                download_url = f"{self.nexus_url}/repository/{self.repository}/{sbom_path}"
            
            logger.debug(f"🌐 Download URL: {download_url}")
            
            response = self.session.get(download_url, timeout=30)
            response.raise_for_status()
            
            # Parse JSON content
            sbom_content = response.json()
            logger.debug(f"✅ Successfully downloaded SBOM ({len(response.content)} bytes)")
            
            # Log basic SBOM info for debugging
            if isinstance(sbom_content, dict):
                logger.debug(f"📋 SBOM type: {sbom_content.get('bomFormat', 'unknown')}")
                logger.debug(f"📋 SBOM version: {sbom_content.get('specVersion', 'unknown')}")
                if 'metadata' in sbom_content:
                    metadata = sbom_content['metadata']
                    if 'component' in metadata:
                        comp = metadata['component']
                        logger.debug(f"📋 Component: {comp.get('name', 'unknown')} v{comp.get('version', 'unknown')}")
            
            return sbom_content
            
        except requests.exceptions.HTTPError as e:
            logger.error(f"❌ HTTP Error downloading SBOM {sbom_path}: {e.response.status_code} - {e.response.text}")
            raise
        except Exception as e:
            logger.error(f"❌ Error downloading SBOM {sbom_path}: {str(e)}")
            raise
    
    def get_repository_info(self):
        """Get information about the SBOM repository"""
        try:
            repo_url = f"{self.nexus_url}/service/rest/v1/repositories/{self.repository}"
            response = self.session.get(repo_url)
            response.raise_for_status()
            
            repo_info = response.json()
            logger.info(f"📊 Repository info: {repo_info.get('name', 'Unknown')}")
            
            return repo_info
            
        except Exception as e:
            logger.error(f"❌ Error getting repository info: {str(e)}")
            return {}
    
    def search_sbom_by_project(self, project_name):
        """Search for SBOM files by project name"""
        logger.info(f"🔍 Searching SBOM files for project: {project_name}")
        
        try:
            search_url = f"{self.nexus_url}/service/rest/v1/search"
            params = {
                'repository': self.repository,
                'name': project_name,
                'format': 'maven2'
            }
            
            response = self.session.get(search_url, params=params)
            response.raise_for_status()
            
            results = response.json()
            sbom_files = []
            
            for item in results.get('items', []):
                if item.get('name') == project_name:
                    sbom_files.append({
                        'project': project_name,
                        'version': item.get('version', ''),
                        'build_number': self._extract_build_number(item.get('version', '')),
                        'download_url': item.get('assets', [{}])[0].get('downloadUrl', ''),
                        'timestamp': self._parse_timestamp(item.get('lastModified', ''))
                    })
            
            logger.info(f"📦 Found {len(sbom_files)} SBOM files for project {project_name}")
            return sbom_files
            
        except Exception as e:
            logger.error(f"❌ Error searching SBOM files for project {project_name}: {str(e)}")
            return []
    
    def _extract_build_number(self, version_string):
        """Extract build number from version string (handles patterns like 1.0.0-20250521034211)"""
        from config import Config
        
        try:
            # First try to extract based on version prefix
            if Config.NEXUS_VERSION_PREFIX and version_string.startswith(Config.NEXUS_VERSION_PREFIX):
                suffix = version_string[len(Config.NEXUS_VERSION_PREFIX):]
                if suffix.isdigit():
                    return int(suffix)
            
            # Fallback patterns for build numbers
            patterns = [
                r'-(\d{8,})',       # timestamp pattern like -20250521034211
                r'build[_-](\d+)',  # build_123, build-123
                r'-(\d+)$',         # version-123
                r'\.(\d+)$',        # version.123
                r'(\d+)$'           # version ending with number
            ]
            
            for pattern in patterns:
                match = re.search(pattern, version_string, re.IGNORECASE)
                if match:
                    return int(match.group(1))
            
            # If no pattern matches, return 1 as default
            return 1
            
        except Exception:
            return 1
    
    def _parse_timestamp(self, timestamp_string):
        """Parse timestamp from Nexus API response"""
        try:
            if timestamp_string:
                # Handle different timestamp formats
                formats = [
                    '%Y-%m-%dT%H:%M:%S.%fZ',  # ISO format with microseconds
                    '%Y-%m-%dT%H:%M:%SZ',     # ISO format without microseconds
                    '%Y-%m-%d %H:%M:%S'       # Simple format
                ]
                
                for fmt in formats:
                    try:
                        return datetime.strptime(timestamp_string, fmt)
                    except ValueError:
                        continue
                        
            # If parsing fails, return current time
            return datetime.now()
            
        except Exception:
            return datetime.now()
    
    def get_storage_stats(self):
        """Get storage statistics for the SBOM repository"""
        try:
            # Get repository storage stats if available
            stats_url = f"{self.nexus_url}/service/rest/v1/repositories/{self.repository}/status"
            
            try:
                response = self.session.get(stats_url)
                if response.status_code == 200:
                    return response.json()
            except:
                pass
            
            # Fallback: calculate from search results
            sbom_files = self.list_sbom_files()
            total_size = sum(f.get('size', 0) for f in sbom_files)
            
            return {
                'total_files': len(sbom_files),
                'total_size_bytes': total_size,
                'total_size_mb': total_size / (1024 * 1024),
                'repository': self.repository
            }
            
        except Exception as e:
            logger.error(f"❌ Error getting storage stats: {str(e)}")
            return {
                'total_files': 0,
                'total_size_bytes': 0,
                'total_size_mb': 0,
                'repository': self.repository
            }
