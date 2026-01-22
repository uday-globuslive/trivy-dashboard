"""
Nexus Repository Client for fetching Trivy report files
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
    
    def list_trivy_files(self, limit=1000):
        """
        List all Trivy report files in the Nexus repository.
        
        Handles McCamish Nexus structure:
        - Repository: mccamish_sbom
        - Path: com/mccamish/{project}/{version}/{project}-{version}-trivy-report.json
        - Example: com/mccamish/Mart_Trivy_Scan/1.0.0-20250924044857/Mart_Trivy_Scan-1.0.0-20250924044857-trivy-report.json
        """
        from config import Config
        
        logger.info(f"📋 Listing Trivy report files from repository: {self.repository}")
        logger.info(f"🔍 Searching for: groupId={Config.NEXUS_GROUP_ID}, suffix={Config.NEXUS_ARTIFACT_SUFFIX}, extension={Config.NEXUS_ASSET_EXTENSION}")
        logger.info(f"🌐 Nexus URL: {self.nexus_url}")
        
        sbom_files = []
        try:
            # Use assets search API for better filtering
            search_url = f"{self.nexus_url}/service/rest/v1/search/assets"
            params = {
                'repository': self.repository,
                'group': Config.NEXUS_GROUP_ID
                # Removed extension filter to see all files first
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
                        # Parse asset path: com/mccamish/AGP_Stellar_SSO.sbom/1.0.0-20250521034211/AGP_Stellar_SSO.sbom-1.0.0-20250521034211-trivy-report.json
                        asset_path = asset.get('path', '')
                        download_url = asset.get('downloadUrl', '')
                        
                        logger.debug(f"🔍 Processing asset: {asset_path}")
                        
                        # Skip checksum files
                        if asset_path.endswith(('.json.sha1', '.json.sha256', '.json.sha512', '.json.md5')):
                            logger.debug(f"⏭️ Skipping checksum file: {asset_path}")
                            continue
                            
                        # Only process Trivy report JSON files (ending with -trivy-report.json)
                        if not asset_path.endswith('-trivy-report.json'):
                            logger.debug(f"⏭️ Skipping non-Trivy-report file: {asset_path}")
                            continue
                        
                        # Parse Maven path structure: com/mccamish/{artifactId}/{version}/{filename}
                        path_parts = asset_path.split('/')
                        if len(path_parts) < 4:
                            logger.debug(f"⏭️ Skipping asset with insufficient path parts: {asset_path}")
                            continue
                            
                        # Extract components from path
                        group_parts = path_parts[:-3]  # ['com', 'mccamish']
                        artifact_id = path_parts[-3]   # e.g., 'Mart_Trivy_Scan'
                        version = path_parts[-2]       # e.g., '1.0.0-20250924044857'
                        filename = path_parts[-1]      # e.g., 'Mart_Trivy_Scan-1.0.0-20250924044857-trivy-report.json'
                        
                        logger.debug(f"📦 Parsed: artifact={artifact_id}, version={version}, filename={filename}")
                        
                        # For Trivy reports, project name is the artifact_id directly
                        project_name = artifact_id
                        
                        # Extract build number from version (timestamp part)
                        build_number = self._extract_build_number(version)
                        
                        # Extract branch name from version (part after the timestamp)
                        branch_name = self._extract_branch_name(version)
                        logger.info(f"🌿 Extracted branch name: '{branch_name}' from version: {version}")
                        
                        # Get timestamp from Nexus metadata
                        timestamp = self._parse_timestamp(asset.get('lastModified', ''))
                        
                        # Construct proper download URL - use downloadUrl from API if available
                        final_download_url = download_url if download_url else f"{self.nexus_url}/repository/{self.repository}/{asset_path}"
                        
                        sbom_file = {
                            'path': final_download_url,
                            'project': project_name,
                            'build_number': build_number,
                            'branch_name': branch_name,
                            'timestamp': timestamp,
                            'size': asset.get('fileSize', 0),
                            'group_id': '/'.join(group_parts),  # 'com/mccamish'
                            'artifact_id': artifact_id,
                            'version': version,
                            'filename': filename,
                            'asset_path': asset_path
                        }
                        
                        logger.debug(f"✅ Added Trivy report file: {project_name} - {version}")
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
            
            logger.info(f"📦 Found {len(sbom_files)} Trivy report files")
            
            # Log a few examples for debugging
            if sbom_files:
                logger.info("📋 Sample Trivy report files found:")
                for i, sbom in enumerate(sbom_files[:3]):
                    logger.info(f"  {i+1}. {sbom['project']} - {sbom['version']} - {sbom['path']}")
            
            return sbom_files
            
        except Exception as e:
            logger.error(f"❌ Error listing Trivy report files: {str(e)}")
            return []
    
    def download_trivy_report(self, trivy_path):
        """
        Download Trivy report content from Nexus
        
        Args:
            trivy_path: Path or URL to the Trivy report file
            
        Returns:
            dict: Parsed JSON content of the Trivy report file
        """
        try:
            logger.debug(f"⬇️ Downloading Trivy report: {trivy_path}")
            
            # Handle both full URLs and relative paths
            if trivy_path.startswith('http'):
                download_url = trivy_path
            else:
                # Construct proper repository URL for McCamish Nexus
                download_url = f"{self.nexus_url}/repository/{self.repository}/{trivy_path}"
            
            logger.debug(f"🌐 Download URL: {download_url}")
            
            response = self.session.get(download_url, timeout=30)
            response.raise_for_status()
            
            # Parse JSON content
            trivy_content = response.json()
            logger.debug(f"✅ Successfully downloaded Trivy report ({len(response.content)} bytes)")
            
            # Log basic Trivy report info for debugging
            if isinstance(trivy_content, dict):
                logger.debug(f"📋 Trivy Schema Version: {trivy_content.get('SchemaVersion', 'unknown')}")
                logger.debug(f"📋 Artifact Name: {trivy_content.get('ArtifactName', 'unknown')}")
                logger.debug(f"📋 Artifact Type: {trivy_content.get('ArtifactType', 'unknown')}")
                results = trivy_content.get('Results', [])
                logger.debug(f"📋 Results: {len(results)} targets found")
            
            return trivy_content
            
        except requests.exceptions.HTTPError as e:
            logger.error(f"❌ HTTP Error downloading Trivy report {trivy_path}: {e.response.status_code} - {e.response.text}")
            raise
        except Exception as e:
            logger.error(f"❌ Error downloading Trivy report {trivy_path}: {str(e)}")
            raise
    
    def download_cyclonedx_sbom(self, trivy_path):
        """
        Download CycloneDX SBOM file from Nexus
        
        Assumes CycloneDX file is in same folder as Trivy report but without the "-trivy-report" suffix
        
        Example:
            Trivy: com/mccamish/projectname.sbom-version/projectname.sbom-version-trivy-report.json
            SBOM:  com/mccamish/projectname.sbom-version/projectname.sbom-version.json
        
        Args:
            trivy_path: Path to Trivy report file (will derive CycloneDX path)
            
        Returns:
            dict: Parsed JSON content of the CycloneDX SBOM
            
        Raises:
            Exception: If file not found or download fails
        """
        try:
            logger.debug(f"⬇️ Downloading CycloneDX SBOM based on Trivy path: {trivy_path}")
            
            # Remove "-trivy-report" from the path to get CycloneDX path
            # Example: path/projectname.sbom-version-trivy-report.json
            #       -> path/projectname.sbom-version.json
            cyclonedx_path = trivy_path.replace('-trivy-report.json', '.json')
            
            # If the path didn't contain -trivy-report, try other patterns
            if cyclonedx_path == trivy_path:
                # Fallback: try replacing -trivy-report part anywhere
                cyclonedx_path = trivy_path.replace('-trivy-report', '')
            
            logger.debug(f"🔍 CycloneDX path derived: {cyclonedx_path}")
            
            # Construct full URL
            download_url = f"{self.nexus_url}/repository/{self.repository}/{cyclonedx_path}"
            logger.debug(f"🌐 Downloading CycloneDX from: {download_url}")
            
            response = self.session.get(download_url, timeout=30)
            response.raise_for_status()
            
            cyclonedx_content = response.json()
            logger.info(f"✅ Successfully downloaded CycloneDX SBOM from {cyclonedx_path}")
            return cyclonedx_content
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logger.debug(f"⚠️ CycloneDX SBOM not found at: {cyclonedx_path}")
                raise FileNotFoundError(f"CycloneDX SBOM not found: {cyclonedx_path}")
            else:
                logger.error(f"❌ HTTP Error downloading CycloneDX SBOM: {e.response.status_code}")
                raise
        except Exception as e:
            logger.error(f"❌ Error downloading CycloneDX SBOM: {str(e)}")
            raise
    
    def get_repository_info(self):
        """Get information about the Trivy report repository"""
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
        """Search for Trivy report files by project name"""
        logger.info(f"🔍 Searching Trivy report files for project: {project_name}")
        
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
            
            logger.info(f"📦 Found {len(sbom_files)} Trivy report files for project {project_name}")
            return sbom_files
            
        except Exception as e:
            logger.error(f"❌ Error searching Trivy report files for project {project_name}: {str(e)}")
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
    
    def _extract_branch_name(self, version_string):
        """Extract branch name from version string
        
        Format: {version}-{timestamp} or {version}-{timestamp}-{branchname}
        Examples:
        - 1.0.0-20251106105615 -> 'not provided' (no branch name)
        - 1.0.0-20251106182437-multitenant-main -> 'multitenant-main'
        """
        try:
            # Look for pattern: -{8+ digits}-{anything}
            # This matches -{timestamp}-{branchname}
            match = re.search(r'-(\d{8,})-(.+)$', version_string)
            if match:
                branch_name = match.group(2)
                if branch_name:
                    logger.info(f"🌿 Branch name found: '{branch_name}' from version: {version_string}")
                    return branch_name
            
            # No branch name found
            logger.info(f"🌿 No branch name in version: {version_string}")
            return 'not provided'
            
        except Exception as e:
            logger.warning(f"Error extracting branch name from {version_string}: {str(e)}")
            return 'not provided'
    
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
        """Get storage statistics for the Trivy report repository"""
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
            trivy_files = self.list_sbom_files()
            total_size = sum(f.get('size', 0) for f in trivy_files)
            
            return {
                'total_files': len(trivy_files),
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
