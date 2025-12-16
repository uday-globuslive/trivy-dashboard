"""
JFrog Artifactory Client for fetching Trivy report files
"""

import requests
import logging
from urllib.parse import urljoin, quote
from datetime import datetime
import base64
import json
import re

logger = logging.getLogger(__name__)

class JFrogClient:
    """Client for interacting with JFrog Artifactory"""
    
    def __init__(self, jfrog_url, username, password, repository):
        self.jfrog_url = jfrog_url.rstrip('/')
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
        
        logger.info(f"🔗 Initialized JFrog client for {jfrog_url} (repository: {repository})")
    
    def test_connection(self):
        """Test connection to JFrog Artifactory"""
        try:
            response = self.session.get(f"{self.jfrog_url}/artifactory/api/system/ping")
            response.raise_for_status()
            logger.info("✅ JFrog connection test successful")
            return True
        except Exception as e:
            logger.error(f"❌ JFrog connection test failed: {str(e)}")
            return False
    
    def list_trivy_files(self, limit=1000):
        """
        List all Trivy report files in the JFrog repository.
        
        Uses JFrog AQL (Artifactory Query Language) to search for trivy report files.
        """
        from config import Config
        
        logger.info(f"📋 Listing Trivy report files from repository: {self.repository}")
        logger.info(f"🔍 Searching for: groupId={Config.JFROG_GROUP_ID}, suffix={Config.JFROG_ARTIFACT_SUFFIX}, extension={Config.JFROG_ASSET_EXTENSION}")
        logger.info(f"🌐 JFrog URL: {self.jfrog_url}")
        
        sbom_files = []
        try:
            # Use AQL (Artifactory Query Language) to search for files
            aql_query = {
                "repo": self.repository,
                "type": "file",
                "$and": [
                    {"name": {"$match": f"*{Config.JFROG_ARTIFACT_SUFFIX}.{Config.JFROG_ASSET_EXTENSION}"}},
                    {"path": {"$match": f"{Config.JFROG_GROUP_ID.replace('.', '/')}/*"}}
                ]
            }
            
            # Convert AQL query to proper format
            aql_string = f'items.find({json.dumps(aql_query)}).limit({limit})'
            
            logger.info(f"🔍 AQL Query: {aql_string}")
            
            search_url = f"{self.jfrog_url}/artifactory/api/search/aql"
            response = self.session.post(search_url, data=aql_string, headers={'Content-Type': 'text/plain'}, timeout=30)
            response.raise_for_status()
            
            search_results = response.json()
            items = search_results.get('results', [])
            
            logger.info(f"📦 Found {len(items)} assets in JFrog")
            
            for asset in items:
                try:
                    # Parse asset path: com/company/project/version/project-version-trivy-report.json
                    asset_path = asset.get('path', '')
                    asset_name = asset.get('name', '')
                    repo = asset.get('repo', '')
                    
                    # Combine path and name for full path
                    full_path = f"{asset_path}/{asset_name}" if asset_path else asset_name
                    
                    logger.debug(f"🔍 Processing asset: {full_path}")
                    
                    # Skip checksum files
                    if asset_name.endswith(('.json.sha1', '.json.sha256', '.json.sha512', '.json.md5')):
                        logger.debug(f"⏭️ Skipping checksum file: {asset_name}")
                        continue
                    
                    # Only process Trivy report JSON files
                    if not asset_name.endswith(f'{Config.JFROG_ARTIFACT_SUFFIX}.{Config.JFROG_ASSET_EXTENSION}'):
                        logger.debug(f"⏭️ Skipping non-Trivy-report file: {asset_name}")
                        continue
                    
                    # Parse Maven path structure: com/company/{artifactId}/{version}/{filename}
                    path_parts = full_path.split('/')
                    if len(path_parts) < 4:
                        logger.debug(f"⏭️ Skipping asset with insufficient path parts: {full_path}")
                        continue
                    
                    # Extract components from path
                    group_parts = path_parts[:-3]  # ['com', 'company']
                    artifact_id = path_parts[-3]   # e.g., 'project_name'
                    version = path_parts[-2]       # e.g., '1.0.0-20250924044857'
                    filename = path_parts[-1]      # e.g., 'project_name-1.0.0-20250924044857-trivy-report.json'
                    
                    logger.debug(f"📦 Parsed: artifact={artifact_id}, version={version}, filename={filename}")
                    
                    # For Trivy reports, project name is the artifact_id directly
                    project_name = artifact_id
                    
                    # Extract build number from version (timestamp part)
                    build_number = self._extract_build_number(version)
                    
                    # Extract branch name from version (part after the timestamp)
                    branch_name = self._extract_branch_name(version)
                    logger.info(f"🌿 Extracted branch name: '{branch_name}' from version: {version}")
                    
                    # Get timestamp from JFrog metadata
                    timestamp = self._parse_timestamp(asset.get('modified', ''))
                    
                    # Construct proper download URL
                    download_url = f"{self.jfrog_url}/artifactory/{repo}/{full_path}"
                    
                    sbom_file = {
                        'path': download_url,
                        'project': project_name,
                        'build_number': build_number,
                        'branch_name': branch_name,
                        'timestamp': timestamp,
                        'size': asset.get('size', 0),
                        'group_id': '/'.join(group_parts),
                        'artifact_id': artifact_id,
                        'version': version,
                        'filename': filename,
                        'asset_path': full_path
                    }
                    
                    logger.debug(f"✅ Added Trivy report file: {project_name} - {version}")
                    sbom_files.append(sbom_file)
                    
                except Exception as e:
                    logger.warning(f"⚠️ Error parsing asset {asset.get('name', 'unknown')}: {str(e)}")
                    continue
            
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
        Download Trivy report content from JFrog
        
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
                # Construct proper repository URL for JFrog
                download_url = f"{self.jfrog_url}/artifactory/{self.repository}/{trivy_path}"
            
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
        Download CycloneDX SBOM file from JFrog
        
        Assumes CycloneDX file is in same folder as Trivy report but without the "-trivy-report" suffix
        
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
            cyclonedx_path = trivy_path.replace('-trivy-report.json', '.json')
            
            # If the path didn't contain -trivy-report, try other patterns
            if cyclonedx_path == trivy_path:
                cyclonedx_path = trivy_path.replace('-trivy-report', '')
            
            logger.debug(f"🔍 CycloneDX path derived: {cyclonedx_path}")
            
            # Construct full URL
            download_url = f"{self.jfrog_url}/artifactory/{self.repository}/{cyclonedx_path}"
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
            repo_url = f"{self.jfrog_url}/artifactory/api/repositories/{self.repository}"
            response = self.session.get(repo_url)
            response.raise_for_status()
            
            repo_info = response.json()
            logger.info(f"📊 Repository info: {repo_info.get('key', 'Unknown')}")
            
            return repo_info
            
        except Exception as e:
            logger.error(f"❌ Error getting repository info: {str(e)}")
            return {}
    
    def search_sbom_by_project(self, project_name):
        """Search for Trivy report files by project name"""
        logger.info(f"🔍 Searching Trivy report files for project: {project_name}")
        
        try:
            # Use AQL to search for specific project
            aql_query = f'items.find({{"repo":"{self.repository}","name":{{"$match":"*{project_name}*trivy-report*"}}}}).limit(100)'
            
            search_url = f"{self.jfrog_url}/artifactory/api/search/aql"
            response = self.session.post(search_url, data=aql_query, headers={'Content-Type': 'text/plain'})
            response.raise_for_status()
            
            results = response.json()
            sbom_files = []
            
            for item in results.get('results', []):
                asset_path = item.get('path', '')
                asset_name = item.get('name', '')
                full_path = f"{asset_path}/{asset_name}" if asset_path else asset_name
                
                path_parts = full_path.split('/')
                if len(path_parts) >= 3:
                    version = path_parts[-2]
                    sbom_files.append({
                        'project': project_name,
                        'version': version,
                        'build_number': self._extract_build_number(version),
                        'download_url': f"{self.jfrog_url}/artifactory/{self.repository}/{full_path}",
                        'timestamp': self._parse_timestamp(item.get('modified', ''))
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
            if Config.JFROG_VERSION_PREFIX and version_string.startswith(Config.JFROG_VERSION_PREFIX):
                suffix = version_string[len(Config.JFROG_VERSION_PREFIX):]
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
        """Parse timestamp from JFrog API response"""
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
            # Get repository storage stats from JFrog
            stats_url = f"{self.jfrog_url}/artifactory/api/storageinfo"
            
            try:
                response = self.session.get(stats_url)
                if response.status_code == 200:
                    storage_info = response.json()
                    # Find specific repository stats
                    for repo in storage_info.get('repositoriesSummaryList', []):
                        if repo.get('repoKey') == self.repository:
                            return {
                                'total_files': repo.get('filesCount', 0),
                                'total_size_bytes': int(repo.get('usedSpace', '0').replace(',', '')),
                                'total_size_mb': int(repo.get('usedSpace', '0').replace(',', '')) / (1024 * 1024),
                                'repository': self.repository
                            }
            except:
                pass
            
            # Fallback: calculate from search results
            trivy_files = self.list_trivy_files()
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
