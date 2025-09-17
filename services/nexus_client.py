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
    
    def __init__(self, nexus_url, username, password, repository='trivy-sbom'):
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
        
        logger.info(f"🔗 Initialized Nexus client for {nexus_url}")
    
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
        List all SBOM files in the Nexus repository
        
        Returns list of SBOM file metadata including:
        - path: Full path to the file
        - project: Project name extracted from path
        - build_number: Build number from artifact version
        - timestamp: File upload timestamp
        - size: File size in bytes
        """
        logger.info(f"📋 Listing SBOM files from repository: {self.repository}")
        
        try:
            # Use Nexus search API to find CycloneDX files
            search_url = f"{self.nexus_url}/service/rest/v1/search"
            params = {
                'repository': self.repository,
                'format': 'maven2',
                'sort': 'version',
                'direction': 'desc'
            }
            
            response = self.session.get(search_url, params=params)
            response.raise_for_status()
            
            search_results = response.json()
            sbom_files = []
            
            for item in search_results.get('items', []):
                try:
                    # Parse artifact information
                    group_id = item.get('group', '')
                    artifact_id = item.get('name', '')
                    version = item.get('version', '')
                    
                    # Extract project name (typically the artifact ID)
                    project_name = artifact_id
                    
                    # Extract build number from version
                    build_number = self._extract_build_number(version)
                    
                    # Get download URL
                    download_url = item.get('assets', [{}])[0].get('downloadUrl', '')
                    
                    if download_url and download_url.endswith('.json'):
                        sbom_file = {
                            'path': download_url,
                            'project': project_name,
                            'build_number': build_number,
                            'timestamp': self._parse_timestamp(item.get('lastModified', '')),
                            'size': item.get('assets', [{}])[0].get('fileSize', 0),
                            'group_id': group_id,
                            'artifact_id': artifact_id,
                            'version': version
                        }
                        sbom_files.append(sbom_file)
                        
                except Exception as e:
                    logger.warning(f"⚠️ Error parsing SBOM file metadata: {str(e)}")
                    continue
            
            logger.info(f"📦 Found {len(sbom_files)} SBOM files")
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
                download_url = f"{self.nexus_url}/repository/{self.repository}/{sbom_path}"
            
            response = self.session.get(download_url, timeout=30)
            response.raise_for_status()
            
            # Parse JSON content
            sbom_content = response.json()
            logger.debug(f"✅ Successfully downloaded SBOM ({len(response.content)} bytes)")
            
            return sbom_content
            
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
        """Extract build number from version string"""
        try:
            # Common patterns for build numbers in versions
            patterns = [
                r'build[_-](\d+)',  # build_123, build-123
                r'(\d+)$',          # version ending with number
                r'\.(\d+)$',        # version.123
                r'-(\d+)$'          # version-123
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
