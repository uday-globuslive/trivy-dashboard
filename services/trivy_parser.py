"""
Trivy Report Parser for extracting vulnerability and component data from native Trivy JSON reports
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class TrivyReportParser:
    """Parser for native Trivy JSON report files"""
    
    def __init__(self):
        self.supported_schema_versions = [2]
        logger.info("🔧 Initialized Trivy report parser")
    
    def is_trivy_report(self, content: Dict[str, Any]) -> bool:
        """
        Check if the content is a valid Trivy report
        
        Args:
            content: Raw JSON content
            
        Returns:
            bool: True if content is a valid Trivy report
        """
        try:
            return (
                isinstance(content, dict) and
                'SchemaVersion' in content and
                'Results' in content
            )
        except Exception:
            return False
    
    def parse_trivy_report(self, trivy_content: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse Trivy report content and extract relevant data
        
        Args:
            trivy_content: Raw Trivy JSON content
            
        Returns:
            dict: Parsed and structured data containing:
                - metadata: Report metadata and project information
                - components: List of targets/components analyzed
                - vulnerabilities: List of vulnerabilities found
        """
        try:
            logger.debug("🔄 Parsing Trivy report content")
            
            # Validate Trivy report format
            self._validate_trivy_report(trivy_content)
            
            parsed_data = {
                'metadata': self._parse_metadata(trivy_content),
                'components': self._parse_components(trivy_content),
                'vulnerabilities': self._parse_vulnerabilities(trivy_content),
                'services': [],  # Trivy reports don't have services section
                'dependencies': self._parse_dependencies(trivy_content),
                'annotations': []  # Trivy reports don't have annotations
            }
            
            logger.debug(f"✅ Successfully parsed Trivy report - Targets: {len(parsed_data['components'])}, "
                        f"Vulnerabilities: {len(parsed_data['vulnerabilities'])}")
            
            return parsed_data
            
        except Exception as e:
            logger.error(f"❌ Error parsing Trivy report: {str(e)}")
            raise
    
    def _validate_trivy_report(self, trivy_content: Dict[str, Any]):
        """Validate Trivy report format and version"""
        if not isinstance(trivy_content, dict):
            raise ValueError("Trivy report content must be a JSON object")
        
        # Check for required fields
        if 'SchemaVersion' not in trivy_content:
            raise ValueError("Missing required field: SchemaVersion")
        
        if 'Results' not in trivy_content:
            raise ValueError("Missing required field: Results")
        
        schema_version = trivy_content.get('SchemaVersion')
        if schema_version not in self.supported_schema_versions:
            logger.warning(f"⚠️ Potentially unsupported Trivy schema version: {schema_version}")
    
    def _parse_metadata(self, trivy_content: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Trivy report metadata"""
        metadata = trivy_content.get('Metadata', {})
        
        parsed_metadata = {
            'bom_format': 'Trivy',
            'spec_version': str(trivy_content.get('SchemaVersion', 'unknown')),
            'serial_number': '',
            'version': 1,
            'timestamp': self._parse_timestamp(trivy_content.get('CreatedAt')),
            'project': self._extract_project_name(trivy_content),
            'project_version': self._extract_project_version(trivy_content),
            'project_type': 'container',  # Most Trivy scans are containers
            'project_group': '',
            'project_description': '',
            'licenses': [],
            'supplier': {},
            'manufacturer': {},
            'tools': [{
                'vendor': 'Aqua Security',
                'name': 'Trivy',
                'version': trivy_content.get('Version', 'unknown'),
                'hashes': {}
            }],
            'authors': [],
            'properties': {
                'trivy_version': trivy_content.get('Version', 'unknown'),
                'schema_version': str(trivy_content.get('SchemaVersion', 'unknown'))
            }
        }
        
        return parsed_metadata
    
    def _parse_components(self, trivy_content: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse targets from Trivy report as components"""
        results = trivy_content.get('Results', [])
        parsed_components = []
        
        for result in results:
            try:
                target = result.get('Target', '')
                target_type = result.get('Type', 'unknown')
                
                parsed_component = {
                    'bom_ref': target,
                    'type': self._map_target_type(target_type),
                    'name': target,
                    'version': self._extract_target_version(result),
                    'group': '',
                    'description': f"Trivy scan target: {target}",
                    'scope': 'required',
                    'licenses': [],
                    'copyright': '',
                    'cpe': '',
                    'purl': '',
                    'swid': {},
                    'hashes': {},
                    'supplier': {},
                    'manufacturer': {},
                    'external_references': [],
                    'properties': {
                        'target': target,
                        'type': target_type,
                        'vulnerability_count': len(result.get('Vulnerabilities', []))
                    }
                }
                
                parsed_components.append(parsed_component)
                
            except Exception as e:
                logger.warning(f"⚠️ Error parsing component: {str(e)}")
                continue
        
        logger.debug(f"📦 Parsed {len(parsed_components)} components")
        return parsed_components
    
    def _parse_vulnerabilities(self, trivy_content: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse vulnerabilities from Trivy report"""
        results = trivy_content.get('Results', [])
        parsed_vulnerabilities = []
        
        for result in results:
            target = result.get('Target', '')
            vulnerabilities = result.get('Vulnerabilities', [])
            
            for vuln in vulnerabilities:
                try:
                    vuln_id = vuln.get('VulnerabilityID', '')
                    
                    parsed_vuln = {
                        'bom_ref': f"{target}#{vuln_id}",
                        'id': vuln_id,
                        'source': {
                            'name': vuln.get('DataSource', {}).get('Name', ''),
                            'url': vuln.get('DataSource', {}).get('URL', '')
                        },
                        'ratings': self._parse_cvss_ratings(vuln),
                        'cwes': self._extract_cwes(vuln),
                        'description': vuln.get('Description', ''),
                        'detail': vuln.get('Description', ''),
                        'recommendation': self._build_recommendation(vuln),
                        'advisories': self._parse_references(vuln),
                        'created': None,
                        'published': self._parse_timestamp(vuln.get('PublishedDate')),
                        'updated': self._parse_timestamp(vuln.get('LastModifiedDate')),
                        'credits': {},
                        'tools': [],
                        'analysis': {},
                        'affects': [{
                            'ref': target,
                            'versions': [vuln.get('InstalledVersion', '')]
                        }],
                        'properties': {
                            'target': target,
                            'package_name': vuln.get('PkgName', ''),
                            'installed_version': vuln.get('InstalledVersion', ''),
                            'fixed_version': vuln.get('FixedVersion', ''),
                            'package_path': vuln.get('PkgPath', ''),
                            'layer_digest': vuln.get('Layer', {}).get('Digest', '') if vuln.get('Layer') else ''
                        },
                        
                        # Calculated fields
                        'severity': vuln.get('Severity', 'UNKNOWN').upper(),
                        'score': self._extract_cvss_score(vuln),
                        'vector': self._extract_cvss_vector(vuln)
                    }
                    
                    parsed_vulnerabilities.append(parsed_vuln)
                    
                except Exception as e:
                    logger.warning(f"⚠️ Error parsing vulnerability: {str(e)}")
                    continue
        
        logger.debug(f"🚨 Parsed {len(parsed_vulnerabilities)} vulnerabilities")
        return parsed_vulnerabilities
    
    def _parse_dependencies(self, trivy_content: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse dependencies from Trivy report (limited compared to SBOM)"""
        # Trivy reports don't have explicit dependency relationships like SBOMs
        # We can infer some relationships from package information
        results = trivy_content.get('Results', [])
        parsed_dependencies = []
        
        for result in results:
            target = result.get('Target', '')
            packages = result.get('Packages', [])
            
            # Create a basic dependency structure where target depends on all packages
            if packages:
                depends_on = []
                for pkg in packages:
                    pkg_id = f"{pkg.get('Name', '')}-{pkg.get('Version', '')}"
                    depends_on.append(pkg_id)
                
                parsed_dependencies.append({
                    'ref': target,
                    'depends_on': depends_on
                })
        
        return parsed_dependencies
    
    # Helper methods for parsing specific data structures
    
    def _parse_timestamp(self, timestamp_str):
        """Parse timestamp string to datetime object"""
        if not timestamp_str:
            return None
            
        try:
            # Handle different timestamp formats
            formats = [
                '%Y-%m-%dT%H:%M:%S.%fZ',
                '%Y-%m-%dT%H:%M:%SZ',
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%d %H:%M:%S'
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(timestamp_str, fmt)
                except ValueError:
                    continue
            
            logger.warning(f"⚠️ Could not parse timestamp: {timestamp_str}")
            return None
            
        except Exception:
            return None
    
    def _extract_project_name(self, trivy_content: Dict[str, Any]) -> str:
        """Extract project name from Trivy report"""
        # Try to get project name from results or metadata
        results = trivy_content.get('Results', [])
        if results:
            target = results[0].get('Target', '')
            # Remove path components and file extensions to get a clean name
            if '/' in target:
                target = target.split('/')[-1]
            if ':' in target:
                target = target.split(':')[0]
            return target
        
        return 'unknown'
    
    def _extract_project_version(self, trivy_content: Dict[str, Any]) -> str:
        """Extract project version from Trivy report"""
        results = trivy_content.get('Results', [])
        if results:
            target = results[0].get('Target', '')
            # Try to extract version from container tag
            if ':' in target:
                parts = target.split(':')
                if len(parts) > 1:
                    return parts[-1]
        
        return 'unknown'
    
    def _map_target_type(self, target_type: str) -> str:
        """Map Trivy target type to component type"""
        type_mapping = {
            'os': 'operating-system',
            'library': 'library',
            'application': 'application',
            'container': 'container',
            'jar': 'library',
            'node': 'library',
            'python': 'library',
            'ruby': 'library',
            'go': 'library'
        }
        return type_mapping.get(target_type.lower(), 'library')
    
    def _extract_target_version(self, result: Dict[str, Any]) -> str:
        """Extract version from target result"""
        target = result.get('Target', '')
        if ':' in target:
            return target.split(':')[-1]
        return 'unknown'
    
    def _parse_cvss_ratings(self, vuln: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse CVSS ratings from vulnerability"""
        ratings = []
        
        # Parse CVSS v2
        cvss_v2 = vuln.get('CVSS', {}).get('nvd', {}).get('V2Score')
        if cvss_v2:
            ratings.append({
                'source': {'name': 'NVD', 'url': ''},
                'score': cvss_v2,
                'severity': self._score_to_severity(cvss_v2, 'v2'),
                'method': 'CVSSv2',
                'vector': vuln.get('CVSS', {}).get('nvd', {}).get('V2Vector', ''),
                'justification': ''
            })
        
        # Parse CVSS v3
        cvss_v3 = vuln.get('CVSS', {}).get('nvd', {}).get('V3Score')
        if cvss_v3:
            ratings.append({
                'source': {'name': 'NVD', 'url': ''},
                'score': cvss_v3,
                'severity': self._score_to_severity(cvss_v3, 'v3'),
                'method': 'CVSSv3',
                'vector': vuln.get('CVSS', {}).get('nvd', {}).get('V3Vector', ''),
                'justification': ''
            })
        
        return ratings
    
    def _extract_cwes(self, vuln: Dict[str, Any]) -> List[int]:
        """Extract CWE IDs from vulnerability"""
        cwes = []
        cwe_ids = vuln.get('CweIDs', [])
        
        for cwe_id in cwe_ids:
            try:
                if isinstance(cwe_id, str) and cwe_id.startswith('CWE-'):
                    cwes.append(int(cwe_id.replace('CWE-', '')))
                elif isinstance(cwe_id, int):
                    cwes.append(cwe_id)
            except ValueError:
                continue
        
        return cwes
    
    def _build_recommendation(self, vuln: Dict[str, Any]) -> str:
        """Build recommendation text from vulnerability data"""
        fixed_version = vuln.get('FixedVersion', '')
        if fixed_version:
            return f"Upgrade {vuln.get('PkgName', 'package')} to version {fixed_version}"
        
        return "Review vulnerability details and apply appropriate mitigation measures"
    
    def _parse_references(self, vuln: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse vulnerability references as advisories"""
        references = vuln.get('References', [])
        advisories = []
        
        for ref in references:
            if isinstance(ref, str):
                advisories.append({
                    'title': 'Reference',
                    'url': ref
                })
        
        return advisories
    
    def _extract_cvss_score(self, vuln: Dict[str, Any]) -> float:
        """Extract the highest CVSS score"""
        cvss_data = vuln.get('CVSS', {})
        
        # Try v3 first, then v2
        v3_score = cvss_data.get('nvd', {}).get('V3Score')
        if v3_score is not None:
            return float(v3_score)
        
        v2_score = cvss_data.get('nvd', {}).get('V2Score')
        if v2_score is not None:
            return float(v2_score)
        
        return None
    
    def _extract_cvss_vector(self, vuln: Dict[str, Any]) -> str:
        """Extract CVSS vector string"""
        cvss_data = vuln.get('CVSS', {})
        
        # Try v3 first, then v2
        v3_vector = cvss_data.get('nvd', {}).get('V3Vector')
        if v3_vector:
            return v3_vector
        
        v2_vector = cvss_data.get('nvd', {}).get('V2Vector')
        if v2_vector:
            return v2_vector
        
        return ''
    
    def _score_to_severity(self, score: float, version: str) -> str:
        """Convert CVSS score to severity level"""
        if version == 'v2':
            if score >= 7.0:
                return 'HIGH'
            elif score >= 4.0:
                return 'MEDIUM'
            else:
                return 'LOW'
        else:  # v3
            if score >= 9.0:
                return 'CRITICAL'
            elif score >= 7.0:
                return 'HIGH'
            elif score >= 4.0:
                return 'MEDIUM'
            elif score >= 0.1:
                return 'LOW'
            else:
                return 'INFO'