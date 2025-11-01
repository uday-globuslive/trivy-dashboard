"""
Hybrid SBOM Parser - Merges Trivy and CycloneDX to generate SPDX-like information

This module combines data from both Trivy JSON reports and CycloneDX SBOMs
to create a unified view with security + license information.

Data Sources:
- Trivy: Vulnerability, severity, affected package versions
- CycloneDX: Package info, licenses, dependencies, supplier
- Generated: Derived SPDX-like fields
"""

import json
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional


class HybridSBOMParser:
    """Parse and merge Trivy + CycloneDX data into unified SBOM"""
    
    def __init__(self, trivy_data: Dict, cyclonedx_data: Dict):
        """
        Initialize parser with both data sources
        
        Args:
            trivy_data: Parsed Trivy JSON report
            cyclonedx_data: Parsed CycloneDX SBOM
        """
        self.trivy_data = trivy_data
        self.cyclonedx_data = cyclonedx_data
        self.merged_components = {}
    
    def parse(self) -> Dict[str, Any]:
        """
        Parse and merge both SBOM formats
        
        Returns:
            Unified SBOM with SPDX-like fields
        """
        return {
            'spdxVersion': 'SPDX-2.3',
            'dataLicense': 'CC0-1.0',
            'name': self._get_document_name(),
            'documentNamespace': self._generate_document_namespace(),
            'creationInfo': self._get_creation_info(),
            'components': self._merge_components(),
            'relationships': self._build_relationships(),
            'externalRefs': self._extract_external_refs(),
        }
    
    def _get_document_name(self) -> str:
        """Get document name from available sources"""
        if self.cyclonedx_data and 'metadata' in self.cyclonedx_data:
            metadata = self.cyclonedx_data.get('metadata', {})
            if 'component' in metadata:
                comp = metadata['component']
                return f"{comp.get('name', 'Unknown')}-{comp.get('version', '1.0')}"
        
        if self.trivy_data and 'ArtifactName' in self.trivy_data:
            return self.trivy_data.get('ArtifactName', 'Unknown')
        
        return 'Hybrid-SBOM'
    
    def _generate_document_namespace(self) -> str:
        """Generate unique document namespace"""
        doc_name = self._get_document_name()
        timestamp = datetime.now().isoformat()
        hash_input = f"{doc_name}-{timestamp}".encode()
        namespace_hash = hashlib.sha256(hash_input).hexdigest()[:12]
        
        return f"https://trivy-dashboard/spdx/{namespace_hash}/{timestamp}"
    
    def _get_creation_info(self) -> Dict[str, Any]:
        """Extract creation information"""
        return {
            'created': datetime.now().isoformat() + 'Z',
            'creators': [
                'Tool: trivy-dashboard',
                'Tool: Trivy',
                'Tool: CycloneDX'
            ],
            'licenseListVersion': '3.19'
        }
    
    def _merge_components(self) -> List[Dict[str, Any]]:
        """
        Merge components from both sources
        
        Priority:
        1. Use CycloneDX as primary source (has license info)
        2. Enrich with Trivy vulnerability data
        3. Generate SPDX-like fields
        """
        components = []
        processed = set()
        
        # First pass: Process CycloneDX components (primary source)
        if self.cyclonedx_data and 'components' in self.cyclonedx_data:
            for cdx_component in self.cyclonedx_data['components']:
                component = self._parse_cyclonedx_component(cdx_component)
                
                # Enrich with Trivy vulnerability data
                if self.trivy_data and 'Results' in self.trivy_data:
                    for result in self.trivy_data['Results']:
                        if 'Vulnerabilities' in result:
                            vulns = self._match_vulnerabilities(
                                component['name'],
                                component['version'],
                                result['Vulnerabilities']
                            )
                            if vulns:
                                component['vulnerabilities'] = vulns
                
                components.append(component)
                processed.add((component['name'], component['version']))
        
        # Second pass: Add Trivy vulnerabilities not in CycloneDX
        if self.trivy_data and 'Results' in self.trivy_data:
            for result in self.trivy_data['Results']:
                if 'Vulnerabilities' in result:
                    for vuln in result['Vulnerabilities']:
                        pkg_name = vuln.get('PkgName', '')
                        version = vuln.get('InstalledVersion', '')
                        
                        if (pkg_name, version) not in processed:
                            component = self._create_component_from_trivy(vuln)
                            components.append(component)
                            processed.add((pkg_name, version))
        
        return components
    
    def _parse_cyclonedx_component(self, cdx_component: Dict) -> Dict[str, Any]:
        """
        Parse CycloneDX component to SPDX-like format
        
        Args:
            cdx_component: CycloneDX component object
            
        Returns:
            Unified component with SPDX fields
        """
        component = {
            'SPDXID': f"SPDXRef-Package-{self._generate_spdx_id(cdx_component)}",
            'name': cdx_component.get('name', 'Unknown'),
            'version': cdx_component.get('version', ''),
            'downloadLocation': self._get_download_location(cdx_component),
            'filesAnalyzed': False,
            'licenseConcluded': self._extract_license_concluded(cdx_component),
            'licenseDeclared': self._extract_license_declared(cdx_component),
            'licenseComments': self._generate_license_comments(cdx_component),
            'copyrightText': self._extract_copyright(cdx_component),
            'externalRefs': self._extract_component_external_refs(cdx_component),
            'supplier': self._extract_supplier(cdx_component),
            'description': cdx_component.get('description', ''),
            'purl': cdx_component.get('purl', ''),
            'type': cdx_component.get('type', 'library'),
        }
        
        # Add source info
        if 'licenses' in cdx_component:
            component['licenses'] = cdx_component['licenses']
        
        return component
    
    def _create_component_from_trivy(self, trivy_vuln: Dict) -> Dict[str, Any]:
        """
        Create component entry from Trivy vulnerability
        
        Args:
            trivy_vuln: Trivy vulnerability object
            
        Returns:
            Component with derived SPDX fields
        """
        pkg_name = trivy_vuln.get('PkgName', '')
        version = trivy_vuln.get('InstalledVersion', '')
        
        return {
            'SPDXID': f"SPDXRef-Package-{self._generate_spdx_id({'name': pkg_name, 'version': version})}",
            'name': pkg_name,
            'version': version,
            'downloadLocation': 'NOASSERTION',
            'filesAnalyzed': False,
            'licenseConcluded': 'NOASSERTION',
            'licenseDeclared': 'NOASSERTION',
            'licenseComments': 'License information not available in Trivy report',
            'copyrightText': 'NOASSERTION',
            'description': f"Package with vulnerabilities - from Trivy scan",
            'vulnerabilities': [{
                'id': trivy_vuln.get('VulnerabilityID', ''),
                'severity': trivy_vuln.get('Severity', 'UNKNOWN'),
                'affectedVersion': version,
                'fixedVersion': trivy_vuln.get('FixedVersion', 'Not available'),
            }],
            'type': 'library',
        }
    
    def _match_vulnerabilities(self, pkg_name: str, version: str, 
                               trivy_vulns: List[Dict]) -> List[Dict]:
        """
        Match and extract vulnerabilities for a component
        
        Args:
            pkg_name: Package name
            version: Package version
            trivy_vulns: List of Trivy vulnerabilities
            
        Returns:
            List of relevant vulnerabilities
        """
        matched = []
        
        for vuln in trivy_vulns:
            if vuln.get('PkgName', '').lower() == pkg_name.lower():
                if self._version_in_range(version, vuln):
                    matched.append({
                        'id': vuln.get('VulnerabilityID', ''),
                        'severity': vuln.get('Severity', 'UNKNOWN'),
                        'affectedVersion': version,
                        'fixedVersion': vuln.get('FixedVersion', 'Not available'),
                        'cvssScore': self._extract_cvss_score(vuln),
                        'description': vuln.get('Description', ''),
                        'title': vuln.get('Title', ''),
                        'primaryURL': vuln.get('PrimaryURL', ''),
                    })
        
        return matched
    
    def _version_in_range(self, installed: str, vuln: Dict) -> bool:
        """
        Check if installed version is affected by vulnerability
        
        Args:
            installed: Installed version
            vuln: Vulnerability object
            
        Returns:
            True if version is affected
        """
        # Simple comparison - in production, use semantic versioning
        if installed == vuln.get('InstalledVersion', ''):
            return True
        return False
    
    def _extract_cvss_score(self, vuln: Dict) -> Optional[float]:
        """Extract CVSS score from vulnerability"""
        if 'CVSS' in vuln:
            cvss = vuln['CVSS']
            if isinstance(cvss, dict):
                for key in ['nvd', 'github', 'redhat']:
                    if key in cvss:
                        return cvss[key].get('V3Score', cvss[key].get('V2Score'))
        return None
    
    def _extract_license_concluded(self, cdx_component: Dict) -> str:
        """
        Extract concluded license from CycloneDX component
        
        For CycloneDX, concluded license = license field
        """
        if 'licenses' in cdx_component and cdx_component['licenses']:
            licenses = []
            for license_obj in cdx_component['licenses']:
                if 'license' in license_obj:
                    license_id = license_obj['license'].get('id')
                    if license_id:
                        licenses.append(license_id)
            
            if licenses:
                return ' OR '.join(licenses) if len(licenses) > 1 else licenses[0]
        
        return 'NOASSERTION'
    
    def _extract_license_declared(self, cdx_component: Dict) -> str:
        """
        Extract declared license from CycloneDX component
        
        In CycloneDX, there's no distinction - use same as concluded
        """
        return self._extract_license_concluded(cdx_component)
    
    def _generate_license_comments(self, cdx_component: Dict) -> str:
        """Generate license comments for SPDX"""
        comments = []
        
        if 'licenses' in cdx_component:
            for license_obj in cdx_component['licenses']:
                if 'license' in license_obj:
                    license_data = license_obj['license']
                    if 'text' in license_data:
                        comments.append(f"License text provided by CycloneDX: {license_data.get('id', 'Unknown')}")
                    if 'url' in license_data:
                        comments.append(f"License URL: {license_data['url']}")
        
        if comments:
            return '; '.join(comments)
        
        return 'License information derived from CycloneDX SBOM'
    
    def _extract_copyright(self, cdx_component: Dict) -> str:
        """
        Extract copyright from CycloneDX component
        
        CycloneDX doesn't have explicit copyright field
        Try to extract from supplier or other fields
        """
        # Check supplier for copyright-like info
        if 'supplier' in cdx_component:
            supplier = cdx_component['supplier']
            if 'name' in supplier:
                return f"Copyright by {supplier['name']}"
        
        return 'NOASSERTION'
    
    def _extract_supplier(self, cdx_component: Dict) -> Optional[Dict[str, str]]:
        """Extract supplier information from CycloneDX"""
        if 'supplier' in cdx_component:
            supplier = cdx_component['supplier']
            return {
                'name': supplier.get('name', 'NOASSERTION'),
                'email': None,
                'url': supplier.get('url', [None])[0] if 'url' in supplier else None,
            }
        return None
    
    def _extract_component_external_refs(self, cdx_component: Dict) -> List[Dict]:
        """Extract external references from CycloneDX component"""
        refs = []
        
        # Add PURL as external reference
        if 'purl' in cdx_component:
            refs.append({
                'referenceCategory': 'PACKAGE_MANAGER',
                'referenceType': 'purl',
                'referenceLocator': cdx_component['purl'],
            })
        
        # Add other external references if present
        if 'externalReferences' in cdx_component:
            for ext_ref in cdx_component['externalReferences']:
                refs.append({
                    'referenceCategory': ext_ref.get('type', 'OTHER').upper(),
                    'referenceType': ext_ref.get('type', 'other'),
                    'referenceLocator': ext_ref.get('url', ''),
                })
        
        return refs
    
    def _extract_external_refs(self) -> List[Dict]:
        """Extract top-level external references"""
        refs = []
        
        # Add artifact information from Trivy
        if self.trivy_data and 'ArtifactName' in self.trivy_data:
            refs.append({
                'referenceCategory': 'SECURITY',
                'referenceType': 'scan-id',
                'referenceLocator': self.trivy_data.get('ArtifactID', ''),
            })
        
        return refs
    
    def _get_download_location(self, cdx_component: Dict) -> str:
        """Get download location from component"""
        if 'purl' in cdx_component:
            return cdx_component['purl']
        
        if 'externalReferences' in cdx_component:
            for ext_ref in cdx_component['externalReferences']:
                if ext_ref.get('type') == 'vcs':
                    return ext_ref.get('url', 'NOASSERTION')
        
        return 'NOASSERTION'
    
    def _generate_spdx_id(self, component: Dict) -> str:
        """Generate unique SPDX ID for component"""
        name = component.get('name', 'unknown').replace('-', '_').replace(' ', '_')
        version = component.get('version', '0').replace('.', '_').replace('-', '_')
        combined = f"{name}-{version}"
        return hashlib.md5(combined.encode()).hexdigest()[:8]
    
    def _build_relationships(self) -> List[Dict[str, Any]]:
        """
        Build relationships between components
        
        Extracts from CycloneDX dependencies
        """
        relationships = []
        
        # Document describes components
        if self.cyclonedx_data and 'components' in self.cyclonedx_data:
            for component in self.cyclonedx_data['components']:
                spdx_id = f"SPDXRef-Package-{self._generate_spdx_id(component)}"
                relationships.append({
                    'spdxElementId': 'SPDXRef-DOCUMENT',
                    'relationshipType': 'DESCRIBES',
                    'relatedSpdxElement': spdx_id,
                })
        
        # Component dependencies
        if self.cyclonedx_data and 'dependencies' in self.cyclonedx_data:
            for dep in self.cyclonedx_data['dependencies']:
                ref_id = dep.get('ref')
                if ref_id and 'depends' in dep:
                    for sub_dep in dep['depends']:
                        relationships.append({
                            'spdxElementId': ref_id,
                            'relationshipType': 'DEPENDS_ON',
                            'relatedSpdxElement': sub_dep.get('ref'),
                        })
        
        return relationships
    
    def to_spdx_json(self) -> str:
        """Convert to SPDX JSON format"""
        return json.dumps(self.parse(), indent=2)
    
    def get_component_sbom(self, pkg_name: str, version: str) -> Optional[Dict[str, Any]]:
        """
        Get unified SBOM information for a specific component
        
        Args:
            pkg_name: Package name
            version: Package version
            
        Returns:
            Unified component information
        """
        components = self._merge_components()
        
        for component in components:
            if component['name'].lower() == pkg_name.lower() and component['version'] == version:
                return component
        
        return None
