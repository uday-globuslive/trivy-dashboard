"""
Comprehensive SBOM Parser - Extracts detailed package information
from Trivy JSON, CycloneDX, and derives SPDX-like details

This parser provides comprehensive SBOM information similar to what's found in SPDX format:
- Package names, versions, and purposes
- Security vulnerabilities with CVE details
- Package verification codes (checksums)
- License information (from CycloneDX)
- External references (PURL, advisory links)
- Package relationships and dependencies
"""

import json
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
import re


class ComprehensiveSBOMParser:
    """Parse and extract comprehensive SBOM details from Trivy and CycloneDX files"""
    
    def __init__(self, trivy_data: Dict, cyclonedx_data: Dict):
        """
        Initialize parser with both data sources
        
        Args:
            trivy_data: Parsed Trivy JSON report
            cyclonedx_data: Parsed CycloneDX SBOM
        """
        self.trivy_data = trivy_data
        self.cyclonedx_data = cyclonedx_data
        self.components_cache = {}
    
    def get_comprehensive_sbom_details(self) -> Dict[str, Any]:
        """
        Generate comprehensive SBOM details similar to SPDX format
        
        Returns:
            Dict containing complete SBOM information
        """
        return {
            'document_info': self._get_document_info(),
            'scan_metadata': self._get_scan_metadata(),
            'packages': self._get_all_packages(),
            'vulnerabilities': self._get_vulnerability_summary(),
            'relationships': self._get_package_relationships(),
            'statistics': self._calculate_statistics(),
        }
    
    def _get_document_info(self) -> Dict[str, Any]:
        """Extract document-level information"""
        return {
            'name': self.trivy_data.get('ArtifactName', 'Unknown'),
            'artifact_type': self.trivy_data.get('ArtifactType', 'unknown'),
            'schema_version': self.trivy_data.get('SchemaVersion', 'unknown'),
            'created_at': self.trivy_data.get('CreatedAt', ''),
            'namespace': self._generate_document_namespace(),
            'spdx_version': 'SPDX-2.3',
            'data_license': 'CC0-1.0',
        }
    
    def _get_scan_metadata(self) -> Dict[str, Any]:
        """Extract scan metadata information"""
        metadata = self.trivy_data.get('Metadata', {})
        return {
            'repo_url': metadata.get('RepoURL', ''),
            'commit': metadata.get('Commit', ''),
            'commit_message': metadata.get('CommitMsg', ''),
            'author': metadata.get('Author', ''),
            'committer': metadata.get('Committer', ''),
        }
    
    def _get_all_packages(self) -> List[Dict[str, Any]]:
        """
        Extract detailed package information combining Trivy and CycloneDX data
        
        Returns SPDX-like package information with enhanced details
        """
        packages = []
        processed_packages = set()
        
        # Build CycloneDX lookup for license info
        cyclonedx_lookup = self._build_cyclonedx_lookup()
        
        # Process packages from Trivy results
        for result in self.trivy_data.get('Results', []):
            target = result.get('Target', 'unknown')
            result_type = result.get('Type', 'unknown')
            
            # Process vulnerabilities to get package info
            for vuln in result.get('Vulnerabilities', []):
                pkg_name = vuln.get('PkgName', '')
                version = vuln.get('InstalledVersion', '')
                
                if not pkg_name or (pkg_name, version) in processed_packages:
                    continue
                
                package_info = self._build_comprehensive_package_info(
                    vuln, target, result_type, cyclonedx_lookup
                )
                packages.append(package_info)
                processed_packages.add((pkg_name, version))
        
        # Add packages from CycloneDX that don't have vulnerabilities
        for component in self.cyclonedx_data.get('components', []):
            pkg_name = component.get('name', '')
            version = component.get('version', '')
            
            if (pkg_name, version) not in processed_packages:
                package_info = self._build_package_from_cyclonedx_only(component)
                packages.append(package_info)
        
        return sorted(packages, key=lambda x: x.get('name', ''))
    
    def _build_cyclonedx_lookup(self) -> Dict[str, Dict]:
        """Build lookup table for CycloneDX component information"""
        lookup = {}
        for component in self.cyclonedx_data.get('components', []):
            name = component.get('name', '')
            version = component.get('version', '')
            key = f"{name}:{version}"
            lookup[key] = component
        return lookup
    
    def _build_comprehensive_package_info(self, vuln: Dict, target: str, 
                                         result_type: str, cyclonedx_lookup: Dict) -> Dict[str, Any]:
        """
        Build comprehensive package information from vulnerability data and CycloneDX
        
        Args:
            vuln: Vulnerability data from Trivy
            target: Target file/path from Trivy result
            result_type: Type of scan result
            cyclonedx_lookup: CycloneDX component lookup
            
        Returns:
            Comprehensive package information dict
        """
        pkg_name = vuln.get('PkgName', '')
        version = vuln.get('InstalledVersion', '')
        pkg_id = vuln.get('PkgID', '')
        
        # Get CycloneDX info if available
        cyclonedx_key = f"{pkg_name}:{version}"
        cyclonedx_info = cyclonedx_lookup.get(cyclonedx_key, {})
        
        # Generate SPDX ID
        spdx_id = self._generate_spdx_id(pkg_name, version)
        
        package_info = {
            # Basic package information
            'spdx_id': spdx_id,
            'name': pkg_name,
            'version': version,
            'pkg_id': pkg_id,
            'target_file': target,
            'scan_type': result_type,
            
            # SPDX-like fields
            'supplier': self._extract_supplier(cyclonedx_info),
            'download_location': self._get_download_location(vuln, cyclonedx_info),
            'primary_purpose': 'LIBRARY',
            'verification_code': self._generate_verification_code(pkg_name, version),
            'license_concluded': self._get_license_concluded(cyclonedx_info),
            'license_declared': self._get_license_declared(cyclonedx_info),
            'copyright_text': self._get_copyright_text(cyclonedx_info),
            
            # External references
            'external_refs': self._get_external_references(vuln, cyclonedx_info),
            
            # Vulnerability information
            'vulnerabilities': [self._format_vulnerability_info(vuln)],
            
            # Package metadata
            'purl': vuln.get('PkgIdentifier', {}).get('PURL', ''),
            'uid': vuln.get('PkgIdentifier', {}).get('UID', ''),
            
            # Additional metadata from CycloneDX
            'component_type': cyclonedx_info.get('type', 'library'),
            'bom_ref': cyclonedx_info.get('bom-ref', ''),
            'description': cyclonedx_info.get('description', ''),
        }
        
        return package_info
    
    def _build_package_from_cyclonedx_only(self, component: Dict) -> Dict[str, Any]:
        """Build package info from CycloneDX component (no vulnerabilities)"""
        pkg_name = component.get('name', '')
        version = component.get('version', '')
        
        return {
            'spdx_id': self._generate_spdx_id(pkg_name, version),
            'name': pkg_name,
            'version': version,
            'pkg_id': f"{pkg_name}:{version}",
            'target_file': 'N/A',
            'scan_type': 'component',
            
            'supplier': self._extract_supplier(component),
            'download_location': 'NONE',
            'primary_purpose': 'LIBRARY',
            'verification_code': self._generate_verification_code(pkg_name, version),
            'license_concluded': self._get_license_concluded(component),
            'license_declared': self._get_license_declared(component),
            'copyright_text': self._get_copyright_text(component),
            
            'external_refs': self._get_external_references({}, component),
            'vulnerabilities': [],
            
            'purl': component.get('purl', ''),
            'uid': component.get('bom-ref', ''),
            'component_type': component.get('type', 'library'),
            'bom_ref': component.get('bom-ref', ''),
            'description': component.get('description', ''),
        }
    
    def _format_vulnerability_info(self, vuln: Dict) -> Dict[str, Any]:
        """Format vulnerability information for display"""
        return {
            'id': vuln.get('VulnerabilityID', ''),
            'severity': vuln.get('Severity', 'UNKNOWN'),
            'title': vuln.get('Title', ''),
            'description': vuln.get('Description', ''),
            'fixed_version': vuln.get('FixedVersion', ''),
            'primary_url': vuln.get('PrimaryURL', ''),
            'data_source': vuln.get('DataSource', {}),
            'cvss_scores': self._extract_cvss_scores(vuln),
            'cwe_ids': vuln.get('CweIDs', []),
            'vendor_severity': vuln.get('VendorSeverity', {}),
            'status': vuln.get('Status', ''),
        }
    
    def _extract_cvss_scores(self, vuln: Dict) -> List[Dict[str, Any]]:
        """Extract CVSS scores from vulnerability"""
        scores = []
        cvss_data = vuln.get('CVSS', {})
        
        for source, score_info in cvss_data.items():
            if isinstance(score_info, dict):
                scores.append({
                    'source': source,
                    'vector': score_info.get('V3Vector', score_info.get('V2Vector', '')),
                    'score': score_info.get('V3Score', score_info.get('V2Score', 0)),
                    'version': 'CVSSv3.1' if 'V3Score' in score_info else 'CVSSv2.0'
                })
        
        return scores
    
    def _extract_supplier(self, cyclonedx_info: Dict) -> str:
        """Extract supplier information"""
        if 'supplier' in cyclonedx_info:
            supplier = cyclonedx_info['supplier']
            if isinstance(supplier, dict):
                return supplier.get('name', 'NOASSERTION')
            return str(supplier)
        return 'NOASSERTION'
    
    def _get_download_location(self, vuln: Dict, cyclonedx_info: Dict) -> str:
        """Get package download location"""
        # Try PURL first
        purl = vuln.get('PkgIdentifier', {}).get('PURL')
        if purl:
            return purl
        
        # Try CycloneDX PURL
        if 'purl' in cyclonedx_info:
            return cyclonedx_info['purl']
        
        return 'NONE'
    
    def _get_license_concluded(self, cyclonedx_info: Dict) -> str:
        """Extract concluded license from CycloneDX"""
        licenses = cyclonedx_info.get('licenses', [])
        if not licenses:
            return 'NOASSERTION'
        
        license_names = []
        for license_obj in licenses:
            if 'license' in license_obj:
                license_id = license_obj['license'].get('id')
                if license_id:
                    license_names.append(license_id)
        
        return ' AND '.join(license_names) if license_names else 'NOASSERTION'
    
    def _get_license_declared(self, cyclonedx_info: Dict) -> str:
        """Extract declared license (same as concluded for CycloneDX)"""
        return self._get_license_concluded(cyclonedx_info)
    
    def _get_copyright_text(self, cyclonedx_info: Dict) -> str:
        """Extract or derive copyright text"""
        supplier = self._extract_supplier(cyclonedx_info)
        if supplier != 'NOASSERTION':
            return f"Copyright by {supplier}"
        return 'NOASSERTION'
    
    def _get_external_references(self, vuln: Dict, cyclonedx_info: Dict) -> List[Dict[str, str]]:
        """Get external references for the package"""
        refs = []
        
        # Add PURL reference
        purl = vuln.get('PkgIdentifier', {}).get('PURL') or cyclonedx_info.get('purl')
        if purl:
            refs.append({
                'category': 'PACKAGE-MANAGER',
                'type': 'purl',
                'locator': purl
            })
        
        # Add vulnerability advisory links
        primary_url = vuln.get('PrimaryURL')
        if primary_url:
            refs.append({
                'category': 'SECURITY',
                'type': 'advisory',
                'locator': primary_url
            })
        
        # Add CycloneDX external references
        for ext_ref in cyclonedx_info.get('externalReferences', []):
            refs.append({
                'category': ext_ref.get('type', 'OTHER').upper(),
                'type': ext_ref.get('type', 'other'),
                'locator': ext_ref.get('url', '')
            })
        
        return refs
    
    def _generate_spdx_id(self, pkg_name: str, version: str) -> str:
        """Generate SPDX ID for package"""
        combined = f"{pkg_name}-{version}".replace(':', '-').replace('/', '-')
        hash_value = hashlib.md5(combined.encode()).hexdigest()[:8]
        return f"SPDXRef-Package-{hash_value}"
    
    def _generate_verification_code(self, pkg_name: str, version: str) -> str:
        """Generate package verification code (SHA1 simulation)"""
        combined = f"{pkg_name}:{version}"
        return hashlib.sha1(combined.encode()).hexdigest()
    
    def _generate_document_namespace(self) -> str:
        """Generate unique document namespace"""
        artifact_name = self.trivy_data.get('ArtifactName', 'unknown')
        timestamp = datetime.now().isoformat()
        hash_input = f"{artifact_name}-{timestamp}".encode()
        namespace_hash = hashlib.sha256(hash_input).hexdigest()[:12]
        
        return f"http://trivy.dev/filesystem/{artifact_name}-{namespace_hash}"
    
    def _get_vulnerability_summary(self) -> Dict[str, Any]:
        """Get vulnerability summary statistics"""
        total_vulns = 0
        by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
        
        for result in self.trivy_data.get('Results', []):
            vulns = result.get('Vulnerabilities', [])
            total_vulns += len(vulns)
            
            for vuln in vulns:
                severity = vuln.get('Severity', 'UNKNOWN')
                by_severity[severity] = by_severity.get(severity, 0) + 1
        
        return {
            'total_vulnerabilities': total_vulns,
            'by_severity': by_severity,
            'targets_scanned': len(self.trivy_data.get('Results', [])),
        }
    
    def _get_package_relationships(self) -> List[Dict[str, str]]:
        """Get package relationships (CONTAINS relationships)"""
        relationships = []
        
        # Document DESCRIBES the main component
        relationships.append({
            'source': 'SPDXRef-DOCUMENT',
            'type': 'DESCRIBES',
            'target': 'SPDXRef-Filesystem-Main'
        })
        
        # Filesystem CONTAINS all packages
        for result in self.trivy_data.get('Results', []):
            for vuln in result.get('Vulnerabilities', []):
                pkg_name = vuln.get('PkgName', '')
                version = vuln.get('InstalledVersion', '')
                spdx_id = self._generate_spdx_id(pkg_name, version)
                
                relationships.append({
                    'source': 'SPDXRef-Filesystem-Main',
                    'type': 'CONTAINS',
                    'target': spdx_id
                })
        
        return relationships
    
    def _calculate_statistics(self) -> Dict[str, Any]:
        """Calculate SBOM statistics"""
        packages = self._get_all_packages()
        
        total_packages = len(packages)
        packages_with_vulns = len([p for p in packages if p.get('vulnerabilities')])
        packages_with_licenses = len([p for p in packages if p.get('license_concluded') != 'NOASSERTION'])
        
        license_distribution = {}
        for pkg in packages:
            license_concluded = pkg.get('license_concluded', 'NOASSERTION')
            license_distribution[license_concluded] = license_distribution.get(license_concluded, 0) + 1
        
        return {
            'total_packages': total_packages,
            'packages_with_vulnerabilities': packages_with_vulns,
            'packages_with_licenses': packages_with_licenses,
            'license_coverage_percentage': round((packages_with_licenses / total_packages * 100), 1) if total_packages > 0 else 0,
            'license_distribution': license_distribution,
        }
    
    def get_package_details(self, pkg_name: str, version: str = None) -> Optional[Dict[str, Any]]:
        """
        Get detailed information for a specific package
        
        Args:
            pkg_name: Package name to search for
            version: Optional specific version
            
        Returns:
            Detailed package information or None if not found
        """
        packages = self._get_all_packages()
        
        for pkg in packages:
            if pkg.get('name', '').lower() == pkg_name.lower():
                if version is None or pkg.get('version') == version:
                    return pkg
        
        return None
    
    def search_packages(self, query: str) -> List[Dict[str, Any]]:
        """
        Search packages by name or description
        
        Args:
            query: Search query string
            
        Returns:
            List of matching packages
        """
        packages = self._get_all_packages()
        query_lower = query.lower()
        
        matches = []
        for pkg in packages:
            name = pkg.get('name', '').lower()
            description = pkg.get('description', '').lower()
            
            if query_lower in name or query_lower in description:
                matches.append(pkg)
        
        return matches
    
    def export_to_spdx_format(self) -> str:
        """
        Export comprehensive SBOM to SPDX text format
        
        Returns:
            SPDX formatted string
        """
        sbom_data = self.get_comprehensive_sbom_details()
        doc_info = sbom_data['document_info']
        packages = sbom_data['packages']
        relationships = sbom_data['relationships']
        
        spdx_lines = []
        
        # Document header
        spdx_lines.extend([
            f"SPDXVersion: {doc_info['spdx_version']}",
            f"DataLicense: {doc_info['data_license']}",
            "SPDXID: SPDXRef-DOCUMENT",
            f"DocumentName: {doc_info['name']}",
            f"DocumentNamespace: {doc_info['namespace']}",
            "Creator: Organization: trivy-dashboard",
            "Creator: Tool: comprehensive-sbom-parser",
            f"Created: {datetime.now().isoformat()}Z",
            ""
        ])
        
        # Packages
        for pkg in packages:
            spdx_lines.extend([
                f"##### Package: {pkg['name']}",
                "",
                f"PackageName: {pkg['name']}",
                f"SPDXID: {pkg['spdx_id']}",
                f"PackageVersion: {pkg['version']}",
                f"PackageSupplier: {pkg['supplier']}",
                f"PackageDownloadLocation: {pkg['download_location']}",
                f"PrimaryPackagePurpose: {pkg['primary_purpose']}",
                f"PackageVerificationCode: {pkg['verification_code']}",
                f"PackageLicenseConcluded: {pkg['license_concluded']}",
                f"PackageLicenseDeclared: {pkg['license_declared']}",
                f"PackageCopyrightText: {pkg['copyright_text']}",
            ])
            
            # External references
            for ref in pkg.get('external_refs', []):
                spdx_lines.append(f"ExternalRef: {ref['category']} {ref['type']} {ref['locator']}")
            
            spdx_lines.append("")
        
        # Relationships
        spdx_lines.append("##### Relationships")
        spdx_lines.append("")
        for rel in relationships:
            spdx_lines.append(f"Relationship: {rel['source']} {rel['type']} {rel['target']}")
        
        return '\n'.join(spdx_lines)