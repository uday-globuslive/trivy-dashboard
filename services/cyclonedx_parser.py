"""
CycloneDX SBOM Parser for extracting vulnerability and component data
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class CycloneDXParser:
    """Parser for CycloneDX SBOM files"""
    
    def __init__(self):
        self.supported_versions = ['1.4', '1.5', '1.6']
        logger.info("🔧 Initialized CycloneDX parser")
    
    def parse_cyclonedx(self, sbom_content: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse CycloneDX SBOM content and extract relevant data
        
        Args:
            sbom_content: Raw CycloneDX JSON content
            
        Returns:
            dict: Parsed and structured data containing:
                - metadata: SBOM metadata and project information
                - components: List of components with details
                - vulnerabilities: List of vulnerabilities found
                - services: List of services (if any)
                - dependencies: Dependency relationships
        """
        try:
            logger.debug("🔄 Parsing CycloneDX SBOM content")
            
            # Validate SBOM format
            self._validate_sbom(sbom_content)
            
            parsed_data = {
                'metadata': self._parse_metadata(sbom_content),
                'components': self._parse_components(sbom_content),
                'vulnerabilities': self._parse_vulnerabilities(sbom_content),
                'services': self._parse_services(sbom_content),
                'dependencies': self._parse_dependencies(sbom_content),
                'annotations': self._parse_annotations(sbom_content)
            }
            
            logger.debug(f"✅ Successfully parsed SBOM - Components: {len(parsed_data['components'])}, "
                        f"Vulnerabilities: {len(parsed_data['vulnerabilities'])}")
            
            return parsed_data
            
        except Exception as e:
            logger.error(f"❌ Error parsing CycloneDX SBOM: {str(e)}")
            raise
    
    def _validate_sbom(self, sbom_content: Dict[str, Any]):
        """Validate SBOM format and version"""
        if not isinstance(sbom_content, dict):
            raise ValueError("SBOM content must be a JSON object")
        
        # Check for required fields
        if 'bomFormat' not in sbom_content:
            raise ValueError("Missing required field: bomFormat")
        
        if sbom_content.get('bomFormat') != 'CycloneDX':
            raise ValueError(f"Unsupported BOM format: {sbom_content.get('bomFormat')}")
        
        spec_version = sbom_content.get('specVersion', '')
        if spec_version not in self.supported_versions:
            logger.warning(f"⚠️ Potentially unsupported CycloneDX version: {spec_version}")
    
    def _parse_metadata(self, sbom_content: Dict[str, Any]) -> Dict[str, Any]:
        """Parse SBOM metadata"""
        metadata = sbom_content.get('metadata', {})
        
        # Extract project information
        component = metadata.get('component', {})
        
        parsed_metadata = {
            'bom_format': sbom_content.get('bomFormat', 'CycloneDX'),
            'spec_version': sbom_content.get('specVersion', 'unknown'),
            'serial_number': sbom_content.get('serialNumber', ''),
            'version': sbom_content.get('version', 1),
            'timestamp': self._parse_timestamp(metadata.get('timestamp')),
            'project': component.get('name', 'unknown'),
            'project_version': component.get('version', 'unknown'),
            'project_type': component.get('type', 'unknown'),
            'project_group': component.get('group', ''),
            'project_description': component.get('description', ''),
            'licenses': self._extract_licenses(component.get('licenses', [])),
            'supplier': self._parse_supplier(component.get('supplier')),
            'manufacturer': self._parse_supplier(component.get('manufacturer')),
            'tools': self._parse_tools(metadata.get('tools', [])),
            'authors': self._parse_authors(metadata.get('authors', [])),
            'properties': self._parse_properties(metadata.get('properties', []))
        }
        
        return parsed_metadata
    
    def _parse_components(self, sbom_content: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse components from SBOM"""
        components = sbom_content.get('components', [])
        parsed_components = []
        
        for component in components:
            try:
                parsed_component = {
                    'bom_ref': component.get('bom-ref', ''),
                    'type': component.get('type', 'library'),
                    'name': component.get('name', ''),
                    'version': component.get('version', ''),
                    'group': component.get('group', ''),
                    'description': component.get('description', ''),
                    'scope': component.get('scope', 'optional'),
                    'licenses': self._extract_licenses(component.get('licenses', [])),
                    'copyright': component.get('copyright', ''),
                    'cpe': component.get('cpe', ''),
                    'purl': component.get('purl', ''),
                    'swid': component.get('swid', {}),
                    'hashes': self._parse_hashes(component.get('hashes', [])),
                    'supplier': self._parse_supplier(component.get('supplier')),
                    'manufacturer': self._parse_supplier(component.get('manufacturer')),
                    'external_references': self._parse_external_references(component.get('externalReferences', [])),
                    'properties': self._parse_properties(component.get('properties', []))
                }
                
                parsed_components.append(parsed_component)
                
            except Exception as e:
                logger.warning(f"⚠️ Error parsing component: {str(e)}")
                continue
        
        logger.debug(f"📦 Parsed {len(parsed_components)} components")
        return parsed_components
    
    def _parse_vulnerabilities(self, sbom_content: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse vulnerabilities from SBOM"""
        vulnerabilities = sbom_content.get('vulnerabilities', [])
        parsed_vulnerabilities = []
        
        for vuln in vulnerabilities:
            try:
                parsed_vuln = {
                    'bom_ref': vuln.get('bom-ref', ''),
                    'id': vuln.get('id', ''),
                    'source': self._parse_vulnerability_source(vuln.get('source', {})),
                    'ratings': self._parse_vulnerability_ratings(vuln.get('ratings', [])),
                    'cwes': vuln.get('cwes', []),
                    'description': vuln.get('description', ''),
                    'detail': vuln.get('detail', ''),
                    'recommendation': vuln.get('recommendation', ''),
                    'advisories': self._parse_advisories(vuln.get('advisories', [])),
                    'created': self._parse_timestamp(vuln.get('created')),
                    'published': self._parse_timestamp(vuln.get('published')),
                    'updated': self._parse_timestamp(vuln.get('updated')),
                    'credits': self._parse_credits(vuln.get('credits', {})),
                    'tools': self._parse_tools(vuln.get('tools', [])),
                    'analysis': self._parse_vulnerability_analysis(vuln.get('analysis')),
                    'affects': self._parse_affects(vuln.get('affects', [])),
                    'properties': self._parse_properties(vuln.get('properties', [])),
                    
                    # Calculated fields
                    'severity': self._determine_severity(vuln),
                    'score': self._determine_score(vuln),
                    'vector': self._determine_vector(vuln)
                }
                
                parsed_vulnerabilities.append(parsed_vuln)
                
            except Exception as e:
                logger.warning(f"⚠️ Error parsing vulnerability: {str(e)}")
                continue
        
        logger.debug(f"🚨 Parsed {len(parsed_vulnerabilities)} vulnerabilities")
        return parsed_vulnerabilities
    
    def _parse_services(self, sbom_content: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse services from SBOM"""
        services = sbom_content.get('services', [])
        parsed_services = []
        
        for service in services:
            try:
                parsed_service = {
                    'bom_ref': service.get('bom-ref', ''),
                    'name': service.get('name', ''),
                    'version': service.get('version', ''),
                    'description': service.get('description', ''),
                    'endpoints': service.get('endpoints', []),
                    'authenticated': service.get('authenticated', False),
                    'x_trust_boundary': service.get('x-trust-boundary', False),
                    'data': self._parse_data_classification(service.get('data', [])),
                    'licenses': self._extract_licenses(service.get('licenses', [])),
                    'external_references': self._parse_external_references(service.get('externalReferences', [])),
                    'properties': self._parse_properties(service.get('properties', []))
                }
                
                parsed_services.append(parsed_service)
                
            except Exception as e:
                logger.warning(f"⚠️ Error parsing service: {str(e)}")
                continue
        
        return parsed_services
    
    def _parse_dependencies(self, sbom_content: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse dependency relationships from SBOM"""
        dependencies = sbom_content.get('dependencies', [])
        parsed_dependencies = []
        
        for dep in dependencies:
            try:
                parsed_dep = {
                    'ref': dep.get('ref', ''),
                    'depends_on': dep.get('dependsOn', [])
                }
                parsed_dependencies.append(parsed_dep)
                
            except Exception as e:
                logger.warning(f"⚠️ Error parsing dependency: {str(e)}")
                continue
        
        return parsed_dependencies
    
    def _parse_annotations(self, sbom_content: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse annotations from SBOM"""
        annotations = sbom_content.get('annotations', [])
        parsed_annotations = []
        
        for annotation in annotations:
            try:
                parsed_annotation = {
                    'bom_ref': annotation.get('bom-ref', ''),
                    'subjects': annotation.get('subjects', []),
                    'annotator': annotation.get('annotator', {}),
                    'timestamp': self._parse_timestamp(annotation.get('timestamp')),
                    'text': annotation.get('text', '')
                }
                parsed_annotations.append(parsed_annotation)
                
            except Exception as e:
                logger.warning(f"⚠️ Error parsing annotation: {str(e)}")
                continue
        
        return parsed_annotations
    
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
    
    def _extract_licenses(self, licenses_list):
        """Extract license information"""
        extracted_licenses = []
        
        for license_item in licenses_list:
            if isinstance(license_item, dict):
                if 'license' in license_item:
                    license_data = license_item['license']
                    if isinstance(license_data, dict):
                        extracted_licenses.append({
                            'id': license_data.get('id', ''),
                            'name': license_data.get('name', ''),
                            'text': license_data.get('text', {}).get('content', ''),
                            'url': license_data.get('url', '')
                        })
                elif 'expression' in license_item:
                    extracted_licenses.append({
                        'expression': license_item['expression']
                    })
        
        return extracted_licenses
    
    def _parse_supplier(self, supplier_data):
        """Parse supplier/manufacturer information"""
        if not supplier_data:
            return {}
        
        return {
            'name': supplier_data.get('name', ''),
            'url': supplier_data.get('url', []),
            'contact': supplier_data.get('contact', [])
        }
    
    def _parse_tools(self, tools_list):
        """Parse tools information"""
        parsed_tools = []
        
        for tool in tools_list:
            if isinstance(tool, dict):
                parsed_tools.append({
                    'vendor': tool.get('vendor', ''),
                    'name': tool.get('name', ''),
                    'version': tool.get('version', ''),
                    'hashes': self._parse_hashes(tool.get('hashes', []))
                })
        
        return parsed_tools
    
    def _parse_authors(self, authors_list):
        """Parse authors information"""
        return [
            {
                'name': author.get('name', ''),
                'email': author.get('email', ''),
                'phone': author.get('phone', '')
            }
            for author in authors_list if isinstance(author, dict)
        ]
    
    def _parse_properties(self, properties_list):
        """Parse properties array"""
        return {
            prop.get('name', ''): prop.get('value', '')
            for prop in properties_list if isinstance(prop, dict)
        }
    
    def _parse_hashes(self, hashes_list):
        """Parse hashes information"""
        return {
            hash_item.get('alg', ''): hash_item.get('content', '')
            for hash_item in hashes_list if isinstance(hash_item, dict)
        }
    
    def _parse_external_references(self, refs_list):
        """Parse external references"""
        return [
            {
                'type': ref.get('type', ''),
                'url': ref.get('url', ''),
                'comment': ref.get('comment', ''),
                'hashes': self._parse_hashes(ref.get('hashes', []))
            }
            for ref in refs_list if isinstance(ref, dict)
        ]
    
    def _parse_vulnerability_source(self, source_data):
        """Parse vulnerability source information"""
        if not source_data:
            return {}
        
        return {
            'name': source_data.get('name', ''),
            'url': source_data.get('url', '')
        }
    
    def _parse_vulnerability_ratings(self, ratings_list):
        """Parse vulnerability ratings"""
        parsed_ratings = []
        
        for rating in ratings_list:
            if isinstance(rating, dict):
                parsed_ratings.append({
                    'source': self._parse_vulnerability_source(rating.get('source')),
                    'score': rating.get('score'),
                    'severity': rating.get('severity', ''),
                    'method': rating.get('method', ''),
                    'vector': rating.get('vector', ''),
                    'justification': rating.get('justification', '')
                })
        
        return parsed_ratings
    
    def _parse_advisories(self, advisories_list):
        """Parse vulnerability advisories"""
        return [
            {
                'title': advisory.get('title', ''),
                'url': advisory.get('url', '')
            }
            for advisory in advisories_list if isinstance(advisory, dict)
        ]
    
    def _parse_credits(self, credits_data):
        """Parse vulnerability credits"""
        if not credits_data:
            return {}
        
        return {
            'organizations': credits_data.get('organizations', []),
            'individuals': credits_data.get('individuals', [])
        }
    
    def _parse_vulnerability_analysis(self, analysis_data):
        """Parse vulnerability analysis"""
        if not analysis_data:
            return {}
        
        return {
            'state': analysis_data.get('state', ''),
            'justification': analysis_data.get('justification', ''),
            'response': analysis_data.get('response', []),
            'detail': analysis_data.get('detail', '')
        }
    
    def _parse_affects(self, affects_list):
        """Parse vulnerability affects"""
        return [
            {
                'ref': affect.get('ref', ''),
                'versions': affect.get('versions', [])
            }
            for affect in affects_list if isinstance(affect, dict)
        ]
    
    def _parse_data_classification(self, data_list):
        """Parse data classification for services"""
        return [
            {
                'flow': data.get('flow', ''),
                'classification': data.get('classification', '')
            }
            for data in data_list if isinstance(data, dict)
        ]
    
    def _determine_severity(self, vulnerability):
        """Determine the highest severity from ratings"""
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN']
        
        ratings = vulnerability.get('ratings', [])
        if not ratings:
            return 'UNKNOWN'
        
        severities = [rating.get('severity', 'UNKNOWN').upper() for rating in ratings]
        
        for severity in severity_order:
            if severity in severities:
                return severity
        
        return 'UNKNOWN'
    
    def _determine_score(self, vulnerability):
        """Determine the highest score from ratings"""
        ratings = vulnerability.get('ratings', [])
        scores = [rating.get('score') for rating in ratings if rating.get('score') is not None]
        
        return max(scores) if scores else None
    
    def _determine_vector(self, vulnerability):
        """Get the attack vector from ratings"""
        ratings = vulnerability.get('ratings', [])
        vectors = [rating.get('vector') for rating in ratings if rating.get('vector')]
        
        return vectors[0] if vectors else None
