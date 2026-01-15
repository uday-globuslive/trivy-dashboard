"""
Trivy Security Dashboard - Main Flask Application

This Flask application provides a comprehensive dashboard for visualizing
Trivy security scan results from native Trivy report JSON files stored in Nexus Repository.
"""

import os
import json
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, send_file, Response
from flask_cors import CORS
import threading
import time

# Import our custom services
from services.nexus_client import NexusClient
from services.jfrog_client import JFrogClient
from services.trivy_parser import TrivyReportParser
from services.analytics import SecurityAnalytics
from services.hybrid_sbom_parser import HybridSBOMParser
from utils.cache import CacheManager
from utils.disk_cache import DiskCacheManager
from utils.helpers import format_timestamp, calculate_risk_score
from config import Config

# Configure logging
logging.basicConfig(
    level=getattr(logging, Config.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)
CORS(app)

# Initialize artifactory client based on configuration
def create_artifactory_client():
    """Factory function to create the appropriate artifactory client"""
    if Config.ARTIFACTORY_TYPE == 'jfrog':
        logger.info(f"🔧 Initializing JFrog Artifactory client")
        return JFrogClient(
            Config.JFROG_URL,
            Config.JFROG_USERNAME,
            Config.JFROG_PASSWORD,
            Config.JFROG_REPOSITORY
        )
    else:  # default to nexus
        logger.info(f"🔧 Initializing Nexus Repository client")
        return NexusClient(
            Config.NEXUS_URL,
            Config.NEXUS_USERNAME,
            Config.NEXUS_PASSWORD,
            Config.NEXUS_REPOSITORY
        )

# Initialize services
artifactory_client = create_artifactory_client()
trivy_parser = TrivyReportParser()
analytics = SecurityAnalytics()
cache_manager = CacheManager()
disk_cache = DiskCacheManager(
    cache_dir='./data/cache',
    max_memory_mb=500  # Limit in-memory cache to 500MB
)

# Maintain backward compatibility - nexus_client is now artifactory_client
nexus_client = artifactory_client

# Global data store (acts as in-memory database for frequently accessed data)
app_data = {
    'projects': {},
    'scans': {},
    'vulnerabilities': {},
    'last_updated': None,
    'is_loading': False,
    'force_refresh': False  # Flag to force immediate refresh
}

# Threading event for immediate refresh trigger
refresh_event = threading.Event()

def refresh_data_background():
    """Background task to refresh data from Nexus"""
    while True:
        try:
            # Check if we should refresh: either on regular interval or forced refresh
            should_refresh = not app_data['is_loading']
            
            if should_refresh or app_data['force_refresh']:
                app_data['force_refresh'] = False  # Reset force refresh flag
                logger.info("🔄 Starting background data refresh...")
                app_data['is_loading'] = True
                
                # Fetch latest Trivy report files from Nexus
                trivy_files = nexus_client.list_trivy_files()
                logger.info(f"📦 Found {len(trivy_files)} Trivy report files in Nexus")
                
                projects = {}
                scans = {}
                vulnerabilities = {}
                
                for trivy_file in trivy_files:
                    try:
                        # Download and parse Trivy report
                        trivy_content = nexus_client.download_trivy_report(trivy_file['path'])
                        
                        # Check if it's a Trivy report (skip if not)
                        if not trivy_parser.is_trivy_report(trivy_content):
                            logger.warning(f"⚠️ Skipping non-Trivy report file: {trivy_file['path']}")
                            continue
                            
                        parsed_data = trivy_parser.parse_trivy_report(trivy_content)
                        
                        # Use project name from Trivy file
                        project_name = trivy_file['project']
                        scan_id = f"{project_name}_{trivy_file['build_number']}"
                        
                        # Store project data
                        if project_name not in projects:
                            projects[project_name] = {
                                'name': project_name,
                                'scans': [],
                                'total_vulnerabilities': 0,
                                'critical_count': 0,
                                'high_count': 0,
                                'medium_count': 0,
                                'low_count': 0,
                                'last_scan': None,
                                'branch_name': 'not provided',
                                'risk_score': 0
                            }
                        
                        # Store scan data
                        # Get branch name, defaulting to 'not provided' if None or not present
                        branch_name = trivy_file.get('branch_name', 'not provided')
                        if branch_name is None:
                            branch_name = 'not provided'
                        
                        scan_data = {
                            'id': scan_id,
                            'project': project_name,
                            'build_number': trivy_file['build_number'],
                            'branch_name': branch_name,
                            'timestamp': parsed_data['metadata']['timestamp'],
                            'trivy_report_path': trivy_file['path'],
                            'vulnerabilities': parsed_data['vulnerabilities'],
                            'components': parsed_data['components'],
                            'metadata': parsed_data['metadata']
                        }
                        
                        scans[scan_id] = scan_data
                        projects[project_name]['scans'].append(scan_id)
                        
                        # Update project statistics with latest scan only
                        vuln_counts = analytics.count_vulnerabilities_by_severity(parsed_data['vulnerabilities'])
                        
                        # Use the CreatedAt timestamp from Trivy report to determine latest scan
                        scan_timestamp = parsed_data['metadata']['timestamp']
                        
                        # Only update if this is the latest scan for this project
                        if (not projects[project_name]['last_scan'] or 
                            scan_timestamp > projects[project_name]['last_scan']):
                            projects[project_name]['critical_count'] = vuln_counts['critical']
                            projects[project_name]['high_count'] = vuln_counts['high']
                            projects[project_name]['medium_count'] = vuln_counts['medium']
                            projects[project_name]['low_count'] = vuln_counts['low']
                            projects[project_name]['total_vulnerabilities'] = vuln_counts['total']
                            # Update branch name from latest scan
                            branch_name = trivy_file.get('branch_name')
                            projects[project_name]['branch_name'] = branch_name if branch_name else 'not provided'
                        
                        # Update last scan timestamp
                        if (not projects[project_name]['last_scan'] or 
                            scan_timestamp > projects[project_name]['last_scan']):
                            projects[project_name]['last_scan'] = scan_timestamp
                        
                        # Store individual vulnerabilities
                        for vuln in parsed_data['vulnerabilities']:
                            vuln_id = vuln['id']
                            if vuln_id not in vulnerabilities:
                                vulnerabilities[vuln_id] = []
                            vulnerabilities[vuln_id].append({
                                'scan_id': scan_id,
                                'project': project_name,
                                'details': vuln
                            })
                        
                    except Exception as e:
                        logger.error(f"❌ Error processing Trivy report file {trivy_file['path']}: {str(e)}")
                        continue
                
                # Calculate risk scores for projects
                for project in projects.values():
                    project['risk_score'] = calculate_risk_score(
                        project['critical_count'],
                        project['high_count'],
                        project['medium_count'],
                        project['low_count']
                    )
                
                # Save all data to disk cache
                logger.info("💾 Saving data to disk cache...")
                disk_cache.clear_all()  # Clear old data
                disk_cache.save_projects(projects)
                
                # Save scans to disk
                for scan_id, scan_data in scans.items():
                    disk_cache.save_scan(scan_id, scan_data)
                
                # Save vulnerabilities to disk
                for vuln_list in vulnerabilities.values():
                    for vuln_item in vuln_list:
                        vuln_id = vuln_item['details'].get('id', '')
                        scan_id = vuln_item.get('scan_id', '')
                        disk_cache.save_vulnerability(vuln_id, scan_id, vuln_item['details'])
                
                # Update global data (keep limited in-memory cache)
                app_data['projects'] = projects
                app_data['scans'] = scans
                app_data['vulnerabilities'] = vulnerabilities
                app_data['last_updated'] = datetime.now()
                app_data['is_loading'] = False
                
                logger.info(f"✅ Data refresh complete. Projects: {len(projects)}, Scans: {len(scans)}")
                
        except Exception as e:
            logger.error(f"❌ Error in background data refresh: {str(e)}")
            app_data['is_loading'] = False
        
        # Wait for next refresh cycle, but can be interrupted by refresh_event
        refresh_event.wait(timeout=Config.REFRESH_INTERVAL)
        refresh_event.clear()  # Clear the event for next use

# Start background data refresh thread
refresh_thread = threading.Thread(target=refresh_data_background, daemon=True)
refresh_thread.start()

@app.route('/debug/nexus')
def debug_nexus():
    """Debug endpoint to inspect Artifactory connection and Trivy report discovery"""
    logger.info("🔧 Debug: Artifactory connection and Trivy report discovery")
    
    # Build config based on artifactory type
    if Config.ARTIFACTORY_TYPE == 'jfrog':
        artifactory_config = {
            'type': 'jfrog',
            'url': Config.JFROG_URL,
            'repository': Config.JFROG_REPOSITORY,
            'username': Config.JFROG_USERNAME,
            'group_id': Config.JFROG_GROUP_ID,
            'artifact_suffix': Config.JFROG_ARTIFACT_SUFFIX,
            'version_prefix': Config.JFROG_VERSION_PREFIX,
            'asset_extension': Config.JFROG_ASSET_EXTENSION
        }
        api_tests = {
            'ping': f"{Config.JFROG_URL}/artifactory/api/system/ping",
            'repositories': f"{Config.JFROG_URL}/artifactory/api/repositories",
            'repository_info': f"{Config.JFROG_URL}/artifactory/api/repositories/{Config.JFROG_REPOSITORY}",
            'browse_repo': f"{Config.JFROG_URL}/artifactory/{Config.JFROG_REPOSITORY}/"
        }
    else:  # nexus
        artifactory_config = {
            'type': 'nexus',
            'url': Config.NEXUS_URL,
            'repository': Config.NEXUS_REPOSITORY,
            'username': Config.NEXUS_USERNAME,
            'group_id': Config.NEXUS_GROUP_ID,
            'artifact_suffix': Config.NEXUS_ARTIFACT_SUFFIX,
            'version_prefix': Config.NEXUS_VERSION_PREFIX,
            'asset_extension': Config.NEXUS_ASSET_EXTENSION
        }
        api_tests = {
            'status': f"{Config.NEXUS_URL}/service/rest/v1/status",
            'repositories': f"{Config.NEXUS_URL}/service/rest/v1/repositories",
            'search_assets': f"{Config.NEXUS_URL}/service/rest/v1/search/assets",
            'repository_info': f"{Config.NEXUS_URL}/service/rest/v1/repositories/{Config.NEXUS_REPOSITORY}",
            'browse_repo': f"{Config.NEXUS_URL}/repository/{Config.NEXUS_REPOSITORY}/com/mccamish/"
        }
    
    debug_info = {
        'artifactory_config': artifactory_config,
        'connection_test': False,
        'trivy_files': [],
        'error_message': None,
        'api_endpoints': {},
        'test_results': {},
        'trivy_analysis': {}
    }
    
    try:
        # Test basic connection
        debug_info['connection_test'] = nexus_client.test_connection()
        
        debug_info['api_endpoints'] = api_tests
        
        # Test each endpoint
        for name, url in api_tests.items():
            try:
                response = nexus_client.session.get(url, timeout=10)
                debug_info['test_results'][name] = {
                    'status_code': response.status_code,
                    'success': response.status_code < 400,
                    'error': None if response.status_code < 400 else response.text[:200]
                }
            except Exception as e:
                debug_info['test_results'][name] = {
                    'status_code': None,
                    'success': False,
                    'error': str(e)
                }
        
        # Try to list Trivy report files with detailed logging
        logger.info("🔍 Attempting to list Trivy report files...")
        trivy_files = nexus_client.list_trivy_files(limit=10)
        debug_info['trivy_files'] = trivy_files
        debug_info['files_found'] = len(trivy_files)
        
        # Test specific McCamish patterns
        debug_info['mccamish_patterns'] = {
            'expected_path_pattern': f"com/mccamish/{{project}}-trivy-report/{{version}}/{{project}}-trivy-report-{{version}}.json",
            'example_path': "com/mccamish/AGP_Stellar_SSO-trivy-report/1.0.0-20250521034211/AGP_Stellar_SSO-trivy-report-1.0.0-20250521034211.json",
            'search_params': {
                'repository': Config.NEXUS_REPOSITORY,
                'group': Config.NEXUS_GROUP_ID,
                'extension': Config.NEXUS_ASSET_EXTENSION
            }
        }
        
        # Get repository info
        try:
            repo_info = nexus_client.get_repository_info()
            debug_info['repository_info'] = repo_info
        except Exception as e:
            debug_info['repository_info'] = {'error': str(e)}
        
        # If we found files, try to download one as a test
        if trivy_files:
            test_file = trivy_files[0]
            debug_info['download_test'] = {
                'test_file': test_file['filename'],
                'download_url': test_file['path'],
                'success': False,
                'error': None,
                'sample_content': None
            }
            
            try:
                trivy_content = nexus_client.download_trivy_report(test_file['path'])
                debug_info['download_test']['success'] = True
                
                # Analyze Trivy report content structure
                results = trivy_content.get('Results', [])
                schema_version = trivy_content.get('SchemaVersion', 'unknown')
                
                # Count total vulnerabilities across all results
                total_vulns = sum(len(result.get('Vulnerabilities', [])) for result in results)
                
                debug_info['download_test']['sample_content'] = {
                    'schemaVersion': schema_version,
                    'results_count': len(results),
                    'total_vulnerabilities': total_vulns,
                    'has_vulnerabilities': total_vulns > 0,
                    'has_metadata': 'Metadata' in trivy_content
                }
                
                # Analyze Trivy report and provide insights
                debug_info['trivy_analysis'] = {
                    'type': 'native-trivy-report',
                    'can_show_vulnerabilities': total_vulns > 0,
                    'results_summary': [
                        {
                            'target': result.get('Target', 'unknown'),
                            'type': result.get('Type', 'unknown'),
                            'vulnerability_count': len(result.get('Vulnerabilities', []))
                        } for result in results[:5]
                    ],
                    'format_info': {
                        'format': 'Native Trivy JSON',
                        'schema_version': schema_version,
                        'description': "Direct Trivy scan results in native JSON format"
                    }
                }
                
            except Exception as e:
                debug_info['download_test']['error'] = str(e)
        
    except Exception as e:
        debug_info['error_message'] = str(e)
        logger.error(f"❌ Debug endpoint error: {str(e)}")
    
    return jsonify(debug_info)

@app.route('/')
def dashboard():
    """Main dashboard view"""
    logger.info("🏠 Rendering main dashboard")
    
    # Calculate summary statistics
    total_projects = len(app_data['projects'])
    total_scans = len(app_data['scans'])
    total_vulnerabilities = sum(p['total_vulnerabilities'] for p in app_data['projects'].values())
    
    # Critical issues (projects with critical vulnerabilities)
    critical_projects = [p for p in app_data['projects'].values() if p['critical_count'] > 0]
    
    # Recent scans (last 24 hours)
    recent_scans = []
    if app_data['last_updated']:
        cutoff_time = datetime.now() - timedelta(hours=24)
        recent_scans = [
            s for s in app_data['scans'].values() 
            if s['timestamp'] > cutoff_time
        ]
    
    return render_template('dashboard.html',
        total_projects=total_projects,
        total_scans=total_scans,
        total_vulnerabilities=total_vulnerabilities,
        critical_projects=len(critical_projects),
        recent_scans=len(recent_scans),
        last_updated=format_timestamp(app_data['last_updated']),
        is_loading=app_data['is_loading']
    )

@app.route('/projects')
def projects():
    """Projects overview page"""
    logger.info("📁 Rendering projects page")
    
    # Sort projects by risk score (highest first)
    sorted_projects = sorted(
        app_data['projects'].values(),
        key=lambda x: x['risk_score'],
        reverse=True
    )
    
    return render_template('projects.html',
        projects=sorted_projects,
        last_updated=format_timestamp(app_data['last_updated'])
    )

@app.route('/project/<project_name>')
def project_detail(project_name):
    """Individual project details with pagination"""
    logger.info(f"📊 Rendering project detail for: {project_name}")
    
    if project_name not in app_data['projects']:
        return "Project not found", 404
    
    project = app_data['projects'][project_name]
    
    # Get scan history for this project
    project_scans = [
        app_data['scans'][scan_id] for scan_id in project['scans']
    ]
    project_scans.sort(key=lambda x: x['timestamp'] if x['timestamp'] else datetime.min, reverse=True)
    
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', Config.DEFAULT_PAGE_SIZE, type=int)
    
    # Calculate pagination
    total_scans = len(project_scans)
    total_pages = (total_scans + per_page - 1) // per_page
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    
    # Get scans for current page
    paginated_scans = project_scans[start_idx:end_idx]
    
    logger.info(f"📊 Project scans: Total={total_scans}, Page={page}/{total_pages}, Showing={len(paginated_scans)}")
    
    # Calculate trend data for current page only
    trend_data = analytics.calculate_vulnerability_trends(paginated_scans)
    
    # Check for DEBUG_DASHBOARD environment variable
    debug_mode = os.environ.get('DEBUG_DASHBOARD', '').lower() in ('true', '1', 'yes', 'on')
    
    return render_template('project.html',
        project=project,
        scans=paginated_scans,
        trend_data=trend_data,
        debug_mode=debug_mode,
        page=page,
        per_page=per_page,
        total_scans=total_scans,
        total_pages=total_pages
    )

@app.route('/scan/<scan_id>')
def scan_detail(scan_id):
    """Individual scan details with pagination"""
    logger.info(f"🔍 Rendering scan detail for: {scan_id}")
    
    # Try to get scan from in-memory cache first, then disk cache
    scan = None
    if scan_id in app_data['scans']:
        scan = app_data['scans'][scan_id]
    else:
        # Load from disk cache
        scan = disk_cache.load_scan(scan_id)
        if scan:
            app_data['scans'][scan_id] = scan
        else:
            return "Scan not found", 404
    
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    severity_filter = request.args.get('severity', '').upper()
    cve_search = request.args.get('cve_search', '').strip().upper()
    
    # Filter vulnerabilities by severity if specified
    vulnerabilities = scan['vulnerabilities']
    if severity_filter and severity_filter in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        vulnerabilities = [v for v in vulnerabilities if v.get('severity', '').upper() == severity_filter]
    
    # Filter vulnerabilities by CVE if specified
    if cve_search:
        vulnerabilities = [v for v in vulnerabilities if cve_search in v.get('id', '').upper()]
    
    # Calculate pagination
    total_vulns = len(vulnerabilities)
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    paginated_vulns = vulnerabilities[start_idx:end_idx]
    
    # Calculate pagination info
    total_pages = (total_vulns + per_page - 1) // per_page
    has_prev = page > 1
    has_next = page < total_pages
    
    # Group vulnerabilities by severity (for summary cards)
    vuln_by_severity = analytics.group_vulnerabilities_by_severity(scan['vulnerabilities'])
    
    # Calculate risk score for this scan
    risk_score = analytics.calculate_risk_score(scan['vulnerabilities'])
    
    # Get component analysis
    component_analysis = analytics.analyze_components(scan['components'])
    
    # Add calculated fields to scan data for template
    scan_with_calculated = scan.copy()
    scan_with_calculated['risk_score'] = risk_score
    scan_with_calculated['vulnerabilities_paginated'] = paginated_vulns
    
    return render_template('scan.html',
        scan=scan_with_calculated,
        vulnerabilities_by_severity=vuln_by_severity,
        component_analysis=component_analysis,
        # Pagination info
        page=page,
        per_page=per_page,
        total_vulns=total_vulns,
        total_pages=total_pages,
        has_prev=has_prev,
        has_next=has_next,
        severity_filter=severity_filter.lower() if severity_filter else '',
        cve_search=cve_search
    )

@app.route('/scan/<scan_id>/vulnerability/<vuln_id>')
def vulnerability_detail(scan_id, vuln_id):
    """Individual vulnerability details with SBOM information from Trivy report"""
    logger.info(f"🔍 Rendering vulnerability detail for: {vuln_id} in scan: {scan_id}")
    
    # Try to get scan from in-memory cache first, then disk cache
    scan = None
    if scan_id in app_data['scans']:
        scan = app_data['scans'][scan_id]
    else:
        # Load from disk cache
        scan = disk_cache.load_scan(scan_id)
        if scan:
            app_data['scans'][scan_id] = scan
        else:
            return "Scan not found", 404
    
    # Find the vulnerability
    vulnerability = None
    for vuln in scan['vulnerabilities']:
        if vuln.get('id') == vuln_id:
            vulnerability = vuln
            break
    
    if not vulnerability:
        return "Vulnerability not found", 404
    
    # Try to enrich with merged SBOM data (license + copyright info from CycloneDX)
    try:
        # Get the Trivy report path from scan metadata
        trivy_report_path = scan.get('trivy_report_path')
        
        if trivy_report_path:
            logger.debug(f"Loading Trivy data from: {trivy_report_path}")
            
            # Fetch Trivy data
            trivy_content = nexus_client.download_trivy_report(trivy_report_path)
            
            # Try to fetch CycloneDX if available (same path, without -trivy-report suffix)
            cyclonedx_content = None
            try:
                logger.debug(f"Attempting to load CycloneDX SBOM from same folder...")
                cyclonedx_content = nexus_client.download_cyclonedx_sbom(trivy_report_path)
            except Exception as e:
                logger.debug(f"CycloneDX SBOM not found or error: {str(e)}")
            
            if trivy_content and cyclonedx_content:
                # Merge data sources
                logger.debug(f"Merging Trivy + CycloneDX data for vulnerability enrichment")
                hybrid_parser = HybridSBOMParser(trivy_content, cyclonedx_content)
                
                # Get component info with license
                pkg_name = vulnerability.get('properties', {}).get('package_name')
                version = vulnerability.get('properties', {}).get('installed_version')
                
                if pkg_name and version:
                    component_info = hybrid_parser.get_component_sbom(pkg_name, version)
                    
                    if component_info:
                        logger.debug(f"Found component info for {pkg_name}:{version}")
                        vulnerability['license_info'] = {
                            'concluded': component_info.get('licenseConcluded'),
                            'declared': component_info.get('licenseDeclared'),
                            'comments': component_info.get('licenseComments'),
                            'copyright': component_info.get('copyrightText'),
                            'supplier': component_info.get('supplier'),
                        }
    except Exception as e:
        logger.debug(f"Could not enrich vulnerability with merged SBOM data: {str(e)}")
    
    return render_template('vulnerability_details.html',
        scan=scan,
        vulnerability=vulnerability
    )

@app.route('/api/dashboard/summary')
def api_dashboard_summary():
    """API endpoint for dashboard summary data"""
    logger.info("🔌 API: Dashboard summary requested")
    
    summary = {
        'total_projects': len(app_data['projects']),
        'total_scans': len(app_data['scans']),
        'total_vulnerabilities': sum(p['total_vulnerabilities'] for p in app_data['projects'].values()),
        'last_updated': app_data['last_updated'].isoformat() if app_data['last_updated'] else None,
        'is_loading': app_data['is_loading']
    }
    
    return jsonify(summary)

@app.route('/api/projects')
def api_projects():
    """API endpoint for projects list"""
    logger.info("🔌 API: Projects list requested")
    
    projects_list = list(app_data['projects'].values())
    
    return jsonify({
        'projects': projects_list,
        'count': len(projects_list)
    })

@app.route('/api/project/<project_name>/charts')
def api_project_charts(project_name):
    """API endpoint for project chart data"""
    logger.info(f"🔌 API: Chart data requested for project: {project_name}")
    
    if project_name not in app_data['projects']:
        return jsonify({'error': 'Project not found'}), 404
    
    project = app_data['projects'][project_name]
    
    # Get scan history for charts
    project_scans = [
        app_data['scans'][scan_id] for scan_id in project['scans']
    ]
    project_scans.sort(key=lambda x: x['timestamp'] if x['timestamp'] else datetime.min)
    
    # Generate chart data
    chart_data = analytics.generate_chart_data(project_scans)
    
    return jsonify(chart_data)

@app.route('/api/vulnerabilities/top')
def api_top_vulnerabilities():
    """API endpoint for most common vulnerabilities"""
    logger.info("🔌 API: Top vulnerabilities requested")
    
    # Count vulnerability occurrences across all scans
    vuln_counts = {}
    for vuln_id, occurrences in app_data['vulnerabilities'].items():
        vuln_counts[vuln_id] = {
            'count': len(occurrences),
            'severity': occurrences[0]['details']['severity'],
            'description': occurrences[0]['details'].get('description', 'N/A'),
            'projects_affected': len(set(occ['project'] for occ in occurrences))
        }
    
    # Sort by count and return top 20
    top_vulns = sorted(
        vuln_counts.items(),
        key=lambda x: x[1]['count'],
        reverse=True
    )[:20]
    
    return jsonify({
        'vulnerabilities': [
            {
                'id': vuln_id,
                'count': data['count'],
                'severity': data['severity'],
                'description': data['description'],
                'projects_affected': data['projects_affected']
            }
            for vuln_id, data in top_vulns
        ]
    })

@app.route('/api/metrics/trends')
def api_metrics_trends():
    """API endpoint for security metrics trends"""
    logger.info("🔌 API: Metrics trends requested")
    
    # Calculate trends across all projects
    all_scans = list(app_data['scans'].values())
    all_scans.sort(key=lambda x: x['timestamp'] if x['timestamp'] else datetime.min)
    
    trends = analytics.calculate_security_trends(all_scans)
    
    return jsonify(trends)

@app.route('/refresh')
def manual_refresh():
    """Manual data refresh endpoint"""
    logger.info("🔄 Manual data refresh requested")
    
    # Set force refresh flag and trigger the refresh event to interrupt sleep
    app_data['force_refresh'] = True
    refresh_event.set()  # Signal the background thread to wake up immediately
    logger.info("✅ Force refresh triggered - background thread awakened immediately")
        
    return jsonify({
        'status': 'refresh_triggered',
        'is_loading': app_data['is_loading'],
        'last_updated': app_data['last_updated'].isoformat() if app_data['last_updated'] else None
    })

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    cache_stats = disk_cache.get_cache_stats()
    
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'artifactory_type': Config.ARTIFACTORY_TYPE,
        'artifactory_connection': nexus_client.test_connection(),
        'data_available': len(app_data['projects']) > 0,
        'cache': cache_stats
    })

@app.route('/api/cache/stats')
def cache_stats():
    """Get detailed cache statistics"""
    logger.info("📊 Cache statistics requested")
    
    stats = disk_cache.get_cache_stats()
    
    return jsonify({
        'status': 'success',
        'timestamp': datetime.now().isoformat(),
        'cache': stats,
        'app_data': {
            'projects_in_memory': len(app_data['projects']),
            'scans_in_memory': len(app_data['scans']),
            'last_updated': app_data['last_updated'].isoformat() if app_data['last_updated'] else None
        }
    })

@app.route('/api/sbom-analysis')
def sbom_analysis():
    """API endpoint for analyzing SBOM content types and capabilities"""
    logger.info("📊 SBOM Analysis requested")
    
    analysis = {
        'total_projects': len(app_data['projects']),
        'projects_with_vulnerabilities': 0,
        'projects_component_only': 0,
        'projects_detail': [],
        'recommendations': [],
        'trivy_commands': {}
    }
    
    for project_name, project_data in app_data['projects'].items():
        project_analysis = {
            'name': project_name,
            'total_scans': len(project_data.get('scans', [])),
            'has_vulnerabilities': project_data.get('total_vulnerabilities', 0) > 0,
            'component_count': project_data.get('component_count', 0),
            'latest_scan': project_data.get('last_scan', 'unknown'),
            'sbom_type': 'vulnerability-enhanced' if project_data.get('total_vulnerabilities', 0) > 0 else 'component-only'
        }
        
        if project_analysis['has_vulnerabilities']:
            analysis['projects_with_vulnerabilities'] += 1
        else:
            analysis['projects_component_only'] += 1
            
        analysis['projects_detail'].append(project_analysis)
    
    # Generate recommendations based on analysis
    if analysis['projects_component_only'] > 0:
        analysis['recommendations'].append({
            'type': 'vulnerability_scanning',
            'title': 'Enhance SBOMs with Vulnerability Data',
            'description': f"You have {analysis['projects_component_only']} projects with component-only SBOMs. Consider generating vulnerability-enhanced SBOMs using Trivy.",
            'priority': 'high',
            'action': 'Run Trivy vulnerability scanning on your images/repositories'
        })
        
        # Generate Trivy commands for different scenarios
        analysis['trivy_commands'] = {
            'container_image': {
                'command': 'trivy image --format cyclonedx --output enhanced-sbom.json your-image:tag',
                'description': 'Scan container image and generate vulnerability-enhanced SBOM'
            },
            'filesystem': {
                'command': 'trivy fs --format cyclonedx --output enhanced-sbom.json /path/to/project',
                'description': 'Scan filesystem/repository and generate vulnerability-enhanced SBOM'
            },
            'repository': {
                'command': 'trivy repo --format cyclonedx --output enhanced-sbom.json https://github.com/your/repo',
                'description': 'Scan Git repository and generate vulnerability-enhanced SBOM'
            },
            'upload_to_nexus': {
                'command': 'curl -u user:pass -X PUT "http://nexus:8081/repository/mccamish_sbom/com/mccamish/project.sbom/1.0.0-$(date +%Y%m%d%H%M%S)/project.sbom-1.0.0-$(date +%Y%m%d%H%M%S).json" --upload-file enhanced-sbom.json',
                'description': 'Upload enhanced SBOM to McCamish Nexus repository'
            }
        }
    
    if analysis['projects_with_vulnerabilities'] == 0:
        analysis['recommendations'].append({
            'type': 'no_vulnerabilities',
            'title': 'No Vulnerability Data Found',
            'description': 'None of your SBOM files contain vulnerability information. This dashboard is designed to show security insights from vulnerability-enhanced SBOMs.',
            'priority': 'critical',
            'action': 'Generate new SBOMs with Trivy vulnerability scanning enabled'
        })
    
    return jsonify(analysis)

@app.route('/scan/<scan_id>/sbom/details')
def sbom_details(scan_id):
    """SBOM details view with comprehensive package information"""
    logger.info(f"📋 Rendering SBOM details for scan: {scan_id}")
    
    if scan_id not in app_data['scans']:
        return "Scan not found", 404
    
    scan = app_data['scans'][scan_id]
    
    try:
        # Get the Trivy report path from scan metadata
        trivy_report_path = scan.get('trivy_report_path')
        
        if not trivy_report_path:
            return "Trivy report path not found in scan metadata", 400
        
        logger.debug(f"Loading Trivy data from: {trivy_report_path}")
        
        # Fetch Trivy data
        trivy_content = nexus_client.download_trivy_report(trivy_report_path)
        
        # Try to fetch CycloneDX if available (same path, without -trivy-report suffix)
        cyclonedx_content = None
        try:
            logger.debug(f"Attempting to load CycloneDX SBOM from same folder...")
            cyclonedx_content = nexus_client.download_cyclonedx_sbom(trivy_report_path)
        except Exception as e:
            logger.debug(f"CycloneDX SBOM not found or error: {str(e)}")
        
        # Always try to use comprehensive parser for the best data
        from services.comprehensive_sbom_parser import ComprehensiveSBOMParser
        
        if cyclonedx_content:
            # Use comprehensive parser with both data sources
            logger.debug(f"Using comprehensive SBOM parser with Trivy + CycloneDX data")
            comprehensive_parser = ComprehensiveSBOMParser(trivy_content, cyclonedx_content)
            sbom_data = comprehensive_parser.get_comprehensive_sbom_details()
        else:
            # Use comprehensive parser with Trivy only (will create empty CycloneDX structure)
            logger.debug(f"Using comprehensive SBOM parser with Trivy-only data")
            empty_cyclonedx = {'components': []}
            comprehensive_parser = ComprehensiveSBOMParser(trivy_content, empty_cyclonedx)
            sbom_data = comprehensive_parser.get_comprehensive_sbom_details()
        
        # Enhance scan info
        sbom_data['scan_info'] = {
            'scan_id': scan_id,
            'scan_date': scan.get('timestamp', '').strftime('%Y-%m-%d %H:%M:%S') if scan.get('timestamp') else 'Unknown'
        }
        
        return render_template('sbom_details.html',
            scan=scan,
            sbom=sbom_data
        )
        
    except Exception as e:
        logger.error(f"Error generating SBOM details: {str(e)}")
        return render_template('error.html',
            error_message=f"Error generating SBOM details: {str(e)}"), 500

@app.route('/scan/<scan_id>/sbom/export')
def export_sbom_spdx_json(scan_id):
    """Export SBOM as SPDX JSON format"""
    logger.info(f"📤 Export SBOM as SPDX JSON for scan: {scan_id}")
    
    if scan_id not in app_data['scans']:
        return jsonify({'error': 'Scan not found'}), 404
    
    scan = app_data['scans'][scan_id]
    trivy_report_path = scan.get('trivy_report_path')
    
    if not trivy_report_path:
        return jsonify({'error': 'Trivy report path not found in scan metadata'}), 400
    
    try:
        # Fetch Trivy data
        logger.debug(f"Fetching Trivy data from: {trivy_report_path}")
        trivy_content = nexus_client.download_trivy_report(trivy_report_path)
        
        # Try to fetch CycloneDX from same path (without -trivy-report suffix)
        cyclonedx_content = None
        try:
            logger.debug(f"Attempting to fetch CycloneDX SBOM...")
            cyclonedx_content = nexus_client.download_cyclonedx_sbom(trivy_report_path)
        except Exception as e:
            logger.debug(f"CycloneDX not available: {str(e)}")
        
        # Generate SPDX using comprehensive parser
        from services.comprehensive_sbom_parser import ComprehensiveSBOMParser
        
        if cyclonedx_content:
            # Use comprehensive parser with both data sources
            logger.debug(f"Using comprehensive SBOM parser with Trivy + CycloneDX data")
            comprehensive_parser = ComprehensiveSBOMParser(trivy_content, cyclonedx_content)
            filename = f"{scan['project']}-{scan['build_number']}-merged-sbom.spdx"
        else:
            # Use comprehensive parser with Trivy only
            logger.debug(f"Using comprehensive SBOM parser with Trivy-only data")
            empty_cyclonedx = {'components': []}
            comprehensive_parser = ComprehensiveSBOMParser(trivy_content, empty_cyclonedx)
            filename = f"{scan['project']}-{scan['build_number']}-trivy-sbom.spdx"
        
        # Export to SPDX format (text format, not JSON)
        spdx_output = comprehensive_parser.export_to_spdx_format()
        
        return Response(
            spdx_output,
            mimetype='text/plain',
            headers={'Content-Disposition': f'attachment; filename={filename}'}
        )
    
    except Exception as e:
        logger.error(f"Error exporting SBOM: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/scan/<scan_id>/sbom/export/json')
def export_sbom_json(scan_id):
    """Export SBOM as regular JSON format"""
    logger.info(f"📤 Export SBOM as JSON for scan: {scan_id}")
    
    if scan_id not in app_data['scans']:
        return jsonify({'error': 'Scan not found'}), 404
    
    scan = app_data['scans'][scan_id]
    trivy_report_path = scan.get('trivy_report_path')
    
    if not trivy_report_path:
        return jsonify({'error': 'Trivy report path not found in scan metadata'}), 400
    
    try:
        # Fetch Trivy data and return as formatted JSON
        logger.debug(f"Fetching Trivy data from: {trivy_report_path}")
        trivy_content = nexus_client.download_trivy_report(trivy_report_path)
        
        filename = f"{scan['project']}-{scan['build_number']}-trivy-report.json"
        
        return Response(
            json.dumps(trivy_content, indent=2),
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment; filename={filename}'}
        )
    
    except Exception as e:
        logger.error(f"Error exporting JSON: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/components')
def component_analysis():
    """Component analysis view for SBOM files"""
    logger.info("🧩 Rendering component analysis page")
    
    # Calculate summary statistics
    total_projects = len(app_data['projects'])
    
    return render_template('component_analysis.html',
        total_projects=total_projects,
        last_updated=format_timestamp(app_data['last_updated']) if app_data['last_updated'] else None
    )

def _convert_trivy_to_packages(trivy_data):
    """Convert Trivy data to package format for SBOM details"""
    logger.debug(f"Converting Trivy data to packages...")
    packages = []
    packages_dict = {}  # To avoid duplicates and collect vulnerabilities
    
    results = trivy_data.get('Results', [])
    logger.debug(f"Processing {len(results)} results from Trivy report")
    
    for result in results:
        target = result.get('Target', 'Unknown')
        vulnerabilities = result.get('Vulnerabilities', [])
        logger.debug(f"Result target: {target}, vulnerabilities: {len(vulnerabilities)}")
        
        # Process vulnerabilities first to get package info
        for vuln in vulnerabilities:
            pkg_name = vuln.get('PkgName', 'Unknown')
            pkg_version = vuln.get('InstalledVersion', 'Unknown')
            pkg_id = vuln.get('PkgID', f"{pkg_name}@{pkg_version}")
            
            # Create unique package key
            pkg_key = f"{pkg_name}:{pkg_version}"
            
            # Initialize package if not exists
            if pkg_key not in packages_dict:
                packages_dict[pkg_key] = {
                    'name': pkg_name,
                    'version': pkg_version,
                    'spdx_id': f"SPDXRef-Package-{pkg_name.replace(':', '-').replace('/', '-')}-{pkg_version.replace(':', '-').replace('/', '-')}",
                    'pkg_id': pkg_id,
                    'license_concluded': 'NOASSERTION',
                    'license_declared': 'NOASSERTION',
                    'copyright_text': 'NOASSERTION',
                    'supplier': 'NOASSERTION',
                    'primary_purpose': 'LIBRARY',
                    'component_type': 'library',
                    'download_location': vuln.get('PkgIdentifier', {}).get('PURL', 'NOASSERTION'),
                    'verification_code': _generate_verification_code(pkg_name, pkg_version),
                    'description': f"Package from {target}",
                    'vulnerabilities': [],
                    'external_refs': []
                }
                
                # Add PURL external reference if available
                purl = vuln.get('PkgIdentifier', {}).get('PURL')
                if purl:
                    packages_dict[pkg_key]['external_refs'].append({
                        'category': 'PACKAGE-MANAGER',
                        'locator': purl
                    })
            
            # Add vulnerability to package
            packages_dict[pkg_key]['vulnerabilities'].append({
                'id': vuln.get('VulnerabilityID', 'Unknown'),
                'severity': vuln.get('Severity', 'UNKNOWN'),
                'title': vuln.get('Title', 'No title available'),
                'description': vuln.get('Description', 'No description available'),
                'fixed_version': vuln.get('FixedVersion', 'N/A'),
                'primary_url': vuln.get('PrimaryURL', '#')
            })
    
    # Convert to list
    packages = list(packages_dict.values())
    logger.debug(f"Final package count: {len(packages)}")
    
    if packages:
        logger.debug(f"Sample package: {packages[0]['name']}:{packages[0]['version']}")
    
    # Sort packages by name for consistent display
    packages.sort(key=lambda x: x['name'])
    
    return packages

def _get_trivy_vulnerability_summary(trivy_data):
    """Get vulnerability summary from Trivy data"""
    vuln_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
    total_vulns = 0
    
    for result in trivy_data.get('Results', []):
        for vuln in result.get('Vulnerabilities', []):
            severity = vuln.get('Severity', 'UNKNOWN')
            if severity in vuln_counts:
                vuln_counts[severity] += 1
            total_vulns += 1
    
    return {
        'total_vulnerabilities': total_vulns,
        'by_severity': vuln_counts
    }

def _calculate_trivy_statistics(trivy_data):
    """Calculate statistics from Trivy data"""
    total_packages = 0
    packages_with_vulns = 0
    
    for result in trivy_data.get('Results', []):
        packages = result.get('Packages', [])
        total_packages += len(packages)
        
        # Count packages with vulnerabilities
        vuln_package_names = set()
        for vuln in result.get('Vulnerabilities', []):
            if vuln.get('PkgName'):
                vuln_package_names.add(vuln.get('PkgName'))
        
        packages_with_vulns += len(vuln_package_names)
    
    return {
        'total_packages': total_packages,
        'packages_with_vulnerabilities': packages_with_vulns,
        'packages_with_licenses': 0,  # No license info in Trivy reports
        'license_coverage_percentage': 0,
        'license_distribution': {}
    }

def _generate_verification_code(name, version):
    """Generate a simple verification code for a package"""
    import hashlib
    return hashlib.sha256(f"{name}:{version}".encode()).hexdigest()[:16]

def _convert_trivy_to_spdx_json(trivy_data, scan):
    """Convert Trivy data to SPDX JSON format"""
    import uuid
    from datetime import datetime
    
    packages = _convert_trivy_to_packages(trivy_data)
    
    # Generate document namespace
    document_namespace = f"http://trivy.dev/{scan['project']}/{scan['build_number']}-{str(uuid.uuid4())}"
    
    spdx_doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{scan['project']}-{scan['build_number']}-SBOM",
        "documentNamespace": document_namespace,
        "creationInfo": {
            "created": datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ'),
            "creators": ["Tool: trivy-dashboard"],
            "licenseListVersion": "3.21"
        },
        "packages": [],
        "relationships": []
    }
    
    # Add root package
    root_package = {
        "SPDXID": "SPDXRef-RootPackage",
        "name": scan['project'],
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION", 
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION"
    }
    spdx_doc["packages"].append(root_package)
    
    # Add dependency packages
    for pkg in packages:
        spdx_package = {
            "SPDXID": pkg['spdx_id'],
            "name": pkg['name'],
            "versionInfo": pkg['version'],
            "downloadLocation": pkg['download_location'],
            "filesAnalyzed": False,
            "licenseConcluded": pkg['license_concluded'],
            "licenseDeclared": pkg['license_declared'],
            "copyrightText": pkg['copyright_text'],
            "supplier": pkg['supplier'],
            "primaryPackagePurpose": pkg['primary_purpose']
        }
        
        # Add external references
        if pkg['external_refs']:
            spdx_package["externalRefs"] = [
                {
                    "referenceCategory": ref['category'],
                    "referenceLocator": ref['locator'],
                    "referenceType": "purl"
                } for ref in pkg['external_refs']
            ]
        
        spdx_doc["packages"].append(spdx_package)
        
        # Add relationship
        spdx_doc["relationships"].append({
            "spdxElementId": "SPDXRef-RootPackage",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": pkg['spdx_id']
        })
    
    return spdx_doc


# ============================================================================
# PDF Report Export API
# ============================================================================

@app.route('/api/report/projects/pdf')
def export_projects_pdf():
    """
    Export projects summary as PDF report with all branches/environments.
    
    Query Parameters:
        timezone: Timezone for date display (default: 'Asia/Kolkata' for IST)
                  Examples: 'America/New_York', 'Europe/London', 'UTC'
    
    Returns:
        PDF file download with projects summary including all branch details
    """
    import io
    import pytz
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, mm
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    
    logger.info("📄 Generating PDF report for projects")
    
    # Get timezone parameter (default to IST)
    tz_name = request.args.get('timezone', 'Asia/Kolkata')
    try:
        tz = pytz.timezone(tz_name)
    except pytz.exceptions.UnknownTimeZoneError:
        logger.warning(f"⚠️ Unknown timezone: {tz_name}, using Asia/Kolkata")
        tz = pytz.timezone('Asia/Kolkata')
    
    # Helper function to format datetime in specified timezone
    def format_datetime_tz(dt, timezone):
        if dt is None:
            return "Never"
        try:
            if dt.tzinfo is None:
                dt = pytz.UTC.localize(dt)
            local_dt = dt.astimezone(timezone)
            return local_dt.strftime('%Y-%m-%d %H:%M:%S %Z')
        except Exception as e:
            logger.warning(f"⚠️ Error formatting datetime: {e}")
            return str(dt)
    
    # Create PDF buffer
    buffer = io.BytesIO()
    
    # Create PDF document in landscape mode for better table fit
    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        rightMargin=15*mm,
        leftMargin=15*mm,
        topMargin=15*mm,
        bottomMargin=15*mm
    )
    
    # Styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=TA_CENTER,
        textColor=colors.HexColor('#1a237e')
    )
    subtitle_style = ParagraphStyle(
        'CustomSubtitle',
        parent=styles['Normal'],
        fontSize=12,
        spaceAfter=20,
        alignment=TA_CENTER,
        textColor=colors.HexColor('#666666')
    )
    header_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontSize=8,
        textColor=colors.white,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    cell_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontSize=7,
        alignment=TA_LEFT
    )
    cell_center_style = ParagraphStyle(
        'TableCellCenter',
        parent=styles['Normal'],
        fontSize=7,
        alignment=TA_CENTER
    )
    project_name_style = ParagraphStyle(
        'ProjectName',
        parent=styles['Normal'],
        fontSize=8,
        alignment=TA_LEFT,
        fontName='Helvetica-Bold'
    )
    branch_style = ParagraphStyle(
        'BranchCell',
        parent=styles['Normal'],
        fontSize=7,
        alignment=TA_LEFT,
        leftIndent=10
    )
    
    # Build PDF content
    elements = []
    
    # Title
    elements.append(Paragraph("Security Vulnerability Report", title_style))
    
    # Subtitle with generation time
    report_time = datetime.now()
    report_time_tz = pytz.UTC.localize(report_time).astimezone(tz)
    elements.append(Paragraph(
        f"Generated on: {report_time_tz.strftime('%Y-%m-%d %H:%M:%S %Z')}<br/>Timezone: {tz_name}",
        subtitle_style
    ))
    
    # Summary section - Calculate totals from latest scan of each branch/environment
    total_projects = len(app_data['projects'])
    total_critical = 0
    total_high = 0
    total_medium = 0
    total_low = 0
    total_environments = 0
    
    # For each project, find latest scan per branch and sum up vulnerabilities
    for project in app_data['projects'].values():
        project_scans = [app_data['scans'].get(scan_id) for scan_id in project.get('scans', [])]
        project_scans = [s for s in project_scans if s is not None]
        
        # Group scans by branch and get latest for each
        branch_latest = {}
        for scan in project_scans:
            branch = scan.get('branch_name') or 'not provided'
            scan_timestamp = scan.get('timestamp') or datetime.min
            
            if branch not in branch_latest:
                branch_latest[branch] = scan
            else:
                existing_timestamp = branch_latest[branch].get('timestamp') or datetime.min
                if scan_timestamp > existing_timestamp:
                    branch_latest[branch] = scan
        
        total_environments += len(branch_latest)
        
        # Sum vulnerabilities from latest scan of each branch only
        for latest_scan in branch_latest.values():
            vulns = latest_scan.get('vulnerabilities', [])
            total_critical += len([v for v in vulns if v.get('severity', '').upper() == 'CRITICAL'])
            total_high += len([v for v in vulns if v.get('severity', '').upper() == 'HIGH'])
            total_medium += len([v for v in vulns if v.get('severity', '').upper() == 'MEDIUM'])
            total_low += len([v for v in vulns if v.get('severity', '').upper() == 'LOW'])
    
    summary_data = [
        ['Total Projects', 'Environments', 'Critical', 'High', 'Medium', 'Low'],
        [str(total_projects), str(total_environments), str(total_critical), str(total_high), str(total_medium), str(total_low)]
    ]
    
    summary_table = Table(summary_data, colWidths=[80, 70, 60, 60, 60, 60])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a237e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('FONTSIZE', (0, 1), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
        ('TOPPADDING', (0, 1), (-1, -1), 8),
        ('BACKGROUND', (1, 1), (1, 1), colors.HexColor('#e8f5e9')),  # Environments - light green
        ('BACKGROUND', (2, 1), (2, 1), colors.HexColor('#ffebee')),  # Critical - light red
        ('BACKGROUND', (3, 1), (3, 1), colors.HexColor('#fff3e0')),  # High - light orange
        ('BACKGROUND', (4, 1), (4, 1), colors.HexColor('#e3f2fd')),  # Medium - light blue
        ('BACKGROUND', (5, 1), (5, 1), colors.HexColor('#e8f5e9')),  # Low - light green
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#cccccc')),
    ]))
    
    elements.append(summary_table)
    elements.append(Spacer(1, 30))
    
    # Projects table header
    elements.append(Paragraph("Projects Overview (with Branch/Environment Details)", styles['Heading2']))
    elements.append(Spacer(1, 10))
    
    # Sort projects by risk score (highest first)
    sorted_projects = sorted(
        app_data['projects'].values(),
        key=lambda x: x.get('risk_score', 0),
        reverse=True
    )
    
    # Build projects table data with sub-rows for each branch
    table_data = [[
        Paragraph('Project Name', header_style),
        Paragraph('Critical', header_style),
        Paragraph('High', header_style),
        Paragraph('Medium', header_style),
        Paragraph('Low', header_style),
        Paragraph('Total', header_style),
        Paragraph('Latest Scan Date', header_style)
    ]]
    
    # Track row indices for styling
    row_styles = []  # List of (row_index, is_project_row, critical_count, high_count)
    current_row = 1
    
    for project in sorted_projects:
        project_name = project.get('name', 'Unknown')
        
        # Get all scans for this project
        project_scans = [app_data['scans'].get(scan_id) for scan_id in project.get('scans', [])]
        project_scans = [s for s in project_scans if s is not None]
        
        # Group scans by branch/environment and get latest for each
        branch_latest_scans = {}
        for scan in project_scans:
            branch = scan.get('branch_name') or 'not provided'
            scan_timestamp = scan.get('timestamp') or datetime.min
            
            if branch not in branch_latest_scans:
                branch_latest_scans[branch] = scan
            else:
                existing_timestamp = branch_latest_scans[branch].get('timestamp') or datetime.min
                if scan_timestamp > existing_timestamp:
                    branch_latest_scans[branch] = scan
        
        branch_count = len(branch_latest_scans)
        
        # Calculate totals from latest scan of each branch
        proj_critical = 0
        proj_high = 0
        proj_medium = 0
        proj_low = 0
        proj_total = 0
        latest_scan_time = None
        
        for branch_scan in branch_latest_scans.values():
            vulns = branch_scan.get('vulnerabilities', [])
            proj_critical += len([v for v in vulns if v.get('severity', '').upper() == 'CRITICAL'])
            proj_high += len([v for v in vulns if v.get('severity', '').upper() == 'HIGH'])
            proj_medium += len([v for v in vulns if v.get('severity', '').upper() == 'MEDIUM'])
            proj_low += len([v for v in vulns if v.get('severity', '').upper() == 'LOW'])
            proj_total += len(vulns)
            scan_time = branch_scan.get('timestamp')
            if scan_time and (latest_scan_time is None or scan_time > latest_scan_time):
                latest_scan_time = scan_time
        
        # Add project main row (totals from latest scan of each branch)
        project_row = [
            Paragraph(f"<b>{project_name[:40]}</b>" + (f" ({branch_count})" if branch_count > 1 else ""), project_name_style),
            Paragraph(f"<b>{proj_critical}</b>", cell_center_style),
            Paragraph(f"<b>{proj_high}</b>", cell_center_style),
            Paragraph(f"<b>{proj_medium}</b>", cell_center_style),
            Paragraph(f"<b>{proj_low}</b>", cell_center_style),
            Paragraph(f"<b>{proj_total}</b>", cell_center_style),
            Paragraph(format_datetime_tz(latest_scan_time, tz), cell_style)
        ]
        table_data.append(project_row)
        row_styles.append((current_row, True, proj_critical, proj_high))
        current_row += 1
        
        # Add sub-rows for each branch/environment (using latest scan only)
        sorted_branches = sorted(branch_latest_scans.items(), 
                                  key=lambda x: x[1].get('timestamp') or datetime.min, 
                                  reverse=True)
        
        for branch_name, latest_scan in sorted_branches:
            # Calculate vulnerability counts for this branch's latest scan only
            vulns = latest_scan.get('vulnerabilities', [])
            branch_critical = len([v for v in vulns if v.get('severity', '').upper() == 'CRITICAL'])
            branch_high = len([v for v in vulns if v.get('severity', '').upper() == 'HIGH'])
            branch_medium = len([v for v in vulns if v.get('severity', '').upper() == 'MEDIUM'])
            branch_low = len([v for v in vulns if v.get('severity', '').upper() == 'LOW'])
            branch_total = len(vulns)
            
            branch_row = [
                Paragraph(f"↳ {branch_name}", branch_style),
                Paragraph(str(branch_critical), cell_center_style),
                Paragraph(str(branch_high), cell_center_style),
                Paragraph(str(branch_medium), cell_center_style),
                Paragraph(str(branch_low), cell_center_style),
                Paragraph(str(branch_total), cell_center_style),
                Paragraph(format_datetime_tz(latest_scan.get('timestamp'), tz), cell_style)
            ]
            table_data.append(branch_row)
            row_styles.append((current_row, False, branch_critical, branch_high))
            current_row += 1
    
    # Create projects table (without Risk Score column)
    col_widths = [170, 50, 50, 50, 50, 50, 125]
    projects_table = Table(table_data, colWidths=col_widths, repeatRows=1)
    
    # Table styling
    table_style = TableStyle([
        # Header styling
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a237e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 8),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('TOPPADDING', (0, 0), (-1, 0), 8),
        
        # Body styling
        ('ALIGN', (1, 1), (-2, -1), 'CENTER'),
        ('ALIGN', (0, 1), (0, -1), 'LEFT'),
        ('ALIGN', (-1, 1), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 7),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 4),
        ('TOPPADDING', (0, 1), (-1, -1), 4),
        
        # Grid
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
    ])
    
    # Add conditional styling for each row
    for row_idx, is_project, critical_count, high_count in row_styles:
        if is_project:
            # Project main row - slightly darker background
            table_style.add('BACKGROUND', (0, row_idx), (-1, row_idx), colors.HexColor('#e8eaf6'))
        else:
            # Branch sub-row - white background
            table_style.add('BACKGROUND', (0, row_idx), (-1, row_idx), colors.white)
        
        # Critical column highlighting (column index 1 after removing Risk Score)
        if critical_count > 0:
            table_style.add('BACKGROUND', (1, row_idx), (1, row_idx), colors.HexColor('#ffcdd2'))
        
        # High column highlighting (column index 2 after removing Risk Score)
        if high_count > 0:
            table_style.add('BACKGROUND', (2, row_idx), (2, row_idx), colors.HexColor('#ffe0b2'))
    
    projects_table.setStyle(table_style)
    elements.append(projects_table)
    
    # Footer
    elements.append(Spacer(1, 30))
    footer_style = ParagraphStyle(
        'Footer',
        parent=styles['Normal'],
        fontSize=8,
        alignment=TA_CENTER,
        textColor=colors.HexColor('#999999')
    )
    elements.append(Paragraph(
        f"Report generated by Trivy Security Dashboard | Data as of: {format_datetime_tz(app_data.get('last_updated'), tz)}",
        footer_style
    ))
    
    # Build PDF
    doc.build(elements)
    
    # Prepare response
    buffer.seek(0)
    
    # Generate filename with timestamp
    filename = f"security_report_{report_time.strftime('%Y%m%d_%H%M%S')}.pdf"
    
    logger.info(f"✅ PDF report generated: {filename}")
    
    return send_file(
        buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=filename
    )


@app.route('/api/report/projects/csv')
def export_projects_csv():
    """
    Export projects summary as CSV report with all branches/environments.
    
    Query Parameters:
        timezone: Timezone for date display (default: 'Asia/Kolkata' for IST)
                  Examples: 'America/New_York', 'Europe/London', 'UTC'
    
    Returns:
        CSV file download with projects summary including all branch details
    """
    import io
    import csv
    import pytz
    
    logger.info("📄 Generating CSV report for projects")
    
    # Get timezone parameter (default to IST)
    tz_name = request.args.get('timezone', 'Asia/Kolkata')
    try:
        tz = pytz.timezone(tz_name)
    except pytz.exceptions.UnknownTimeZoneError:
        logger.warning(f"⚠️ Unknown timezone: {tz_name}, using Asia/Kolkata")
        tz = pytz.timezone('Asia/Kolkata')
    
    # Helper function to format datetime in specified timezone
    def format_datetime_tz(dt, timezone):
        if dt is None:
            return "Never"
        try:
            if dt.tzinfo is None:
                dt = pytz.UTC.localize(dt)
            local_dt = dt.astimezone(timezone)
            return local_dt.strftime('%Y-%m-%d %H:%M:%S %Z')
        except Exception as e:
            logger.warning(f"⚠️ Error formatting datetime: {e}")
            return str(dt)
    
    # Create CSV buffer
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    
    # Report metadata
    report_time = datetime.now()
    report_time_tz = pytz.UTC.localize(report_time).astimezone(tz)
    
    writer.writerow(['Security Vulnerability Report'])
    writer.writerow([f'Generated on: {report_time_tz.strftime("%Y-%m-%d %H:%M:%S %Z")}'])
    writer.writerow([f'Timezone: {tz_name}'])
    writer.writerow([])  # Empty row
    
    # Summary section - Calculate totals from latest scan of each branch/environment
    total_projects = len(app_data['projects'])
    total_critical = 0
    total_high = 0
    total_medium = 0
    total_low = 0
    total_environments = 0
    
    # For each project, find latest scan per branch and sum up vulnerabilities
    for project in app_data['projects'].values():
        project_scans = [app_data['scans'].get(scan_id) for scan_id in project.get('scans', [])]
        project_scans = [s for s in project_scans if s is not None]
        
        # Group scans by branch and get latest for each
        branch_latest = {}
        for scan in project_scans:
            branch = scan.get('branch_name') or 'not provided'
            scan_timestamp = scan.get('timestamp') or datetime.min
            
            if branch not in branch_latest:
                branch_latest[branch] = scan
            else:
                existing_timestamp = branch_latest[branch].get('timestamp') or datetime.min
                if scan_timestamp > existing_timestamp:
                    branch_latest[branch] = scan
        
        total_environments += len(branch_latest)
        
        # Sum vulnerabilities from latest scan of each branch only
        for latest_scan in branch_latest.values():
            vulns = latest_scan.get('vulnerabilities', [])
            total_critical += len([v for v in vulns if v.get('severity', '').upper() == 'CRITICAL'])
            total_high += len([v for v in vulns if v.get('severity', '').upper() == 'HIGH'])
            total_medium += len([v for v in vulns if v.get('severity', '').upper() == 'MEDIUM'])
            total_low += len([v for v in vulns if v.get('severity', '').upper() == 'LOW'])
    
    # Summary section
    writer.writerow(['SUMMARY'])
    writer.writerow(['Total Projects', 'Environments', 'Critical', 'High', 'Medium', 'Low'])
    writer.writerow([total_projects, total_environments, total_critical, total_high, total_medium, total_low])
    writer.writerow([])  # Empty row
    
    # Projects table header
    writer.writerow(['PROJECTS OVERVIEW (with Branch/Environment Details)'])
    writer.writerow(['Project Name', 'Branch/Environment', 'Critical', 'High', 'Medium', 'Low', 'Total', 'Latest Scan Date'])
    
    # Sort projects by risk score (highest first)
    sorted_projects = sorted(
        app_data['projects'].values(),
        key=lambda x: x.get('risk_score', 0),
        reverse=True
    )
    
    for project in sorted_projects:
        project_name = project.get('name', 'Unknown')
        
        # Get all scans for this project
        project_scans = [app_data['scans'].get(scan_id) for scan_id in project.get('scans', [])]
        project_scans = [s for s in project_scans if s is not None]
        
        # Group scans by branch/environment and get latest for each
        branch_latest_scans = {}
        for scan in project_scans:
            branch = scan.get('branch_name') or 'not provided'
            scan_timestamp = scan.get('timestamp') or datetime.min
            
            if branch not in branch_latest_scans:
                branch_latest_scans[branch] = scan
            else:
                existing_timestamp = branch_latest_scans[branch].get('timestamp') or datetime.min
                if scan_timestamp > existing_timestamp:
                    branch_latest_scans[branch] = scan
        
        branch_count = len(branch_latest_scans)
        
        # Calculate totals from latest scan of each branch
        proj_critical = 0
        proj_high = 0
        proj_medium = 0
        proj_low = 0
        proj_total = 0
        latest_scan_time = None
        
        for branch_scan in branch_latest_scans.values():
            vulns = branch_scan.get('vulnerabilities', [])
            proj_critical += len([v for v in vulns if v.get('severity', '').upper() == 'CRITICAL'])
            proj_high += len([v for v in vulns if v.get('severity', '').upper() == 'HIGH'])
            proj_medium += len([v for v in vulns if v.get('severity', '').upper() == 'MEDIUM'])
            proj_low += len([v for v in vulns if v.get('severity', '').upper() == 'LOW'])
            proj_total += len(vulns)
            scan_time = branch_scan.get('timestamp')
            if scan_time and (latest_scan_time is None or scan_time > latest_scan_time):
                latest_scan_time = scan_time
        
        # Add project main row (totals from latest scan of each branch)
        project_display = f"{project_name}" + (f" ({branch_count} branches)" if branch_count > 1 else "")
        writer.writerow([
            project_display,
            'ALL BRANCHES (Total)',
            proj_critical,
            proj_high,
            proj_medium,
            proj_low,
            proj_total,
            format_datetime_tz(latest_scan_time, tz)
        ])
        
        # Add sub-rows for each branch/environment (using latest scan only)
        sorted_branches = sorted(branch_latest_scans.items(), 
                                  key=lambda x: x[1].get('timestamp') or datetime.min, 
                                  reverse=True)
        
        for branch_name, latest_scan in sorted_branches:
            # Calculate vulnerability counts for this branch's latest scan only
            vulns = latest_scan.get('vulnerabilities', [])
            branch_critical = len([v for v in vulns if v.get('severity', '').upper() == 'CRITICAL'])
            branch_high = len([v for v in vulns if v.get('severity', '').upper() == 'HIGH'])
            branch_medium = len([v for v in vulns if v.get('severity', '').upper() == 'MEDIUM'])
            branch_low = len([v for v in vulns if v.get('severity', '').upper() == 'LOW'])
            branch_total = len(vulns)
            
            writer.writerow([
                '',  # Empty for project name column (sub-row)
                f'  ↳ {branch_name}',
                branch_critical,
                branch_high,
                branch_medium,
                branch_low,
                branch_total,
                format_datetime_tz(latest_scan.get('timestamp'), tz)
            ])
    
    # Footer
    writer.writerow([])  # Empty row
    writer.writerow([f'Report generated by Trivy Security Dashboard | Data as of: {format_datetime_tz(app_data.get("last_updated"), tz)}'])
    
    # Prepare response
    output = buffer.getvalue()
    buffer.close()
    
    # Create bytes buffer for send_file
    bytes_buffer = io.BytesIO(output.encode('utf-8-sig'))  # utf-8-sig for Excel compatibility
    bytes_buffer.seek(0)
    
    # Generate filename with timestamp
    filename = f"security_report_{report_time.strftime('%Y%m%d_%H%M%S')}.csv"
    
    logger.info(f"✅ CSV report generated: {filename}")
    
    return send_file(
        bytes_buffer,
        mimetype='text/csv',
        as_attachment=True,
        download_name=filename
    )


@app.errorhandler(500)
def internal_error(error):
    """Handle internal server errors"""
    logger.error(f"❌ Internal server error: {str(error)}")
    return render_template('error.html', 
        error_message="Internal server error occurred"), 500

@app.errorhandler(404)
def not_found_error(error):
    """Handle not found errors"""
    logger.warning(f"⚠️ Page not found: {request.url}")
    return render_template('error.html',
        error_message="Page not found"), 404

if __name__ == '__main__':
    logger.info("🚀 Starting Trivy Security Dashboard")
    logger.info(f"🔗 Nexus URL: {Config.NEXUS_URL}")
    logger.info(f"� Repository: {Config.NEXUS_REPOSITORY}")
    logger.info(f"🏷️ Group ID: {Config.NEXUS_GROUP_ID}")
    logger.info(f"📄 Artifact Suffix: {Config.NEXUS_ARTIFACT_SUFFIX}")
    logger.info(f"�📊 Dashboard will be available at http://localhost:{Config.PORT}")
    logger.info(f"🔧 Debug endpoint: http://localhost:{Config.PORT}/debug/nexus")
    
    # Test initial connection
    logger.info(f"🔗 Testing {Config.ARTIFACTORY_TYPE.upper()} connection...")
    if nexus_client.test_connection():
        logger.info(f"✅ {Config.ARTIFACTORY_TYPE.upper()} connection successful")
    else:
        logger.warning(f"⚠️ {Config.ARTIFACTORY_TYPE.upper()} connection failed - check configuration")
    
    logger.info("📥 Background data refresh started...")
    
    app.run(
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.DEBUG,
        threaded=True
    )
