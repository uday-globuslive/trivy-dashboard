"""
Trivy Security Dashboard - Main Flask Application

This Flask application provides a comprehensive dashboard for visualizing
Trivy security scan results from native Trivy report JSON files stored in Nexus Repository.
"""

import os
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
import threading
import time

# Import our custom services
from services.nexus_client import NexusClient
from services.trivy_parser import TrivyReportParser
from services.analytics import SecurityAnalytics
from services.hybrid_sbom_parser import HybridSBOMParser
from utils.cache import CacheManager
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

# Initialize services
nexus_client = NexusClient(Config.NEXUS_URL, Config.NEXUS_USERNAME, Config.NEXUS_PASSWORD, Config.NEXUS_REPOSITORY)
trivy_parser = TrivyReportParser()
analytics = SecurityAnalytics()
cache_manager = CacheManager()

# Global data store (acts as in-memory database)
app_data = {
    'projects': {},
    'scans': {},
    'vulnerabilities': {},
    'last_updated': None,
    'is_loading': False
}

def refresh_data_background():
    """Background task to refresh data from Nexus"""
    while True:
        try:
            if not app_data['is_loading']:
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
                                'risk_score': 0
                            }
                        
                        # Store scan data
                        scan_data = {
                            'id': scan_id,
                            'project': project_name,
                            'build_number': trivy_file['build_number'],
                            'timestamp': trivy_file['timestamp'],
                            'trivy_report_path': trivy_file['path'],
                            'vulnerabilities': parsed_data['vulnerabilities'],
                            'components': parsed_data['components'],
                            'metadata': parsed_data['metadata']
                        }
                        
                        scans[scan_id] = scan_data
                        projects[project_name]['scans'].append(scan_id)
                        
                        # Update project statistics with latest scan only
                        vuln_counts = analytics.count_vulnerabilities_by_severity(parsed_data['vulnerabilities'])
                        
                        # Only update if this is the latest scan for this project
                        if (not projects[project_name]['last_scan'] or 
                            trivy_file['timestamp'] > projects[project_name]['last_scan']):
                            projects[project_name]['critical_count'] = vuln_counts['critical']
                            projects[project_name]['high_count'] = vuln_counts['high']
                            projects[project_name]['medium_count'] = vuln_counts['medium']
                            projects[project_name]['low_count'] = vuln_counts['low']
                            projects[project_name]['total_vulnerabilities'] = vuln_counts['total']
                        
                        # Update last scan timestamp
                        if (not projects[project_name]['last_scan'] or 
                            trivy_file['timestamp'] > projects[project_name]['last_scan']):
                            projects[project_name]['last_scan'] = trivy_file['timestamp']
                        
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
                
                # Update global data
                app_data['projects'] = projects
                app_data['scans'] = scans
                app_data['vulnerabilities'] = vulnerabilities
                app_data['last_updated'] = datetime.now()
                app_data['is_loading'] = False
                
                logger.info(f"✅ Data refresh complete. Projects: {len(projects)}, Scans: {len(scans)}")
                
        except Exception as e:
            logger.error(f"❌ Error in background data refresh: {str(e)}")
            app_data['is_loading'] = False
        
        # Wait for next refresh cycle
        time.sleep(Config.REFRESH_INTERVAL)

# Start background data refresh thread
refresh_thread = threading.Thread(target=refresh_data_background, daemon=True)
refresh_thread.start()

@app.route('/debug/nexus')
def debug_nexus():
    """Debug endpoint to inspect Nexus connection and Trivy report discovery"""
    logger.info("🔧 Debug: Nexus connection and Trivy report discovery")
    
    debug_info = {
        'nexus_config': {
            'url': Config.NEXUS_URL,
            'repository': Config.NEXUS_REPOSITORY,
            'username': Config.NEXUS_USERNAME,
            'group_id': Config.NEXUS_GROUP_ID,
            'artifact_suffix': Config.NEXUS_ARTIFACT_SUFFIX,
            'version_prefix': Config.NEXUS_VERSION_PREFIX,
            'asset_extension': Config.NEXUS_ASSET_EXTENSION
        },
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
        
        # Test various API endpoints
        api_tests = {
            'status': f"{Config.NEXUS_URL}/service/rest/v1/status",
            'repositories': f"{Config.NEXUS_URL}/service/rest/v1/repositories",
            'search_assets': f"{Config.NEXUS_URL}/service/rest/v1/search/assets",
            'repository_info': f"{Config.NEXUS_URL}/service/rest/v1/repositories/{Config.NEXUS_REPOSITORY}",
            'browse_repo': f"{Config.NEXUS_URL}/repository/{Config.NEXUS_REPOSITORY}/com/mccamish/"
        }
        
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
    """Individual project details"""
    logger.info(f"📊 Rendering project detail for: {project_name}")
    
    if project_name not in app_data['projects']:
        return "Project not found", 404
    
    project = app_data['projects'][project_name]
    
    # Get scan history for this project
    project_scans = [
        app_data['scans'][scan_id] for scan_id in project['scans']
    ]
    project_scans.sort(key=lambda x: x['timestamp'], reverse=True)
    
    # Calculate trend data
    trend_data = analytics.calculate_vulnerability_trends(project_scans)
    
    return render_template('project.html',
        project=project,
        scans=project_scans[:10],  # Last 10 scans
        trend_data=trend_data
    )

@app.route('/scan/<scan_id>')
def scan_detail(scan_id):
    """Individual scan details with pagination"""
    logger.info(f"🔍 Rendering scan detail for: {scan_id}")
    
    if scan_id not in app_data['scans']:
        return "Scan not found", 404
    
    scan = app_data['scans'][scan_id]
    
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    severity_filter = request.args.get('severity', '').upper()
    
    # Filter vulnerabilities by severity if specified
    vulnerabilities = scan['vulnerabilities']
    if severity_filter and severity_filter in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        vulnerabilities = [v for v in vulnerabilities if v.get('severity', '').upper() == severity_filter]
    
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
        severity_filter=severity_filter.lower() if severity_filter else ''
    )

@app.route('/scan/<scan_id>/vulnerability/<vuln_id>')
def vulnerability_detail(scan_id, vuln_id):
    """Individual vulnerability details with SBOM information from Trivy report"""
    logger.info(f"🔍 Rendering vulnerability detail for: {vuln_id} in scan: {scan_id}")
    
    if scan_id not in app_data['scans']:
        return "Scan not found", 404
    
    scan = app_data['scans'][scan_id]
    
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
    project_scans.sort(key=lambda x: x['timestamp'])
    
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
    all_scans.sort(key=lambda x: x['timestamp'])
    
    trends = analytics.calculate_security_trends(all_scans)
    
    return jsonify(trends)

@app.route('/refresh')
def manual_refresh():
    """Manual data refresh endpoint"""
    logger.info("🔄 Manual data refresh requested")
    
    if not app_data['is_loading']:
        # Trigger immediate refresh by setting loading flag
        app_data['is_loading'] = False
        
    return jsonify({
        'status': 'refresh_triggered',
        'is_loading': app_data['is_loading'],
        'last_updated': app_data['last_updated'].isoformat() if app_data['last_updated'] else None
    })

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'nexus_connection': nexus_client.test_connection(),
        'data_available': len(app_data['projects']) > 0
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
            'latest_scan': project_data.get('latest_scan', 'unknown'),
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
    """Comprehensive SBOM details view with package information"""
    logger.info(f"📊 SBOM details requested for scan: {scan_id}")
    
    if scan_id not in app_data['scans']:
        return "Scan not found", 404
    
    scan = app_data['scans'][scan_id]
    trivy_report_path = scan.get('trivy_report_path')
    
    if not trivy_report_path:
        return render_template('error.html', 
                             error="Trivy report path not found in scan metadata"), 400
    
    try:
        # Import the comprehensive SBOM parser
        from services.comprehensive_sbom_parser import ComprehensiveSBOMParser
        
        # Fetch Trivy data
        logger.debug(f"Fetching Trivy data from: {trivy_report_path}")
        trivy_content = nexus_client.download_trivy_report(trivy_report_path)
        
        # Try to fetch CycloneDX from same path
        cyclonedx_content = None
        try:
            logger.debug(f"Attempting to fetch CycloneDX SBOM...")
            cyclonedx_content = nexus_client.download_cyclonedx_sbom(trivy_report_path)
        except Exception as e:
            logger.debug(f"CycloneDX not available: {str(e)}")
            # Use empty CycloneDX structure if not available
            cyclonedx_content = {"components": []}
        
        # Parse with comprehensive SBOM parser
        logger.debug("Parsing comprehensive SBOM details...")
        parser = ComprehensiveSBOMParser(trivy_content, cyclonedx_content)
        sbom_details = parser.get_comprehensive_sbom_details()
        
        # Add scan context
        sbom_details['scan_info'] = {
            'scan_id': scan_id,
            'project_name': scan.get('project_name'),
            'scan_date': scan.get('scan_date'),
            'target': scan.get('target_name'),
            'report_path': trivy_report_path
        }
        
        logger.info(f"✅ Generated comprehensive SBOM with {sbom_details['statistics']['total_packages']} packages")
        
        return render_template('sbom_details.html', 
                             scan=scan,
                             sbom=sbom_details)
        
    except Exception as e:
        logger.error(f"❌ Error generating SBOM details: {str(e)}")
        return render_template('error.html', 
                             error=f"Error generating SBOM details: {str(e)}"), 500

@app.route('/scan/<scan_id>/sbom/export')
def export_merged_sbom(scan_id):
    """Export merged SBOM (Trivy + CycloneDX) as SPDX JSON"""
    logger.info(f"📤 Export merged SBOM for scan: {scan_id}")
    
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
        
        # Merge if both available
        if trivy_content and cyclonedx_content:
            logger.info(f"Merging Trivy + CycloneDX data for export")
            hybrid_parser = HybridSBOMParser(trivy_content, cyclonedx_content)
            spdx_output = hybrid_parser.to_spdx_json()
            filename = f"{scan['project']}-{scan['build_number']}-merged-sbom.spdx.json"
        else:
            # Return Trivy if CycloneDX not available
            import json
            spdx_output = json.dumps(trivy_content, indent=2)
            filename = f"{scan['project']}-{scan['build_number']}-trivy-report.json"
        
        return Response(
            spdx_output,
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment; filename={filename}'}
        )
    
    except Exception as e:
        logger.error(f"Error exporting merged SBOM: {str(e)}")
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
    logger.info("🔗 Testing Nexus connection...")
    if nexus_client.test_connection():
        logger.info("✅ Nexus connection successful")
    else:
        logger.warning("⚠️ Nexus connection failed - check configuration")
    
    logger.info("📥 Background data refresh started...")
    
    app.run(
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.DEBUG,
        threaded=True
    )
