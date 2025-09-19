"""
Trivy Security Dashboard - Main Flask Application

This Flask application provides a comprehensive dashboard for visualizing
Trivy security scan results from CycloneDX files stored in Nexus Repository.
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
from services.cyclonedx_parser import CycloneDXParser
from services.analytics import SecurityAnalytics
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
parser = CycloneDXParser()
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
                
                # Fetch latest SBOM files from Nexus
                sbom_files = nexus_client.list_sbom_files()
                logger.info(f"📦 Found {len(sbom_files)} SBOM files in Nexus")
                
                projects = {}
                scans = {}
                vulnerabilities = {}
                
                for sbom_file in sbom_files:
                    try:
                        # Download and parse SBOM
                        sbom_content = nexus_client.download_sbom(sbom_file['path'])
                        parsed_data = parser.parse_cyclonedx(sbom_content)
                        
                        project_name = parsed_data['metadata']['project']
                        scan_id = f"{project_name}_{sbom_file['build_number']}"
                        
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
                            'build_number': sbom_file['build_number'],
                            'timestamp': sbom_file['timestamp'],
                            'vulnerabilities': parsed_data['vulnerabilities'],
                            'components': parsed_data['components'],
                            'metadata': parsed_data['metadata']
                        }
                        
                        scans[scan_id] = scan_data
                        projects[project_name]['scans'].append(scan_id)
                        
                        # Update project statistics
                        vuln_counts = analytics.count_vulnerabilities_by_severity(parsed_data['vulnerabilities'])
                        projects[project_name]['critical_count'] += vuln_counts['critical']
                        projects[project_name]['high_count'] += vuln_counts['high']
                        projects[project_name]['medium_count'] += vuln_counts['medium']
                        projects[project_name]['low_count'] += vuln_counts['low']
                        projects[project_name]['total_vulnerabilities'] += vuln_counts['total']
                        
                        # Update last scan timestamp
                        if (not projects[project_name]['last_scan'] or 
                            sbom_file['timestamp'] > projects[project_name]['last_scan']):
                            projects[project_name]['last_scan'] = sbom_file['timestamp']
                        
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
                        logger.error(f"❌ Error processing SBOM file {sbom_file['path']}: {str(e)}")
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
    """Debug endpoint to inspect Nexus connection and SBOM discovery"""
    logger.info("🔧 Debug: Nexus connection and SBOM discovery")
    
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
        'sbom_files': [],
        'error_message': None,
        'api_endpoints': {},
        'test_results': {}
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
        
        # Try to list SBOM files with detailed logging
        logger.info("🔍 Attempting to list SBOM files...")
        sbom_files = nexus_client.list_sbom_files(limit=10)
        debug_info['sbom_files'] = sbom_files
        debug_info['files_found'] = len(sbom_files)
        
        # Test specific McCamish patterns
        debug_info['mccamish_patterns'] = {
            'expected_path_pattern': f"com/mccamish/{{project}}.sbom/{{version}}/{{project}}.sbom-{{version}}.json",
            'example_path': "com/mccamish/AGP_Stellar_SSO.sbom/1.0.0-20250521034211/AGP_Stellar_SSO.sbom-1.0.0-20250521034211.json",
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
        if sbom_files:
            test_file = sbom_files[0]
            debug_info['download_test'] = {
                'test_file': test_file['filename'],
                'download_url': test_file['path'],
                'success': False,
                'error': None,
                'sample_content': None
            }
            
            try:
                sbom_content = nexus_client.download_sbom(test_file['path'])
                debug_info['download_test']['success'] = True
                debug_info['download_test']['sample_content'] = {
                    'bomFormat': sbom_content.get('bomFormat', 'unknown'),
                    'specVersion': sbom_content.get('specVersion', 'unknown'),
                    'component_count': len(sbom_content.get('components', [])),
                    'vulnerability_count': len(sbom_content.get('vulnerabilities', []))
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
    """Individual scan details"""
    logger.info(f"🔍 Rendering scan detail for: {scan_id}")
    
    if scan_id not in app_data['scans']:
        return "Scan not found", 404
    
    scan = app_data['scans'][scan_id]
    
    # Group vulnerabilities by severity
    vuln_by_severity = analytics.group_vulnerabilities_by_severity(scan['vulnerabilities'])
    
    # Get component analysis
    component_analysis = analytics.analyze_components(scan['components'])
    
    return render_template('scan.html',
        scan=scan,
        vulnerabilities_by_severity=vuln_by_severity,
        component_analysis=component_analysis
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
