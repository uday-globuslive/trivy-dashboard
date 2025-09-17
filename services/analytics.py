"""
Security Analytics Service for calculating metrics and trends
"""

import logging
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import List, Dict, Any
import statistics

logger = logging.getLogger(__name__)

class SecurityAnalytics:
    """Analytics engine for security data processing"""
    
    def __init__(self):
        self.severity_weights = {
            'CRITICAL': 10,
            'HIGH': 7,
            'MEDIUM': 4,
            'LOW': 1,
            'INFO': 0.5,
            'UNKNOWN': 2
        }
        logger.info("📊 Initialized Security Analytics engine")
    
    def count_vulnerabilities_by_severity(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Count vulnerabilities by severity level"""
        counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'unknown': 0,
            'total': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN').lower()
            if severity in counts:
                counts[severity] += 1
            else:
                counts['unknown'] += 1
            counts['total'] += 1
        
        return counts
    
    def calculate_risk_score(self, vulnerabilities: List[Dict]) -> float:
        """Calculate overall risk score based on vulnerabilities"""
        if not vulnerabilities:
            return 0.0
        
        total_score = 0
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN').upper()
            weight = self.severity_weights.get(severity, 2)
            
            # Factor in CVSS score if available
            score = vuln.get('score')
            if score is not None:
                total_score += (score * weight / 10)
            else:
                total_score += weight
        
        # Normalize score (0-100 scale)
        max_possible_score = len(vulnerabilities) * 10
        risk_score = min((total_score / max_possible_score) * 100, 100) if max_possible_score > 0 else 0
        
        return round(risk_score, 2)
    
    def calculate_vulnerability_trends(self, scans: List[Dict]) -> Dict[str, Any]:
        """Calculate vulnerability trends over time"""
        if not scans:
            return {}
        
        # Sort scans by timestamp
        sorted_scans = sorted(scans, key=lambda x: x.get('timestamp', datetime.min))
        
        trend_data = {
            'timestamps': [],
            'critical_counts': [],
            'high_counts': [],
            'medium_counts': [],
            'low_counts': [],
            'total_counts': [],
            'risk_scores': []
        }
        
        for scan in sorted_scans:
            timestamp = scan.get('timestamp')
            if timestamp:
                trend_data['timestamps'].append(timestamp.isoformat())
                
                counts = self.count_vulnerabilities_by_severity(scan.get('vulnerabilities', []))
                trend_data['critical_counts'].append(counts['critical'])
                trend_data['high_counts'].append(counts['high'])
                trend_data['medium_counts'].append(counts['medium'])
                trend_data['low_counts'].append(counts['low'])
                trend_data['total_counts'].append(counts['total'])
                
                risk_score = self.calculate_risk_score(scan.get('vulnerabilities', []))
                trend_data['risk_scores'].append(risk_score)
        
        # Calculate trend direction
        trend_data['trend_direction'] = self._calculate_trend_direction(trend_data['total_counts'])
        trend_data['risk_trend'] = self._calculate_trend_direction(trend_data['risk_scores'])
        
        return trend_data
    
    def group_vulnerabilities_by_severity(self, vulnerabilities: List[Dict]) -> Dict[str, List[Dict]]:
        """Group vulnerabilities by severity level"""
        grouped = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': [],
            'unknown': []
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN').lower()
            if severity in grouped:
                grouped[severity].append(vuln)
            else:
                grouped['unknown'].append(vuln)
        
        return grouped
    
    def analyze_components(self, components: List[Dict]) -> Dict[str, Any]:
        """Analyze components for security insights"""
        if not components:
            return {}
        
        analysis = {
            'total_components': len(components),
            'component_types': Counter(),
            'license_distribution': Counter(),
            'outdated_components': [],
            'high_risk_components': [],
            'component_languages': Counter()
        }
        
        for component in components:
            # Component type analysis
            comp_type = component.get('type', 'unknown')
            analysis['component_types'][comp_type] += 1
            
            # License analysis
            licenses = component.get('licenses', [])
            for license_info in licenses:
                if isinstance(license_info, dict):
                    license_id = license_info.get('id', license_info.get('name', 'Unknown'))
                    analysis['license_distribution'][license_id] += 1
            
            # Language detection (basic heuristics)
            name = component.get('name', '').lower()
            purl = component.get('purl', '').lower()
            
            if any(x in purl for x in ['npm', 'javascript', 'node']):
                analysis['component_languages']['JavaScript'] += 1
            elif any(x in purl for x in ['maven', 'java']):
                analysis['component_languages']['Java'] += 1
            elif any(x in purl for x in ['pypi', 'python']):
                analysis['component_languages']['Python'] += 1
            elif any(x in purl for x in ['nuget', 'dotnet']):
                analysis['component_languages']['.NET'] += 1
            elif any(x in purl for x in ['golang', 'go']):
                analysis['component_languages']['Go'] += 1
            else:
                analysis['component_languages']['Other'] += 1
        
        return analysis
    
    def generate_chart_data(self, scans: List[Dict]) -> Dict[str, Any]:
        """Generate data for dashboard charts"""
        if not scans:
            return {}
        
        chart_data = {}
        
        # Vulnerability trend chart
        trend_data = self.calculate_vulnerability_trends(scans)
        chart_data['vulnerability_trend'] = {
            'type': 'line',
            'data': {
                'labels': [ts.split('T')[0] for ts in trend_data.get('timestamps', [])],
                'datasets': [
                    {
                        'label': 'Critical',
                        'data': trend_data.get('critical_counts', []),
                        'borderColor': 'rgb(220, 53, 69)',
                        'backgroundColor': 'rgba(220, 53, 69, 0.1)',
                        'tension': 0.1
                    },
                    {
                        'label': 'High',
                        'data': trend_data.get('high_counts', []),
                        'borderColor': 'rgb(255, 193, 7)',
                        'backgroundColor': 'rgba(255, 193, 7, 0.1)',
                        'tension': 0.1
                    },
                    {
                        'label': 'Medium',
                        'data': trend_data.get('medium_counts', []),
                        'borderColor': 'rgb(255, 165, 0)',
                        'backgroundColor': 'rgba(255, 165, 0, 0.1)',
                        'tension': 0.1
                    },
                    {
                        'label': 'Low',
                        'data': trend_data.get('low_counts', []),
                        'borderColor': 'rgb(40, 167, 69)',
                        'backgroundColor': 'rgba(40, 167, 69, 0.1)',
                        'tension': 0.1
                    }
                ]
            },
            'options': {
                'responsive': True,
                'scales': {
                    'y': {
                        'beginAtZero': True,
                        'title': {
                            'display': True,
                            'text': 'Vulnerability Count'
                        }
                    }
                }
            }
        }
        
        # Risk score trend
        chart_data['risk_trend'] = {
            'type': 'line',
            'data': {
                'labels': [ts.split('T')[0] for ts in trend_data.get('timestamps', [])],
                'datasets': [{
                    'label': 'Risk Score',
                    'data': trend_data.get('risk_scores', []),
                    'borderColor': 'rgb(153, 102, 255)',
                    'backgroundColor': 'rgba(153, 102, 255, 0.1)',
                    'tension': 0.1
                }]
            },
            'options': {
                'responsive': True,
                'scales': {
                    'y': {
                        'beginAtZero': True,
                        'max': 100,
                        'title': {
                            'display': True,
                            'text': 'Risk Score (%)'
                        }
                    }
                }
            }
        }
        
        # Latest scan severity distribution
        if scans:
            latest_scan = max(scans, key=lambda x: x.get('timestamp', datetime.min))
            vuln_counts = self.count_vulnerabilities_by_severity(latest_scan.get('vulnerabilities', []))
            
            chart_data['severity_distribution'] = {
                'type': 'doughnut',
                'data': {
                    'labels': ['Critical', 'High', 'Medium', 'Low', 'Info'],
                    'datasets': [{
                        'data': [
                            vuln_counts['critical'],
                            vuln_counts['high'],
                            vuln_counts['medium'],
                            vuln_counts['low'],
                            vuln_counts['info']
                        ],
                        'backgroundColor': [
                            'rgb(220, 53, 69)',
                            'rgb(255, 193, 7)',
                            'rgb(255, 165, 0)',
                            'rgb(40, 167, 69)',
                            'rgb(108, 117, 125)'
                        ]
                    }]
                },
                'options': {
                    'responsive': True,
                    'plugins': {
                        'legend': {
                            'position': 'bottom'
                        }
                    }
                }
            }
        
        return chart_data
    
    def calculate_security_trends(self, all_scans: List[Dict]) -> Dict[str, Any]:
        """Calculate security trends across all projects"""
        if not all_scans:
            return {}
        
        # Group scans by time periods
        now = datetime.now()
        time_periods = {
            'last_7_days': now - timedelta(days=7),
            'last_30_days': now - timedelta(days=30),
            'last_90_days': now - timedelta(days=90)
        }
        
        trends = {}
        
        for period_name, start_date in time_periods.items():
            period_scans = [
                scan for scan in all_scans
                if scan.get('timestamp', datetime.min) >= start_date
            ]
            
            if period_scans:
                total_vulns = sum(
                    len(scan.get('vulnerabilities', []))
                    for scan in period_scans
                )
                
                avg_risk_score = statistics.mean([
                    self.calculate_risk_score(scan.get('vulnerabilities', []))
                    for scan in period_scans
                ]) if period_scans else 0
                
                trends[period_name] = {
                    'total_scans': len(period_scans),
                    'total_vulnerabilities': total_vulns,
                    'avg_risk_score': round(avg_risk_score, 2),
                    'projects_scanned': len(set(scan.get('project', '') for scan in period_scans))
                }
            else:
                trends[period_name] = {
                    'total_scans': 0,
                    'total_vulnerabilities': 0,
                    'avg_risk_score': 0,
                    'projects_scanned': 0
                }
        
        return trends
    
    def identify_common_vulnerabilities(self, all_vulnerabilities: Dict[str, List]) -> List[Dict]:
        """Identify most common vulnerabilities across projects"""
        vuln_stats = []
        
        for vuln_id, occurrences in all_vulnerabilities.items():
            if len(occurrences) > 1:  # Only include vulnerabilities found in multiple scans
                projects = set(occ['project'] for occ in occurrences)
                severities = [occ['details'].get('severity', 'UNKNOWN') for occ in occurrences]
                
                # Get the highest severity
                severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN']
                highest_severity = 'UNKNOWN'
                for severity in severity_order:
                    if severity in severities:
                        highest_severity = severity
                        break
                
                vuln_stats.append({
                    'id': vuln_id,
                    'occurrences': len(occurrences),
                    'projects_affected': len(projects),
                    'projects_list': list(projects),
                    'severity': highest_severity,
                    'description': occurrences[0]['details'].get('description', 'N/A')
                })
        
        # Sort by number of projects affected, then by occurrences
        vuln_stats.sort(key=lambda x: (x['projects_affected'], x['occurrences']), reverse=True)
        
        return vuln_stats[:20]  # Top 20 most common vulnerabilities
    
    def calculate_mttr(self, project_scans: List[Dict]) -> Dict[str, float]:
        """Calculate Mean Time To Remediation (MTTR) for vulnerabilities"""
        # This is a simplified MTTR calculation
        # In a real implementation, you'd track when vulnerabilities are introduced vs resolved
        
        if len(project_scans) < 2:
            return {'mttr_days': 0, 'remediation_rate': 0}
        
        # Sort scans by timestamp
        sorted_scans = sorted(project_scans, key=lambda x: x.get('timestamp', datetime.min))
        
        total_resolved = 0
        total_days = 0
        
        for i in range(1, len(sorted_scans)):
            prev_scan = sorted_scans[i-1]
            curr_scan = sorted_scans[i]
            
            prev_vulns = set(v['id'] for v in prev_scan.get('vulnerabilities', []))
            curr_vulns = set(v['id'] for v in curr_scan.get('vulnerabilities', []))
            
            resolved_vulns = prev_vulns - curr_vulns
            total_resolved += len(resolved_vulns)
            
            if resolved_vulns:
                time_diff = curr_scan.get('timestamp', datetime.min) - prev_scan.get('timestamp', datetime.min)
                total_days += time_diff.days
        
        mttr_days = (total_days / total_resolved) if total_resolved > 0 else 0
        remediation_rate = (total_resolved / len(project_scans)) if project_scans else 0
        
        return {
            'mttr_days': round(mttr_days, 2),
            'remediation_rate': round(remediation_rate, 2),
            'total_resolved': total_resolved
        }
    
    def _calculate_trend_direction(self, values: List[float]) -> str:
        """Calculate trend direction from a series of values"""
        if len(values) < 2:
            return 'stable'
        
        # Use linear regression to determine trend
        n = len(values)
        x_sum = sum(range(n))
        y_sum = sum(values)
        xy_sum = sum(i * values[i] for i in range(n))
        x_squared_sum = sum(i * i for i in range(n))
        
        # Calculate slope
        slope = (n * xy_sum - x_sum * y_sum) / (n * x_squared_sum - x_sum * x_sum)
        
        if slope > 0.1:
            return 'increasing'
        elif slope < -0.1:
            return 'decreasing'
        else:
            return 'stable'
    
    def generate_executive_summary(self, all_projects: Dict, all_scans: Dict) -> Dict[str, Any]:
        """Generate executive summary for dashboard"""
        total_projects = len(all_projects)
        total_scans = len(all_scans)
        
        # Calculate totals
        total_vulnerabilities = sum(p['total_vulnerabilities'] for p in all_projects.values())
        critical_projects = len([p for p in all_projects.values() if p['critical_count'] > 0])
        
        # Calculate average risk score
        risk_scores = [p['risk_score'] for p in all_projects.values() if p['risk_score'] > 0]
        avg_risk_score = statistics.mean(risk_scores) if risk_scores else 0
        
        # Security posture assessment
        if avg_risk_score < 20:
            security_posture = 'Excellent'
        elif avg_risk_score < 40:
            security_posture = 'Good'
        elif avg_risk_score < 60:
            security_posture = 'Fair'
        elif avg_risk_score < 80:
            security_posture = 'Poor'
        else:
            security_posture = 'Critical'
        
        # Recent activity
        recent_scans = [
            s for s in all_scans.values()
            if s.get('timestamp', datetime.min) > (datetime.now() - timedelta(days=7))
        ]
        
        return {
            'total_projects': total_projects,
            'total_scans': total_scans,
            'total_vulnerabilities': total_vulnerabilities,
            'critical_projects': critical_projects,
            'avg_risk_score': round(avg_risk_score, 2),
            'security_posture': security_posture,
            'recent_scans': len(recent_scans),
            'scan_coverage': round((len(recent_scans) / total_projects * 100), 2) if total_projects > 0 else 0
        }
