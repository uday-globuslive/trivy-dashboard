"""
Helper utilities for the dashboard application
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
import re

logger = logging.getLogger(__name__)

def format_timestamp(timestamp: Optional[datetime], format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Format timestamp for display"""
    if timestamp is None:
        return "Never"
    
    try:
        return timestamp.strftime(format_str)
    except Exception as e:
        logger.warning(f"⚠️ Error formatting timestamp {timestamp}: {str(e)}")
        return "Invalid Date"

def time_ago(timestamp: Optional[datetime]) -> str:
    """Return human-readable time difference"""
    if timestamp is None:
        return "Never"
    
    try:
        now = datetime.now()
        if timestamp.tzinfo is not None:
            # Handle timezone-aware timestamps
            import pytz
            if now.tzinfo is None:
                now = pytz.UTC.localize(now)
        
        diff = now - timestamp
        
        if diff.days > 0:
            return f"{diff.days} day{'s' if diff.days != 1 else ''} ago"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
        else:
            return "Just now"
            
    except Exception as e:
        logger.warning(f"⚠️ Error calculating time ago for {timestamp}: {str(e)}")
        return "Unknown"

def calculate_risk_score(critical: int, high: int, medium: int, low: int) -> float:
    """Calculate risk score based on vulnerability counts"""
    weights = {
        'critical': 10,
        'high': 7,
        'medium': 4,
        'low': 1
    }
    
    total_weighted = (
        critical * weights['critical'] +
        high * weights['high'] +
        medium * weights['medium'] +
        low * weights['low']
    )
    
    total_vulnerabilities = critical + high + medium + low
    
    if total_vulnerabilities == 0:
        return 0.0
    
    # Normalize to 0-100 scale
    max_possible_score = total_vulnerabilities * weights['critical']
    risk_score = (total_weighted / max_possible_score) * 100
    
    return round(min(risk_score, 100), 2)

def format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable format"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.1f} {size_names[i]}"

def sanitize_string(input_str: str, max_length: int = 100) -> str:
    """Sanitize string for safe display"""
    if not isinstance(input_str, str):
        return str(input_str)
    
    # Remove potential HTML/script tags
    sanitized = re.sub(r'<[^>]+>', '', input_str)
    
    # Limit length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "..."
    
    return sanitized

def extract_cve_id(text: str) -> Optional[str]:
    """Extract CVE ID from text"""
    cve_pattern = r'CVE-\d{4}-\d{4,}'
    match = re.search(cve_pattern, text, re.IGNORECASE)
    return match.group(0) if match else None

def severity_to_color(severity: str) -> str:
    """Convert severity to color class"""
    severity_colors = {
        'CRITICAL': 'danger',
        'HIGH': 'warning',
        'MEDIUM': 'info',
        'LOW': 'success',
        'INFO': 'secondary',
        'UNKNOWN': 'dark'
    }
    
    return severity_colors.get(severity.upper(), 'dark')

def severity_to_badge_class(severity: str) -> str:
    """Convert severity to Bootstrap badge class"""
    return f"badge bg-{severity_to_color(severity)}"

def truncate_text(text: str, max_length: int = 50, suffix: str = "...") -> str:
    """Truncate text to specified length"""
    if len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix

def parse_semver(version: str) -> Dict[str, Any]:
    """Parse semantic version string"""
    # Simple semver parsing
    pattern = r'^(\d+)\.(\d+)\.(\d+)(?:-([a-zA-Z0-9\-\.]+))?(?:\+([a-zA-Z0-9\-\.]+))?$'
    match = re.match(pattern, version)
    
    if match:
        return {
            'major': int(match.group(1)),
            'minor': int(match.group(2)),
            'patch': int(match.group(3)),
            'prerelease': match.group(4),
            'build': match.group(5),
            'is_valid': True
        }
    
    return {
        'major': 0,
        'minor': 0,
        'patch': 0,
        'prerelease': None,
        'build': None,
        'is_valid': False,
        'original': version
    }

def generate_colors(count: int) -> List[str]:
    """Generate a list of distinct colors for charts"""
    base_colors = [
        '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0',
        '#9966FF', '#FF9F40', '#FF6384', '#C9CBCF'
    ]
    
    if count <= len(base_colors):
        return base_colors[:count]
    
    # Generate additional colors using HSL
    colors = base_colors.copy()
    hue_step = 360 / count
    
    for i in range(len(base_colors), count):
        hue = (i * hue_step) % 360
        color = f'hsl({hue}, 70%, 60%)'
        colors.append(color)
    
    return colors

def validate_email(email: str) -> bool:
    """Validate email address format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def format_vulnerability_description(description: str, max_length: int = 200) -> str:
    """Format vulnerability description for display"""
    if not description:
        return "No description available"
    
    # Clean up common formatting issues
    cleaned = re.sub(r'\s+', ' ', description.strip())
    cleaned = re.sub(r'^\*\*|\*\*$', '', cleaned)  # Remove markdown bold
    
    return truncate_text(cleaned, max_length)

def calculate_percentage(part: int, total: int) -> float:
    """Calculate percentage safely"""
    if total == 0:
        return 0.0
    
    return round((part / total) * 100, 1)

def group_by_date(items: List[Dict], date_field: str = 'timestamp', 
                  date_format: str = '%Y-%m-%d') -> Dict[str, List]:
    """Group items by date"""
    grouped = {}
    
    for item in items:
        timestamp = item.get(date_field)
        if timestamp:
            if isinstance(timestamp, datetime):
                date_key = timestamp.strftime(date_format)
            else:
                try:
                    parsed_date = datetime.fromisoformat(str(timestamp).replace('Z', '+00:00'))
                    date_key = parsed_date.strftime(date_format)
                except:
                    date_key = 'unknown'
            
            if date_key not in grouped:
                grouped[date_key] = []
            grouped[date_key].append(item)
    
    return grouped

def sort_severity_groups(severity_dict: Dict[str, Any]) -> List[tuple]:
    """Sort severity groups by priority"""
    severity_order = ['critical', 'high', 'medium', 'low', 'info', 'unknown']
    
    sorted_items = []
    for severity in severity_order:
        if severity in severity_dict and severity_dict[severity]:
            sorted_items.append((severity, severity_dict[severity]))
    
    return sorted_items

def format_duration(seconds: int) -> str:
    """Format duration in seconds to human readable format"""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        minutes = seconds // 60
        return f"{minutes}m {seconds % 60}s"
    else:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours}h {minutes}m"

def safe_divide(numerator: float, denominator: float, default: float = 0.0) -> float:
    """Safely divide two numbers"""
    try:
        return numerator / denominator if denominator != 0 else default
    except (TypeError, ZeroDivisionError):
        return default

def extract_project_info(sbom_metadata: Dict) -> Dict[str, Any]:
    """Extract standardized project information from SBOM metadata"""
    return {
        'name': sbom_metadata.get('project', 'Unknown Project'),
        'version': sbom_metadata.get('project_version', 'Unknown'),
        'type': sbom_metadata.get('project_type', 'application'),
        'group': sbom_metadata.get('project_group', ''),
        'description': sbom_metadata.get('project_description', ''),
        'supplier': sbom_metadata.get('supplier', {}),
        'timestamp': sbom_metadata.get('timestamp')
    }

def is_outdated_version(current_version: str, latest_version: str) -> bool:
    """Check if current version is outdated compared to latest"""
    try:
        current = parse_semver(current_version)
        latest = parse_semver(latest_version)
        
        if not current['is_valid'] or not latest['is_valid']:
            return False
        
        # Compare major.minor.patch
        current_tuple = (current['major'], current['minor'], current['patch'])
        latest_tuple = (latest['major'], latest['minor'], latest['patch'])
        
        return current_tuple < latest_tuple
        
    except Exception:
        return False

def get_risk_level_description(risk_score: float) -> str:
    """Get descriptive text for risk score"""
    if risk_score >= 80:
        return "Critical Risk"
    elif risk_score >= 60:
        return "High Risk"
    elif risk_score >= 40:
        return "Medium Risk"
    elif risk_score >= 20:
        return "Low Risk"
    else:
        return "Minimal Risk"

def format_chart_date(timestamp: datetime) -> str:
    """Format timestamp for chart labels"""
    return timestamp.strftime('%m/%d')

def generate_report_filename(project_name: str, scan_date: datetime, 
                           report_type: str = 'security') -> str:
    """Generate standardized report filename"""
    date_str = scan_date.strftime('%Y%m%d_%H%M%S')
    safe_project_name = re.sub(r'[^\w\-_]', '_', project_name)
    
    return f"{safe_project_name}_{report_type}_report_{date_str}.pdf"
