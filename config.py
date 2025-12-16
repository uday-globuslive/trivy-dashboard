"""
Configuration settings for the Trivy Security Dashboard
"""

import os
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Configuration class for the Flask application"""
    
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'trivy-dashboard-secret-key-change-in-production'
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() in ['true', '1', 'on']
    HOST = os.environ.get('FLASK_HOST', '0.0.0.0')
    PORT = int(os.environ.get('FLASK_PORT', 5000))
    
    # Artifactory Type Configuration - Choose 'nexus' or 'jfrog'
    ARTIFACTORY_TYPE = os.environ.get('ARTIFACTORY_TYPE', 'nexus').lower()
    
    # Nexus Repository settings - used when ARTIFACTORY_TYPE='nexus'
    NEXUS_URL = os.environ.get('NEXUS_URL')
    NEXUS_USERNAME = os.environ.get('NEXUS_USERNAME')
    NEXUS_PASSWORD = os.environ.get('NEXUS_PASSWORD')
    NEXUS_REPOSITORY = os.environ.get('NEXUS_REPOSITORY')
    
    # Generic Nexus artifact pattern settings - customize for your Jenkins upload pattern
    NEXUS_GROUP_ID = os.environ.get('NEXUS_GROUP_ID', 'com.mccamish')
    NEXUS_ARTIFACT_SUFFIX = os.environ.get('NEXUS_ARTIFACT_SUFFIX', '-trivy-report')
    NEXUS_VERSION_PREFIX = os.environ.get('NEXUS_VERSION_PREFIX', '1.0.0-')
    NEXUS_ASSET_EXTENSION = os.environ.get('NEXUS_ASSET_EXTENSION', 'json')
    NEXUS_TIMEOUT = int(os.environ.get('NEXUS_TIMEOUT', 30))
    
    # JFrog Artifactory settings - used when ARTIFACTORY_TYPE='jfrog'
    JFROG_URL = os.environ.get('JFROG_URL')
    JFROG_USERNAME = os.environ.get('JFROG_USERNAME')
    JFROG_PASSWORD = os.environ.get('JFROG_PASSWORD')
    JFROG_REPOSITORY = os.environ.get('JFROG_REPOSITORY')
    
    # Generic JFrog artifact pattern settings
    JFROG_GROUP_ID = os.environ.get('JFROG_GROUP_ID', 'com.yourcompany')
    JFROG_ARTIFACT_SUFFIX = os.environ.get('JFROG_ARTIFACT_SUFFIX', '-trivy-report')
    JFROG_VERSION_PREFIX = os.environ.get('JFROG_VERSION_PREFIX', '1.0.0-')
    JFROG_ASSET_EXTENSION = os.environ.get('JFROG_ASSET_EXTENSION', 'json')
    JFROG_TIMEOUT = int(os.environ.get('JFROG_TIMEOUT', 30))
    
    # Data refresh settings
    REFRESH_INTERVAL = int(os.environ.get('REFRESH_INTERVAL', 300))  # 5 minutes
    CACHE_TTL = int(os.environ.get('CACHE_TTL', 3600))  # 1 hour
    
    # Logging settings
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', None)
    
    # Dashboard settings
    MAX_SCANS_PER_PROJECT = int(os.environ.get('MAX_SCANS_PER_PROJECT', 50))
    VULNERABILITY_RETENTION_DAYS = int(os.environ.get('VULNERABILITY_RETENTION_DAYS', 90))
    DEFAULT_PAGE_SIZE = int(os.environ.get('DEFAULT_PAGE_SIZE', 10))
    
    # Chart settings
    DEFAULT_CHART_THEME = os.environ.get('DEFAULT_CHART_THEME', 'plotly')
    CHART_HEIGHT = int(os.environ.get('CHART_HEIGHT', 400))
    
    # Security settings
    ENABLE_AUTH = os.environ.get('ENABLE_AUTH', 'False').lower() in ['true', '1', 'on']
    SESSION_TIMEOUT = timedelta(hours=int(os.environ.get('SESSION_TIMEOUT_HOURS', 8)))
    
    # Performance settings
    ENABLE_CACHING = os.environ.get('ENABLE_CACHING', 'True').lower() in ['true', '1', 'on']
    MAX_WORKERS = int(os.environ.get('MAX_WORKERS', 4))
    
    @classmethod
    def validate_config(cls):
        """Validate configuration settings"""
        # Validate artifactory type
        if cls.ARTIFACTORY_TYPE not in ['nexus', 'jfrog']:
            raise ValueError(f"Invalid ARTIFACTORY_TYPE: {cls.ARTIFACTORY_TYPE}. Must be 'nexus' or 'jfrog'")
        
        # Validate based on artifactory type
        if cls.ARTIFACTORY_TYPE == 'nexus':
            required_settings = [
                'NEXUS_URL',
                'NEXUS_USERNAME',
                'NEXUS_PASSWORD',
                'NEXUS_REPOSITORY'
            ]
        else:  # jfrog
            required_settings = [
                'JFROG_URL',
                'JFROG_USERNAME',
                'JFROG_PASSWORD',
                'JFROG_REPOSITORY'
            ]
        
        missing_settings = []
        for setting in required_settings:
            if not getattr(cls, setting):
                missing_settings.append(setting)
        
        if missing_settings:
            raise ValueError(f"Missing required configuration for {cls.ARTIFACTORY_TYPE.upper()}: {', '.join(missing_settings)}")
        
        return True

# Validate configuration on import
Config.validate_config()
