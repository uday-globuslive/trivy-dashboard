#!/usr/bin/env python3
"""
Configuration Test Script
Run this to verify your environment variables are correctly configured
"""

import os
import sys

def test_configuration():
    """Test the configuration and display current values"""
    
    print("🔧 Testing Trivy Dashboard Configuration")
    print("=" * 50)
    
    # Required environment variables
    required_vars = {
        'NEXUS_URL': 'Nexus Repository URL',
        'NEXUS_USERNAME': 'Nexus authentication username', 
        'NEXUS_PASSWORD': 'Nexus authentication password',
        'NEXUS_REPOSITORY': 'Repository name containing SBOM files'
    }
    
    # Optional environment variables with defaults
    optional_vars = {
        'NEXUS_GROUP_ID': ('Maven group ID pattern', 'com.mccamish'),
        'NEXUS_ARTIFACT_SUFFIX': ('Artifact suffix pattern', '.sbom'),
        'NEXUS_VERSION_PREFIX': ('Version prefix pattern', '1.0.0-'),
        'NEXUS_ASSET_EXTENSION': ('Asset file extension', 'json'),
        'NEXUS_TIMEOUT': ('Nexus API timeout', '30')
    }
    
    print("\n📋 Required Configuration:")
    print("-" * 30)
    
    missing_required = []
    for var, description in required_vars.items():
        value = os.environ.get(var)
        if value:
            # Mask password for security
            display_value = value if var != 'NEXUS_PASSWORD' else '*' * len(value)
            print(f"✅ {var:<20} = {display_value}")
            print(f"   └─ {description}")
        else:
            print(f"❌ {var:<20} = NOT SET")
            print(f"   └─ {description}")
            missing_required.append(var)
        print()
    
    print("\n🔧 Optional Configuration:")
    print("-" * 30)
    
    for var, (description, default) in optional_vars.items():
        value = os.environ.get(var, default)
        source = "ENV" if os.environ.get(var) else "DEFAULT"
        print(f"ℹ️  {var:<20} = {value} ({source})")
        print(f"   └─ {description}")
        print()
    
    print("\n📊 Configuration Summary:")
    print("-" * 30)
    
    if missing_required:
        print(f"❌ Missing {len(missing_required)} required variables: {', '.join(missing_required)}")
        print("\n🔧 To fix, export the missing variables:")
        for var in missing_required:
            if var == 'NEXUS_PASSWORD':
                print(f"export {var}='your-secure-password'")
            elif var == 'NEXUS_URL':
                print(f"export {var}='http://swdlvapp682.mccamish.com:8081'")
            elif var == 'NEXUS_REPOSITORY':
                print(f"export {var}='mccamish_sbom'")
            else:
                print(f"export {var}='your-{var.lower().replace('_', '-')}'")
        return False
    else:
        print("✅ All required configuration is present!")
        
        # Try to load the actual config
        try:
            from config import Config
            print(f"✅ Config class loaded successfully")
            print(f"   └─ Nexus URL: {Config.NEXUS_URL}")
            print(f"   └─ Repository: {Config.NEXUS_REPOSITORY}")
            print(f"   └─ Group ID: {Config.NEXUS_GROUP_ID}")
            return True
        except Exception as e:
            print(f"❌ Error loading config: {str(e)}")
            return False

if __name__ == '__main__':
    print(f"Python: {sys.version}")
    print(f"Working directory: {os.getcwd()}")
    print()
    
    success = test_configuration()
    
    if success:
        print("\n🚀 Configuration is ready!")
        print("You can now run:")
        print("  python app.py")
        print("or build the Docker image with these settings.")
        sys.exit(0)
    else:
        print("\n❌ Configuration needs attention before proceeding.")
        sys.exit(1)
