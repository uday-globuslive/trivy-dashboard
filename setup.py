#!/usr/bin/env python3
"""
Setup script for Trivy Security Dashboard
Helps configure environment and validate connectivity
"""

import os
import sys
import requests
import subprocess
from pathlib import Path

def print_banner():
    """Print setup banner"""
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                    Trivy Security Dashboard Setup                ║
║                                                                  ║
║  This script will help you configure and validate your           ║
║  Trivy Security Dashboard environment.                           ║
╚══════════════════════════════════════════════════════════════════╝
    """)

def check_python_version():
    """Check Python version compatibility"""
    print("🐍 Checking Python version...")
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ is required. Current version:", sys.version)
        return False
    print(f"✅ Python {sys.version.split()[0]} - Compatible")
    return True

def create_env_file():
    """Create .env file from template if it doesn't exist"""
    print("📝 Setting up environment configuration...")
    
    env_file = Path('.env')
    env_example = Path('.env.example')
    
    if not env_file.exists():
        if env_example.exists():
            # Copy example file
            with open(env_example, 'r') as src, open(env_file, 'w') as dst:
                dst.write(src.read())
            print("✅ Created .env file from template")
        else:
            # Create basic .env file
            env_content = """# Nexus Repository Configuration
NEXUS_URL=http://localhost:8081
NEXUS_USERNAME=admin
NEXUS_PASSWORD=admin123
NEXUS_REPOSITORY=trivy-reports

# Flask Configuration
FLASK_ENV=development
FLASK_DEBUG=true
SECRET_KEY=change-me-in-production

# Dashboard Configuration
CACHE_TTL=300
DATA_REFRESH_INTERVAL=600
"""
            with open(env_file, 'w') as f:
                f.write(env_content)
            print("✅ Created basic .env file")
    else:
        print("✅ .env file already exists")
    
    return True

def install_dependencies():
    """Install Python dependencies"""
    print("📦 Installing dependencies...")
    
    try:
        result = subprocess.run([
            sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'
        ], capture_output=True, text=True, check=True)
        print("✅ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e.stderr}")
        return False
    except FileNotFoundError:
        print("❌ requirements.txt not found")
        return False

def validate_nexus_connection():
    """Test connection to Nexus Repository"""
    print("🔗 Testing Nexus Repository connection...")
    
    # Load environment variables from .env file
    env_vars = {}
    try:
        with open('.env', 'r') as f:
            for line in f:
                if '=' in line and not line.startswith('#'):
                    key, value = line.strip().split('=', 1)
                    env_vars[key] = value
    except FileNotFoundError:
        print("❌ .env file not found")
        return False
    
    nexus_url = env_vars.get('NEXUS_URL', 'http://localhost:8081')
    nexus_username = env_vars.get('NEXUS_USERNAME', 'admin')
    nexus_password = env_vars.get('NEXUS_PASSWORD', 'admin123')
    
    try:
        # Test Nexus API endpoint
        response = requests.get(
            f"{nexus_url}/service/rest/v1/repositories",
            auth=(nexus_username, nexus_password),
            timeout=10
        )
        
        if response.status_code == 200:
            repositories = response.json()
            print(f"✅ Connected to Nexus ({len(repositories)} repositories found)")
            
            # Check for configured repository
            repo_name = env_vars.get('NEXUS_REPOSITORY', 'trivy-reports')
            repo_exists = any(repo['name'] == repo_name for repo in repositories)
            
            if repo_exists:
                print(f"✅ Repository '{repo_name}' found")
            else:
                print(f"⚠️  Repository '{repo_name}' not found - you may need to create it")
            
            return True
        else:
            print(f"❌ Nexus authentication failed (HTTP {response.status_code})")
            return False
            
    except requests.exceptions.ConnectTimeout:
        print("❌ Connection timeout - check NEXUS_URL")
        return False
    except requests.exceptions.ConnectionError:
        print("❌ Connection refused - is Nexus running?")
        return False
    except Exception as e:
        print(f"❌ Connection error: {str(e)}")
        return False

def create_directories():
    """Create necessary directories"""
    print("📁 Creating directories...")
    
    directories = ['logs', 'static/css', 'static/js', 'templates']
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
    
    print("✅ Directories created")
    return True

def run_health_check():
    """Run basic application health check"""
    print("🏥 Running application health check...")
    
    try:
        # Try to import main modules
        import flask
        print("✅ Flask imported successfully")
        
        import requests
        print("✅ Requests imported successfully")
        
        # Check if app.py exists and can be imported
        if Path('app.py').exists():
            print("✅ app.py found")
        else:
            print("❌ app.py not found")
            return False
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False

def main():
    """Main setup function"""
    print_banner()
    
    success = True
    
    # Run all setup steps
    success &= check_python_version()
    success &= create_directories()
    success &= create_env_file()
    success &= install_dependencies()
    success &= run_health_check()
    success &= validate_nexus_connection()
    
    print("\n" + "="*70)
    
    if success:
        print("""
✅ Setup completed successfully!

Next steps:
1. Review and update .env file with your Nexus settings
2. Start the dashboard: python app.py
3. Open browser to: http://localhost:5000

For Docker deployment:
1. docker-compose up -d
2. Access at: http://localhost:5000
        """)
    else:
        print("""
❌ Setup completed with issues.

Please review the errors above and:
1. Check your .env configuration
2. Verify Nexus Repository is running and accessible
3. Ensure all dependencies are installed correctly
        """)
    
    return 0 if success else 1

if __name__ == '__main__':
    sys.exit(main())
