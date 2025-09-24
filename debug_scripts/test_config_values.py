#!/usr/bin/env python3
"""
Test script to verify configuration values
"""

from config import Config

print("🔧 Configuration Test Results:")
print("=" * 50)

print(f"✅ NEXUS_URL: {Config.NEXUS_URL}")
print(f"✅ NEXUS_REPOSITORY: {Config.NEXUS_REPOSITORY}")
print(f"✅ NEXUS_GROUP_ID: {Config.NEXUS_GROUP_ID}")
print(f"✅ NEXUS_ARTIFACT_SUFFIX: {Config.NEXUS_ARTIFACT_SUFFIX}")
print(f"✅ TRIVY_REPORT_SUFFIX: {Config.TRIVY_REPORT_SUFFIX}")
print(f"✅ NEXUS_ASSET_EXTENSION: {Config.NEXUS_ASSET_EXTENSION}")
print(f"✅ FLASK_HOST: {Config.HOST}")
print(f"✅ FLASK_PORT: {Config.PORT}")
print(f"✅ CACHE_TTL: {Config.CACHE_TTL}")
print(f"✅ REFRESH_INTERVAL: {Config.REFRESH_INTERVAL}")

print("\n📋 Expected File Patterns:")
print(f"   SBOM files: *{Config.NEXUS_ARTIFACT_SUFFIX}.{Config.NEXUS_ASSET_EXTENSION}")
print(f"   Trivy reports: *{Config.TRIVY_REPORT_SUFFIX}.{Config.NEXUS_ASSET_EXTENSION}")

print(f"\n🏗️ Nexus Path Structure:")
print(f"   {Config.NEXUS_GROUP_ID.replace('.', '/')}/{{project}}/{{version}}/{{filename}}")

print("\n✅ All configuration values loaded successfully!")