#!/bin/bash

# Test script for McCamish Nexus Dashboard Configuration
# This script helps verify that environment variables are properly configured

echo "🔧 McCamish Nexus Dashboard Configuration Test"
echo "=" * 60

# Set McCamish environment variables for testing
export NEXUS_URL="http://swdlvapp682.mccamish.com:8081"
export NEXUS_USERNAME="your-actual-username"  # Replace with real username
export NEXUS_PASSWORD="your-actual-password"  # Replace with real password
export NEXUS_REPOSITORY="mccamish_sbom"
export NEXUS_GROUP_ID="com.mccamish"
export NEXUS_ARTIFACT_SUFFIX=".sbom"
export NEXUS_VERSION_PREFIX="1.0.0-"
export NEXUS_ASSET_EXTENSION="json"

echo ""
echo "📋 Current Configuration:"
echo "NEXUS_URL=$NEXUS_URL"
echo "NEXUS_REPOSITORY=$NEXUS_REPOSITORY"
echo "NEXUS_GROUP_ID=$NEXUS_GROUP_ID"
echo "NEXUS_ARTIFACT_SUFFIX=$NEXUS_ARTIFACT_SUFFIX"
echo ""

# Test configuration
echo "Testing configuration..."
python test_config.py

# Build Docker image with current fixes
echo ""
echo "🐳 Building Docker image with fixed configuration..."
docker build -t mccamish-trivy-dashboard:test .

# Run container with McCamish configuration
echo ""
echo "🚀 Starting container with McCamish Nexus configuration..."
docker run -d \
  --name trivy-dashboard-test \
  -p 5000:5000 \
  -e NEXUS_URL="$NEXUS_URL" \
  -e NEXUS_USERNAME="$NEXUS_USERNAME" \
  -e NEXUS_PASSWORD="$NEXUS_PASSWORD" \
  -e NEXUS_REPOSITORY="$NEXUS_REPOSITORY" \
  -e NEXUS_GROUP_ID="$NEXUS_GROUP_ID" \
  -e NEXUS_ARTIFACT_SUFFIX="$NEXUS_ARTIFACT_SUFFIX" \
  -e NEXUS_VERSION_PREFIX="$NEXUS_VERSION_PREFIX" \
  -e NEXUS_ASSET_EXTENSION="$NEXUS_ASSET_EXTENSION" \
  mccamish-trivy-dashboard:test

echo ""
echo "⏳ Waiting for container to start..."
sleep 10

echo ""
echo "🔍 Testing debug endpoint..."
curl -s http://localhost:5000/debug/nexus | python -m json.tool

echo ""
echo "📋 Container logs:"
docker logs trivy-dashboard-test

echo ""
echo "🧹 Cleaning up test container..."
docker stop trivy-dashboard-test
docker rm trivy-dashboard-test

echo ""
echo "✅ Test completed!"
