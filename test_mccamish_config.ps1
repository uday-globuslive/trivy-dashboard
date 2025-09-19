# PowerShell Test Script for McCamish Nexus Dashboard Configuration
# This script helps verify that environment variables are properly configured

Write-Host "🔧 McCamish Nexus Dashboard Configuration Test" -ForegroundColor Cyan
Write-Host "=" * 60

# Set McCamish environment variables for testing
$env:NEXUS_URL = "http://swdlvapp682.mccamish.com:8081"
$env:NEXUS_USERNAME = "your-actual-username"  # Replace with real username  
$env:NEXUS_PASSWORD = "your-actual-password"  # Replace with real password
$env:NEXUS_REPOSITORY = "mccamish_sbom"
$env:NEXUS_GROUP_ID = "com.mccamish"
$env:NEXUS_ARTIFACT_SUFFIX = ".sbom"
$env:NEXUS_VERSION_PREFIX = "1.0.0-"
$env:NEXUS_ASSET_EXTENSION = "json"

Write-Host ""
Write-Host "📋 Current Configuration:" -ForegroundColor Yellow
Write-Host "NEXUS_URL=$env:NEXUS_URL"
Write-Host "NEXUS_REPOSITORY=$env:NEXUS_REPOSITORY"
Write-Host "NEXUS_GROUP_ID=$env:NEXUS_GROUP_ID"
Write-Host "NEXUS_ARTIFACT_SUFFIX=$env:NEXUS_ARTIFACT_SUFFIX"
Write-Host ""

# Test configuration
Write-Host "Testing configuration..." -ForegroundColor Green
python test_config.py

# Build Docker image with current fixes
Write-Host ""
Write-Host "🐳 Building Docker image with fixed configuration..." -ForegroundColor Blue
docker build -t mccamish-trivy-dashboard:test .

# Run container with McCamish configuration
Write-Host ""
Write-Host "🚀 Starting container with McCamish Nexus configuration..." -ForegroundColor Green
docker run -d `
  --name trivy-dashboard-test `
  -p 5000:5000 `
  -e NEXUS_URL="$env:NEXUS_URL" `
  -e NEXUS_USERNAME="$env:NEXUS_USERNAME" `
  -e NEXUS_PASSWORD="$env:NEXUS_PASSWORD" `
  -e NEXUS_REPOSITORY="$env:NEXUS_REPOSITORY" `
  -e NEXUS_GROUP_ID="$env:NEXUS_GROUP_ID" `
  -e NEXUS_ARTIFACT_SUFFIX="$env:NEXUS_ARTIFACT_SUFFIX" `
  -e NEXUS_VERSION_PREFIX="$env:NEXUS_VERSION_PREFIX" `
  -e NEXUS_ASSET_EXTENSION="$env:NEXUS_ASSET_EXTENSION" `
  mccamish-trivy-dashboard:test

Write-Host ""
Write-Host "⏳ Waiting for container to start..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

Write-Host ""
Write-Host "🔍 Testing debug endpoint..." -ForegroundColor Cyan
try {
    $response = Invoke-RestMethod -Uri "http://localhost:5000/debug/nexus" -Method Get
    $response | ConvertTo-Json -Depth 10
} catch {
    Write-Host "❌ Error calling debug endpoint: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "📋 Container logs:" -ForegroundColor Yellow
docker logs trivy-dashboard-test

Write-Host ""
Write-Host "🧹 Cleaning up test container..." -ForegroundColor Magenta
docker stop trivy-dashboard-test
docker rm trivy-dashboard-test

Write-Host ""
Write-Host "✅ Test completed!" -ForegroundColor Green
Write-Host ""
Write-Host "📝 Next steps:" -ForegroundColor Cyan
Write-Host "1. Update the username and password in this script with your actual McCamish credentials"
Write-Host "2. Run this script again to test with real credentials"
Write-Host "3. Once working, build and push to your Docker registry"
