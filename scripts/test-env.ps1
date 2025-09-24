# Simple Environment Test for SBOM Conversion Utilities
Write-Host "Testing SBOM Conversion Environment" -ForegroundColor Cyan

# Load environment file
if (Test-Path ".env") {
    Write-Host "Found .env configuration file" -ForegroundColor Green
    Get-Content ".env" | Where-Object { $_ -match "^[^#].*=" } | ForEach-Object {
        $parts = $_ -split "=", 2
        $name = $parts[0].Trim()
        $value = $parts[1].Trim().Trim('"').Trim("'")
        [Environment]::SetEnvironmentVariable($name, $value, 'Process')
    }
    Write-Host "Configuration loaded successfully" -ForegroundColor Gray
} else {
    Write-Host "ERROR: .env file not found" -ForegroundColor Red
    exit 1
}

# Check for Trivy executable
if (Test-Path ".\trivy\trivy.exe") {
    Write-Host "Trivy executable found" -ForegroundColor Green
    try {
        $version = & ".\trivy\trivy.exe" --version 2>$null | Select-Object -First 1
        Write-Host "Version: $($version.Trim())" -ForegroundColor Gray
    } catch {
        Write-Host "Warning: Could not get Trivy version" -ForegroundColor Yellow
    }
} else {
    Write-Host "ERROR: Trivy executable not found at .\trivy\trivy.exe" -ForegroundColor Red
}

# Test Nexus connectivity
Write-Host "Testing Nexus connectivity..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "$env:NEXUS_URL/service/rest/v1/status" -TimeoutSec 5 -UseBasicParsing
    if ($response.StatusCode -eq 200) {
        Write-Host "Nexus is reachable" -ForegroundColor Green
    }
} catch {
    Write-Host "Cannot reach Nexus server" -ForegroundColor Red
}

# Check credentials
if ($env:NEXUS_USERNAME -and $env:NEXUS_PASSWORD) {
    Write-Host "Nexus credentials configured" -ForegroundColor Green
    Write-Host "Username: $env:NEXUS_USERNAME" -ForegroundColor Gray
} else {
    Write-Host "ERROR: Nexus credentials missing" -ForegroundColor Red
}

Write-Host ""
Write-Host "Summary: Environment check complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:"
Write-Host "1. Run dry test: .\convert-sbom-clean.ps1 -DryRun"
Write-Host "2. Run conversion: .\convert-sbom-clean.ps1"
Write-Host ""

$null = Read-Host "Press Enter to continue"