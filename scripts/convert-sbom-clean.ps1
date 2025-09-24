# SBOM to Trivy Report Conversion Utility
# Uses local Trivy installation and .env configuration
param(
    [switch]$DryRun,
    [switch]$Force,
    [int]$MaxFiles = 100
)

# Load configuration from .env file
function Import-EnvFile {
    param([string]$Path = ".env")
    
    if (-not (Test-Path $Path)) {
        Write-Host "ERROR: .env file not found at $Path" -ForegroundColor Red
        exit 1
    }
    
    Get-Content $Path | Where-Object { $_ -match '^[^#].*=' } | ForEach-Object {
        $parts = $_ -split '=', 2
        $name = $parts[0].Trim()
        $value = $parts[1].Trim().Trim('"').Trim("'")
        [Environment]::SetEnvironmentVariable($name, $value, 'Process')
    }
}

# Logging function
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    
    $color = switch($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" } 
        "SUCCESS" { "Green" }
        default { "White" }
    }
    
    $timestamp = Get-Date -Format "HH:mm:ss"
    Write-Host "[$timestamp] $Message" -ForegroundColor $color
}

# Get authentication header for Nexus
function Get-AuthHeader {
    $auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$env:NEXUS_USERNAME`:$env:NEXUS_PASSWORD"))
    return @{ Authorization = "Basic $auth" }
}

# Get list of SBOM files from Nexus
function Get-SbomFiles {
    Write-Log "Fetching SBOM files from Nexus repository: $env:NEXUS_REPOSITORY"
    
    $url = "$env:NEXUS_URL/service/rest/v1/components?repository=$env:NEXUS_REPOSITORY"
    $headers = Get-AuthHeader
    $allFiles = @()
    
    do {
        try {
            $response = Invoke-RestMethod -Uri $url -Headers $headers -Method GET
            $allFiles += $response.items
            if ($response.continuationToken) {
                $url = "$($url.Split('&')[0])&continuationToken=$($response.continuationToken)"
            } else {
                $url = $null
            }
        } catch {
            Write-Log "Error fetching files: $($_.Exception.Message)" "ERROR"
            return @()
        }
    } while ($url)
    
    # Filter for SBOM files (not trivy reports)
    $sbomFiles = $allFiles | Where-Object {
        $_.assets -and 
        $_.assets[0].path -like "*.$env:NEXUS_ASSET_EXTENSION" -and
        $_.assets[0].path -notlike "*-trivy-report.*" -and
        $_.assets[0].path -like "*$env:NEXUS_ARTIFACT_SUFFIX*"
    }
    
    Write-Log "Found $($sbomFiles.Count) SBOM files"
    return $sbomFiles
}

# Check if trivy report already exists
function Test-TrivyReportExists {
    param($SbomAsset)
    
    $trivyPath = $SbomAsset.path -replace "\.$env:NEXUS_ASSET_EXTENSION$", "-trivy-report.$env:NEXUS_ASSET_EXTENSION"
    $checkUrl = "$env:NEXUS_URL/repository/$env:NEXUS_REPOSITORY/$trivyPath"
    $headers = Get-AuthHeader
    
    try {
        Invoke-RestMethod -Uri $checkUrl -Method HEAD -Headers $headers | Out-Null
        return $true
    } catch {
        return $false
    }
}

# Convert single SBOM file
function Convert-SbomFile {
    param($Component)
    
    $asset = $Component.assets[0]
    $downloadUrl = $asset.downloadUrl
    $filename = Split-Path $asset.path -Leaf
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($filename)
    
    Write-Log "Processing: $filename"
    
    # Check if trivy report exists (unless Force is used)
    if (-not $Force -and (Test-TrivyReportExists $asset)) {
        Write-Log "  Trivy report already exists, skipping" "WARN"
        return $true
    }
    
    if ($DryRun) {
        Write-Log "  [DRY RUN] Would convert $filename" "SUCCESS"
        return $true
    }
    
    try {
        # Download SBOM file
        $tempSbom = "$env:TEMP\$filename"
        $tempTrivy = "$env:TEMP\$baseName-trivy-report.$env:NEXUS_ASSET_EXTENSION"
        
        Write-Log "  Downloading SBOM..."
        $headers = Get-AuthHeader
        Invoke-WebRequest -Uri $downloadUrl -Headers $headers -OutFile $tempSbom
        
        # Convert with Trivy
        Write-Log "  Converting with Trivy..."
        $trivyPath = ".\trivy\trivy.exe"
        & $trivyPath sbom --format json --output $tempTrivy $tempSbom
        
        if ($LASTEXITCODE -ne 0) {
            throw "Trivy conversion failed with exit code $LASTEXITCODE"
        }
        
        # Upload trivy report
        Write-Log "  Uploading Trivy report..."
        $uploadPath = $asset.path -replace "\.$env:NEXUS_ASSET_EXTENSION$", "-trivy-report.$env:NEXUS_ASSET_EXTENSION"
        $uploadUrl = "$env:NEXUS_URL/repository/$env:NEXUS_REPOSITORY/$uploadPath"
        
        Invoke-RestMethod -Uri $uploadUrl -Method PUT -Headers $headers -InFile $tempTrivy -ContentType "application/json"
        
        # Cleanup
        Remove-Item $tempSbom -ErrorAction SilentlyContinue
        Remove-Item $tempTrivy -ErrorAction SilentlyContinue
        
        Write-Log "  Successfully converted $filename" "SUCCESS"
        return $true
        
    } catch {
        Write-Log "  Error converting $($filename): $($_.Exception.Message)" "ERROR"
        # Cleanup on error
        Remove-Item $tempSbom -ErrorAction SilentlyContinue
        Remove-Item $tempTrivy -ErrorAction SilentlyContinue
        return $false
    }
}

# Main execution
function Main {
    Write-Log "SBOM to Trivy Report Conversion Starting"
    Write-Log "Mode: $(if($DryRun){'DRY RUN'}else{'LIVE CONVERSION'})"
    
    # Load environment
    Import-EnvFile
    
    # Validate Trivy
    if (-not (Test-Path ".\trivy\trivy.exe")) {
        Write-Log "ERROR: Trivy executable not found at .\trivy\trivy.exe" "ERROR"
        exit 1
    }
    
    # Get SBOM files
    $sbomFiles = Get-SbomFiles
    if ($sbomFiles.Count -eq 0) {
        Write-Log "No SBOM files found to convert" "WARN"
        return
    }
    
    # Limit processing
    if ($sbomFiles.Count -gt $MaxFiles) {
        Write-Log "Limiting to first $MaxFiles files (found $($sbomFiles.Count))" "WARN"
        $sbomFiles = $sbomFiles | Select-Object -First $MaxFiles
    }
    
    # Process files
    $success = 0
    $failed = 0
    
    foreach ($file in $sbomFiles) {
        if (Convert-SbomFile $file) {
            $success++
        } else {
            $failed++
        }
    }
    
    Write-Log ""
    Write-Log "Conversion Summary:"
    Write-Log "  Total processed: $($sbomFiles.Count)"
    Write-Log "  Successful: $success" "SUCCESS"
    Write-Log "  Failed: $failed" $(if($failed -gt 0){"ERROR"}else{"SUCCESS"})
}

# Execute if run directly
if ($MyInvocation.InvocationName -ne '.') {
    Main
}