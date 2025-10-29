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

# Get Nexus version info
function Get-NexusVersion {
    try {
        $versionUrl = "$env:NEXUS_URL/service/rest/v1/status"
        $headers = Get-AuthHeader
        $response = Invoke-RestMethod -Uri $versionUrl -Headers $headers -Method GET
        return $response.version
    } catch {
        Write-Log "Could not retrieve Nexus version: $($_.Exception.Message)" "WARN"
        return "Unknown"
    }
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
        $_.assets[0].path -notlike "*$env:TRIVY_REPORT_SUFFIX.*" -and
        $_.assets[0].path -like "*$env:NEXUS_ARTIFACT_SUFFIX*"
    }
    
    Write-Log "Found $($sbomFiles.Count) SBOM files"
    return $sbomFiles
}

# Check if trivy report already exists
function Test-TrivyReportExists {
    param($SbomAsset)
    
    $trivyPath = $SbomAsset.path -replace "\.$env:NEXUS_ASSET_EXTENSION$", "$env:TRIVY_REPORT_SUFFIX.$env:NEXUS_ASSET_EXTENSION"
    $checkUrl = "$env:NEXUS_URL/repository/$env:NEXUS_REPOSITORY/$trivyPath"
    $headers = Get-AuthHeader
    
    try {
        Invoke-RestMethod -Uri $checkUrl -Method HEAD -Headers $headers | Out-Null
        return $true
    } catch {
        return $false
    }
}

# Generate checksums manually if Nexus doesn't create them
function New-ChecksumFiles {
    param($FilePath, $UploadUrl, $Headers)
    
    Write-Log "  Generating and uploading checksum files..."
    
    try {
        $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
        
        # Generate checksums
        $md5 = [System.Security.Cryptography.MD5]::Create()
        $sha1 = [System.Security.Cryptography.SHA1]::Create()
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $sha512 = [System.Security.Cryptography.SHA512]::Create()
        
        $md5Hash = [System.BitConverter]::ToString($md5.ComputeHash($fileBytes)).Replace("-", "").ToLower()
        $sha1Hash = [System.BitConverter]::ToString($sha1.ComputeHash($fileBytes)).Replace("-", "").ToLower()
        $sha256Hash = [System.BitConverter]::ToString($sha256.ComputeHash($fileBytes)).Replace("-", "").ToLower()
        $sha512Hash = [System.BitConverter]::ToString($sha512.ComputeHash($fileBytes)).Replace("-", "").ToLower()
        
        # Upload checksum files
        $checksums = @{
            ".md5" = $md5Hash
            ".sha1" = $sha1Hash
            ".sha256" = $sha256Hash
            ".sha512" = $sha512Hash
        }
        
        foreach ($ext in $checksums.Keys) {
            $checksumUrl = "$UploadUrl$ext"
            $checksumContent = $checksums[$ext]
            
            try {
                Invoke-RestMethod -Uri $checksumUrl -Method PUT -Headers $Headers -Body $checksumContent -ContentType "text/plain"
                Write-Log "    Uploaded $ext checksum" "SUCCESS"
            } catch {
                Write-Log "    Failed to upload $ext checksum: $($_.Exception.Message)" "WARN"
            }
        }
        
        # Cleanup
        $md5.Dispose()
        $sha1.Dispose() 
        $sha256.Dispose()
        $sha512.Dispose()
        
    } catch {
        Write-Log "  Error generating checksums: $($_.Exception.Message)" "ERROR"
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
        $tempTrivy = "$env:TEMP\$baseName$env:TRIVY_REPORT_SUFFIX.$env:NEXUS_ASSET_EXTENSION"
        
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
        
        # Upload trivy report using original PUT method
        Write-Log "  Uploading Trivy report..."
        $uploadPath = $asset.path -replace "\.$env:NEXUS_ASSET_EXTENSION$", "$env:TRIVY_REPORT_SUFFIX.$env:NEXUS_ASSET_EXTENSION"
        $uploadUrl = "$env:NEXUS_URL/repository/$env:NEXUS_REPOSITORY/$uploadPath"
        
        # Upload the main file
        Invoke-RestMethod -Uri $uploadUrl -Method PUT -Headers $headers -InFile $tempTrivy -ContentType "application/json"
        
        # Check if checksums were created automatically, if not create them manually
        Start-Sleep -Seconds 2  # Give Nexus time to generate checksums
        
        $md5CheckUrl = "$uploadUrl.md5"
        try {
            Invoke-RestMethod -Uri $md5CheckUrl -Method HEAD -Headers $headers | Out-Null
            Write-Log "  Checksums generated automatically by Nexus" "SUCCESS"
        } catch {
            Write-Log "  Checksums not generated automatically, creating manually..." "WARN"
            New-ChecksumFiles -FilePath $tempTrivy -UploadUrl $uploadUrl -Headers $headers
        }
        
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
    
    # Check Nexus version
    $nexusVersion = Get-NexusVersion
    Write-Log "Nexus Version: $nexusVersion"
    
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
