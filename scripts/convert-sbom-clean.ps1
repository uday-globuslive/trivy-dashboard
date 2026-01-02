# SBOM to Trivy Report Conversion Utility (Pure PowerShell JSON Transformation)
param(
    [switch]$DryRun,
    [switch]$Force,
    [int]$MaxFiles = 100
)

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

function Get-AuthHeader {
    $auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$env:NEXUS_USERNAME`:$env:NEXUS_PASSWORD"))
    return @{ Authorization = "Basic $auth" }
}

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
    $sbomFiles = $allFiles | Where-Object {
        $_.assets -and
        $_.assets[0].path -like "*.$env:NEXUS_ASSET_EXTENSION" -and
        $_.assets[0].path -notlike "*$env:TRIVY_REPORT_SUFFIX.*" -and
        $_.assets[0].path -like "*$env:NEXUS_ARTIFACT_SUFFIX*"
    }
    Write-Log "Found $($sbomFiles.Count) SBOM files"
    return $sbomFiles
}

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

function New-ChecksumFiles {
    param($FilePath, $UploadUrl, $Headers)
    Write-Log "  Generating and uploading checksum files..."
    try {
        $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
        $md5 = [System.Security.Cryptography.MD5]::Create()
        $sha1 = [System.Security.Cryptography.SHA1]::Create()
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $sha512 = [System.Security.Cryptography.SHA512]::Create()
        $md5Hash = [System.BitConverter]::ToString($md5.ComputeHash($fileBytes)).Replace("-", "").ToLower()
        $sha1Hash = [System.BitConverter]::ToString($sha1.ComputeHash($fileBytes)).Replace("-", "").ToLower()
        $sha256Hash = [System.BitConverter]::ToString($sha256.ComputeHash($fileBytes)).Replace("-", "").ToLower()
        $sha512Hash = [System.BitConverter]::ToString($sha512.ComputeHash($fileBytes)).Replace("-", "").ToLower()
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
        $md5.Dispose(); $sha1.Dispose(); $sha256.Dispose(); $sha512.Dispose()
    } catch {
        Write-Log "  Error generating checksums: $($_.Exception.Message)" "ERROR"
    }
}

function Convert-CycloneDXToTrivy {
    param ($CycloneDXPath, $OutputPath)
    $sbom = Get-Content $CycloneDXPath | ConvertFrom-Json
    $components = $sbom.components
    $vulns = $sbom.vulnerabilities
    $results = @()
    foreach ($component in $components) {
        $compId = if ($component.'bom-ref') { $component.'bom-ref' } else { $component.purl }
        $compName = $component.name
        $compType = $component.type
        $compVersion = $component.version
        $componentVulns = @()
        foreach ($vuln in $vulns) {
            if ($vuln.affects) {
                foreach ($aff in $vuln.affects) {
                    if ($aff.ref -eq $compId) {
                        $componentVulns += [PSCustomObject]@{
                            VulnerabilityID     = $vuln.id
                            PkgName             = $compName
                            InstalledVersion    = $compVersion
                            FixedVersion        = $vuln.recommendation
                            Severity            = $vuln.severity
                            Description         = $vuln.description
                        }
                    }
                }
            }
        }
        if ($componentVulns.Count -gt 0) {
            $results += [PSCustomObject]@{
                Target          = $compName
                Class           = "lang-pkgs"
                Type            = $compType
                Vulnerabilities = $componentVulns
            }
        }
    }
    $trivyObj = [PSCustomObject]@{
        SchemaVersion  = 2
        ArtifactName   = if ($sbom.metadata.name) { $sbom.metadata.name } else { 'unknown' }
        ArtifactType   = "library"
        Metadata       = @{}
        Results        = $results
    }
    $trivyJson = $trivyObj | ConvertTo-Json -Depth 5
    Set-Content -Path $OutputPath -Value $trivyJson
}

function Convert-SbomFile {
    param($Component)
    $asset = $Component.assets[0]
    $downloadUrl = $asset.downloadUrl
    $filename = Split-Path $asset.path -Leaf
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($filename)
    Write-Log "Processing: $filename"
    if (-not $Force -and (Test-TrivyReportExists $asset)) {
        Write-Log "  Trivy report already exists, skipping" "WARN"
        return $true
    }
    if ($DryRun) {
        Write-Log "  [DRY RUN] Would convert $filename" "SUCCESS"
        return $true
    }
    try {
		$tempSbom = Join-Path $env:TEMP $filename
		$tempTrivy = Join-Path $env:TEMP ("$baseName$($env:TRIVY_REPORT_SUFFIX).$($env:NEXUS_ASSET_EXTENSION)")
        Write-Log "  Downloading SBOM..."
        $headers = Get-AuthHeader
        Invoke-WebRequest -Uri $downloadUrl -Headers $headers -OutFile $tempSbom
        # --- CycloneDX → Trivy Transformation ---
        Write-Log "  Converting CycloneDX to Trivy-compatible JSON..."
        Convert-CycloneDXToTrivy -CycloneDXPath $tempSbom -OutputPath $tempTrivy
        Write-Log "  Uploading Trivy report..."
        $uploadPath = $asset.path -replace "\.$env:NEXUS_ASSET_EXTENSION$", "$env:TRIVY_REPORT_SUFFIX.$env:NEXUS_ASSET_EXTENSION"
        $uploadUrl = "$env:NEXUS_URL/repository/$env:NEXUS_REPOSITORY/$uploadPath"
        Invoke-RestMethod -Uri $uploadUrl -Method PUT -Headers $headers -InFile $tempTrivy -ContentType "application/json"
        Start-Sleep -Seconds 2
        $md5CheckUrl = "$uploadUrl.md5"
        try {
            Invoke-RestMethod -Uri $md5CheckUrl -Method HEAD -Headers $headers | Out-Null
            Write-Log "  Checksums generated automatically by Nexus" "SUCCESS"
        } catch {
            Write-Log "  Checksums not generated automatically, creating manually..." "WARN"
            New-ChecksumFiles -FilePath $tempTrivy -UploadUrl $uploadUrl -Headers $headers
        }
        Remove-Item $tempSbom -ErrorAction SilentlyContinue
        Remove-Item $tempTrivy -ErrorAction SilentlyContinue
        Write-Log "  Successfully converted $filename" "SUCCESS"
        return $true
    } catch {
        Write-Log "  Error converting $($filename): $($_.Exception.Message)" "ERROR"
        Remove-Item $tempSbom -ErrorAction SilentlyContinue
        Remove-Item $tempTrivy -ErrorAction SilentlyContinue
        return $false
    }
}

function Main {
    Write-Log "SBOM to Trivy Report Conversion Starting"
    Write-Log "Mode: $(if($DryRun){'DRY RUN'}else{'LIVE CONVERSION'})"
    Import-EnvFile
    $nexusVersion = Get-NexusVersion
    Write-Log "Nexus Version: $nexusVersion"
    $sbomFiles = Get-SbomFiles
    if ($sbomFiles.Count -eq 0) {
        Write-Log "No SBOM files found to convert" "WARN"
        return
    }
    if ($sbomFiles.Count -gt $MaxFiles) {
        Write-Log "Limiting to first $MaxFiles files (found $($sbomFiles.Count))" "WARN"
        $sbomFiles = $sbomFiles | Select-Object -First $MaxFiles
    }
    $success = 0; $failed = 0
    foreach ($file in $sbomFiles) {
        if (Convert-SbomFile $file) { $success++ } else { $failed++ }
    }
    Write-Log ""
    Write-Log "Conversion Summary:"
    Write-Log "  Total processed: $($sbomFiles.Count)"
    Write-Log "  Successful: $success" "SUCCESS"
    Write-Log "  Failed: $failed" $(if($failed -gt 0){"ERROR"}else{"SUCCESS"})
}

if ($MyInvocation.InvocationName -ne '.') { Main }
