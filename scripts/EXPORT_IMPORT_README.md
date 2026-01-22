# Trivy Data Export/Import Scripts

These scripts allow you to export Trivy report data from JFrog Artifactory and import it into Nexus Repository for testing and integration purposes.

## Overview

### 1. Export from JFrog (`export_jfrog_data.py`)
- Connects to JFrog Artifactory
- Discovers all JSON files in the repository
- Downloads all files locally
- Creates a manifest for tracking

### 2. Import to Nexus (`import_to_nexus.py`)
- Reads the exported data manifest
- Creates a new raw repository in Nexus (if it doesn't exist)
- Uploads all exported files to Nexus
- Maintains directory structure

## Prerequisites

Install required Python packages:
```bash
pip install requests python-dotenv
```

## Usage

### Step 1: Export Data from JFrog

Set up your JFrog environment variables:
```bash
# Windows PowerShell
$env:JFROG_URL="https://your-jfrog-url"
$env:JFROG_USERNAME="your-username"
$env:JFROG_PASSWORD="your-password"
$env:JFROG_REPOSITORY="sbom"
$env:EXPORT_DIR="./jfrog_export"
```

Or create a `.env` file:
```
JFROG_URL=https://your-jfrog-url
JFROG_USERNAME=your-username
JFROG_PASSWORD=your-password
JFROG_REPOSITORY=sbom
EXPORT_DIR=./jfrog_export
```

Run the export script:
```bash
python scripts/export_jfrog_data.py
```

This will:
- Download all JSON files from JFrog
- Save them to `./jfrog_export/files/` directory
- Create a `manifest.json` file tracking all files

### Step 2: Import Data to Nexus

Set up your Nexus environment variables:
```bash
# Windows PowerShell
$env:NEXUS_URL="https://your-nexus-url"
$env:NEXUS_USERNAME="admin"
$env:NEXUS_PASSWORD="admin123"
$env:NEXUS_REPOSITORY="mccamish_sbom"
$env:IMPORT_DIR="./jfrog_export"
```

Or add to your `.env` file:
```
NEXUS_URL=https://your-nexus-url
NEXUS_USERNAME=admin
NEXUS_PASSWORD=admin123
NEXUS_REPOSITORY=mccamish_sbom
IMPORT_DIR=./jfrog_export
```

Run the import script:
```bash
python scripts/import_to_nexus.py
```

This will:
- Create a new raw repository in Nexus if it doesn't exist
- Upload all files maintaining the original directory structure
- Report upload status

## Environment Variables

### Export Script (`export_jfrog_data.py`)
| Variable | Default | Description |
|----------|---------|-------------|
| `JFROG_URL` | Required | JFrog Artifactory base URL |
| `JFROG_USERNAME` | Required | JFrog username |
| `JFROG_PASSWORD` | Required | JFrog password/API key |
| `JFROG_REPOSITORY` | `sbom` | Repository name in JFrog |
| `EXPORT_DIR` | `./jfrog_export` | Local directory to export files |
| `EXPORT_MANIFEST` | `{EXPORT_DIR}/manifest.json` | Manifest file location |

### Import Script (`import_to_nexus.py`)
| Variable | Default | Description |
|----------|---------|-------------|
| `NEXUS_URL` | Required | Nexus base URL |
| `NEXUS_USERNAME` | Required | Nexus username |
| `NEXUS_PASSWORD` | Required | Nexus password |
| `NEXUS_REPOSITORY` | `mccamish_sbom` | Repository name to create/use |
| `IMPORT_DIR` | `./jfrog_export` | Directory with exported data |
| `IMPORT_MANIFEST` | `{IMPORT_DIR}/manifest.json` | Manifest file location |

## Output Structure

After export, your directory structure will be:
```
jfrog_export/
├── manifest.json          # Metadata and file tracking
└── files/
    ├── com/
    │   └── yourcompany/
    │       ├── project1/
    │       │   └── 1.0.0-20250622161605/
    │       │       └── project1-1.0.0-20250622161605.json
    │       └── project2/
    │           └── 1.0.0-20250626214412/
    │               └── project2-1.0.0-20250626214412.json
    └── ... (maintains original JFrog structure)
```

## Manifest File Format

The `manifest.json` contains:
```json
{
  "export_date": "2026-01-22T12:34:56.789012",
  "jfrog_url": "https://your-jfrog-url",
  "jfrog_repository": "sbom",
  "total_files": 915,
  "files": [
    {
      "jfrog_path": "com/yourcompany/project1/1.0.0-20250622161605/project1-1.0.0-20250622161605.json",
      "local_path": "./jfrog_export/files/com/yourcompany/project1/1.0.0-20250622161605/project1-1.0.0-20250622161605.json",
      "filename": "project1-1.0.0-20250622161605.json",
      "size": 125000,
      "downloaded": true
    }
  ]
}
```

## Troubleshooting

### Export Issues
- **No files found**: Check JFrog repository name and credentials
- **Download failures**: May be temporary - script continues with other files
- **Timeout errors**: Increase network timeout or reduce batch size

### Import Issues
- **Repository creation fails**: Check Nexus admin credentials and permissions
- **Upload failures**: Ensure Nexus repository permissions allow uploads
- **Large file transfers**: May take time for 900+ files - be patient

## Example Workflow

```bash
# 1. Export from JFrog
$env:JFROG_URL="https://jfrog.mccamish.com"
$env:JFROG_USERNAME="automation"
$env:JFROG_PASSWORD="api-token-here"
python scripts/export_jfrog_data.py

# Output: 915 files downloaded to ./jfrog_export/

# 2. Import to Nexus
$env:NEXUS_URL="https://nexus.mccamish.com"
$env:NEXUS_USERNAME="admin"
$env:NEXUS_PASSWORD="nexus-password"
python scripts/import_to_nexus.py

# Output: All 915 files uploaded to Nexus mccamish_sbom repository
```

## Testing the Dashboard

After import to Nexus:

1. Update your `.env` file to use Nexus:
```
ARTIFACTORY_TYPE=nexus
NEXUS_URL=https://nexus.mccamish.com
NEXUS_USERNAME=admin
NEXUS_PASSWORD=nexus-password
NEXUS_REPOSITORY=mccamish_sbom
```

2. Restart the dashboard:
```bash
python app.py
```

3. Navigate to `http://localhost:5000/projects` - you should now see all 23 projects with their scans!

## Notes

- Files are downloaded/uploaded as-is, preserving their structure
- The scripts skip checksum files (.sha1, .sha256, etc.)
- Export can be run multiple times to sync new files
- Import creates the repository if it doesn't exist
- Both scripts include comprehensive logging for debugging
