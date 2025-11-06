# Export Functionality Fix

## Issue Resolution

### Problem
When clicking export and selecting JSON or SPDX format, the exported files were getting named as `unknown_unknown` instead of meaningful filenames.

### Root Cause
The export functions in `app.py` were trying to access incorrect scan data keys:
- Looking for `'project_name'` but scan data stores it as `'project'`
- Looking for `'scan_date'` but scan data stores it as `'timestamp'`

### Solution
Fixed both export routes (`/scan/<scan_id>/sbom/export` and `/scan/<scan_id>/sbom/export/json`) to:

1. **Use Correct Data Keys**:
   ```python
   # BEFORE (incorrect)
   project_name = scan.get('project_name', 'unknown')  # ❌ Wrong key
   scan_date = scan.get('scan_date', 'unknown')        # ❌ Wrong key
   
   # AFTER (correct)
   project_name = scan.get('project', 'unknown')       # ✅ Correct key
   build_number = scan.get('build_number', 'unknown')  # ✅ Added build number
   scan_timestamp = scan.get('timestamp', 'unknown')   # ✅ Correct key
   ```

2. **Handle Datetime Objects Properly**:
   ```python
   # Format timestamp for filename
   if scan_timestamp != 'unknown' and hasattr(scan_timestamp, 'strftime'):
       scan_date = scan_timestamp.strftime('%Y%m%d_%H%M%S')
   else:
       scan_date = str(scan_timestamp).replace(':', '-').replace(' ', '_') if scan_timestamp != 'unknown' else 'unknown'
   ```

3. **Generate Meaningful Filenames**:
   ```python
   # New filename format includes project, build number, and timestamp
   filename = f"{project_name}-build{build_number}-{scan_date}-sbom.spdx"
   filename = f"{project_name}-build{build_number}-{scan_date}-sbom.json"
   ```

## How Filename Generation Works

### Data Source
The filename components come from the scan data stored in `app_data['scans'][scan_id]`:

```python
scan_data = {
    'id': scan_id,
    'project': project_name,           # Used for filename ✅
    'build_number': build_number,      # Used for filename ✅  
    'timestamp': timestamp_datetime,   # Used for filename ✅
    'trivy_report_path': path,
    'vulnerabilities': [...],
    'components': [...],
    'metadata': {...}
}
```

### Filename Components

1. **Project Name**: Extracted from `scan.get('project')` 
   - Source: Parsed from Nexus artifact metadata
   - Example: `Mart_Trivy_Scan.sbom`

2. **Build Number**: Extracted from `scan.get('build_number')`
   - Source: Parsed from Nexus version string (e.g., `1.0.0-20251106112049`)
   - Example: `20251106112049`

3. **Timestamp**: Extracted from `scan.get('timestamp')`
   - Source: Nexus asset `lastModified` field, parsed as datetime object
   - Format: `YYYYMMDD_HHMMSS` (e.g., `20251106_112049`)

### Example Filenames

For a scan with:
- Project: `Mart_Trivy_Scan.sbom`
- Build: `20251106112049` 
- Timestamp: `2025-11-06 11:20:49`

Generated filenames:
- **SPDX**: `Mart_Trivy_Scan.sbom-build20251106112049-20251106_112049-sbom.spdx`
- **JSON**: `Mart_Trivy_Scan.sbom-build20251106112049-20251106_112049-sbom.json`

## Testing the Fix

1. **Start the Dashboard**:
   ```bash
   python app.py
   ```

2. **Navigate to a Scan**:
   - Go to http://localhost:5002
   - Click on a project
   - Click on a scan

3. **Test Export**:
   - Click "Export" button in scan details
   - Select "SPDX Text" or "JSON" format
   - Verify the downloaded file has a meaningful name instead of `unknown_unknown`

## Code Changes Made

### File: `app.py`

**Function**: `export_comprehensive_sbom()` (line ~800)
**Function**: `export_comprehensive_sbom_json()` (line ~853)

**Changes**:
- Fixed data key access from `'project_name'` → `'project'`
- Fixed data key access from `'scan_date'` → `'timestamp'`
- Added build number to filename for better identification
- Added proper datetime handling for timestamp formatting
- Improved filename format: `{project}-build{build_number}-{timestamp}-sbom.{ext}`

## Verification

The fix ensures that:
- ✅ Export filenames are meaningful and descriptive
- ✅ Filenames include project name, build number, and timestamp
- ✅ Special characters in timestamps are properly handled
- ✅ Both SPDX and JSON exports work correctly
- ✅ Fallback to 'unknown' only occurs if data is genuinely missing

---

*Fix applied on 2025-11-06 by correcting scan data key access in export functions.*