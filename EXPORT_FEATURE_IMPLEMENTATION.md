# Vulnerability Export Feature Implementation

## Overview
Added export functionality to the Recent Scans section in the individual project details page. Users can now export vulnerability details for each scan in either **PDF** or **CSV** format.

## Changes Made

### 1. Frontend Changes - `templates/project.html`

**Location:** Recent Scans table, Actions column (lines 239-251)

**Added Export Button with Dropdown Menu:**
- New "Export" button with dropdown options (PDF and CSV)
- Button styling: Green success button with download icon
- Dropdown menu with two options:
  - **Export as PDF** - Downloads vulnerabilities as a formatted PDF report
  - **Export as CSV** - Downloads vulnerabilities as a CSV spreadsheet

**HTML Structure:**
```html
<div class="btn-group" role="group">
    <button type="button" class="btn btn-sm btn-success dropdown-toggle" data-bs-toggle="dropdown" aria-expanded="false">
        <i class="fas fa-download"></i> Export
    </button>
    <ul class="dropdown-menu dropdown-menu-end">
        <li><a class="dropdown-item" href="{{ url_for('export_scan_vulnerabilities', scan_id=scan.id, format='pdf') }}"><i class="fas fa-file-pdf text-danger"></i> Export as PDF</a></li>
        <li><a class="dropdown-item" href="{{ url_for('export_scan_vulnerabilities', scan_id=scan.id, format='csv') }}"><i class="fas fa-file-csv text-success"></i> Export as CSV</a></li>
    </ul>
</div>
```

### 2. Backend Changes - `app.py`

**Added Three New Functions:**

#### a) `export_scan_vulnerabilities(scan_id, format)` - Main Route Handler
- **Route:** `/scan/<scan_id>/export/vulnerabilities/<format>`
- **Parameters:**
  - `scan_id`: ID of the scan to export
  - `format`: Either 'pdf' or 'csv'
- **Function:** Routes the request to appropriate export function based on format

#### b) `_export_vulnerabilities_pdf(scan)` - PDF Generation
**Features:**
- Creates a professional PDF report with landscape orientation
- **Report Sections:**
  1. Title with project and scan information
  2. Scan metadata table (Project, Build Number, Branch, Scan Date, Total Vulnerabilities)
  3. Vulnerability summary by severity (Critical, High, Medium, Low)
  4. Detailed vulnerability table with columns:
     - CVE ID
     - Severity (with color coding)
     - Package Name
     - Installed Version
     - Fixed Version
     - Type
  5. Report generation timestamp

**Styling:**
- Professional color scheme with dark blue headers
- Color-coded severity levels
- Proper spacing and formatting
- Timezone support (default: Asia/Kolkata, customizable via `timezone` query parameter)

#### c) `_export_vulnerabilities_csv(scan)` - CSV Generation
**Features:**
- Creates a well-structured CSV file
- **Report Sections:**
  1. Header with report title
  2. Scan metadata (Project, Build Number, Branch, Scan Date, Report Generated)
  3. Vulnerability summary statistics
  4. Detailed vulnerability list with columns:
     - CVE ID
     - Severity
     - Package Name
     - Installed Version
     - Fixed Version
     - Type
     - Description (first 100 characters)

**Formatting:**
- UTF-8 encoding with BOM for Excel compatibility
- Descriptive section headers
- Timezone support (default: Asia/Kolkata, customizable via `timezone` query parameter)

## File Naming

Export files are named with the following convention:
- **PDF:** `vulnerabilities_{project_name}_{build_number}.pdf`
- **CSV:** `vulnerabilities_{project_name}_{build_number}.csv`

Example: `vulnerabilities_MyProject_build-123.pdf`

## Timezone Support

Both PDF and CSV exports support timezone customization via the `timezone` query parameter:
```
/scan/{scan_id}/export/vulnerabilities/pdf?timezone=America/New_York
/scan/{scan_id}/export/vulnerabilities/csv?timezone=Europe/London
```

Supported timezone examples:
- `Asia/Kolkata` (default)
- `America/New_York`
- `Europe/London`
- `UTC`
- And all other valid IANA timezone names

## Technical Implementation Details

### Dependencies Used
- **reportlab** - For PDF generation (already in requirements.txt)
- **csv** - Python standard library for CSV handling
- **io** - Python standard library for buffer operations
- **pytz** - For timezone handling (already in requirements.txt)

### Error Handling
- Returns 404 if scan not found
- Returns 400 if invalid export format requested
- Gracefully handles missing or null fields with 'N/A' or 'Unknown' defaults

## User Experience

### For PDF Exports:
1. Click the "Export" button in the Actions column
2. Select "Export as PDF" from dropdown
3. Browser downloads a professionally formatted PDF with all vulnerability details
4. Can be opened in any PDF reader or printed

### For CSV Exports:
1. Click the "Export" button in the Actions column
2. Select "Export as CSV" from dropdown
3. Browser downloads a CSV file
4. Can be opened in Excel, Google Sheets, or any spreadsheet application
5. Easy to sort, filter, and analyze data

## Integration Points

The new export feature integrates seamlessly with:
- Existing scan data structure in `app_data['scans']`
- Current vulnerability data format
- Flask's `send_file` function for downloads
- Bootstrap dropdown components (already used throughout the app)

## Testing Notes

The implementation has been tested for:
- ✓ Python syntax validation (py_compile)
- ✓ Module import test
- ✓ Route function correctness
- ✓ Error handling for missing scans
- ✓ Proper file download headers
- ✓ Template integration with existing UI

## Future Enhancement Possibilities

1. Add export for all scans of a project at once
2. Add email delivery of reports
3. Add scheduled report generation
4. Add custom report template selection
5. Add additional formats (Excel XLSX, JSON)
6. Add report filtering options (by severity, date range)

---

**Implementation Date:** January 17, 2026  
**Feature Status:** Complete and Ready for Production
