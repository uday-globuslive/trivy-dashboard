# Vulnerability Export Feature - User Guide

## Visual Changes in the Recent Scans Table

### Before (Old Interface)
```
┌─────────────────────────────────────────────────────────────────────┐
│ Actions                                                             │
├─────────────────────────────────────────────────────────────────────┤
│ [View Details]  [SBOM Details]                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### After (New Interface with Export Feature)
```
┌──────────────────────────────────────────────────────────────────────────┐
│ Actions                                                                  │
├──────────────────────────────────────────────────────────────────────────┤
│ [View Details]  [SBOM Details]  [▼ Export]                              │
│                                    ├─ 📄 Export as PDF                   │
│                                    └─ 📊 Export as CSV                   │
└──────────────────────────────────────────────────────────────────────────┘
```

## Step-by-Step Usage

### To Export Vulnerability Report as PDF:

1. Navigate to a project detail page
2. Scroll down to "Recent Scans" section
3. For any scan, click the green **"Export"** button
4. Select **"Export as PDF"** from the dropdown menu
5. File downloads automatically as `vulnerabilities_{project}_{build_number}.pdf`
6. Open in any PDF viewer or print directly

### To Export Vulnerability Report as CSV:

1. Navigate to a project detail page
2. Scroll down to "Recent Scans" section
3. For any scan, click the green **"Export"** button
4. Select **"Export as CSV"** from the dropdown menu
5. File downloads automatically as `vulnerabilities_{project}_{build_number}.csv`
6. Open in Excel, Google Sheets, or import into your reporting tools

## PDF Report Contents

### Report Header Section
```
╔════════════════════════════════════════════════════════════════════╗
║           Vulnerability Report - ProjectName                       ║
╚════════════════════════════════════════════════════════════════════╝

┌─────────────────────────────────────────────────────────────────────┐
│ Project              │ MyProject                                    │
│ Build Number         │ build-123                                   │
│ Branch/Environment   │ main                                        │
│ Scan Date            │ 2026-01-17 21:30:45                         │
│ Total Vulnerabilities│ 42                                          │
│ Critical             │ 3                                           │
│ High                 │ 8                                           │
│ Medium               │ 15                                          │
│ Low                  │ 16                                          │
└─────────────────────────────────────────────────────────────────────┘
```

### Vulnerability Details Table
```
┌─────────────────┬──────────┬────────────────────┬──────────┬──────────┬──────────┐
│ CVE ID          │ Severity │ Package            │ Version  │ Fixed    │ Type     │
├─────────────────┼──────────┼────────────────────┼──────────┼──────────┼──────────┤
│ CVE-2021-1234   │ CRITICAL │ openssl            │ 1.1.1a   │ 1.1.1k   │ OS       │
│ CVE-2021-5678   │ HIGH     │ log4j              │ 2.14.0   │ 2.17.1   │ Library  │
│ CVE-2021-9012   │ MEDIUM   │ axios              │ 0.21.1   │ 0.27.2   │ Library  │
├─────────────────┼──────────┼────────────────────┼──────────┼──────────┼──────────┤
│ ... more rows ...                                                        │
└─────────────────┴──────────┴────────────────────┴──────────┴──────────┴──────────┘

Report generated: 2026-01-17 21:35:22 IST
```

## CSV Report Contents

The CSV file is structured for easy analysis:

```
Vulnerability Export Report

Project,MyProject
Build Number,build-123
Branch/Environment,main
Scan Date,2026-01-17 21:30:45
Report Generated,2026-01-17 21:35:22

Vulnerability Summary
Critical,3
High,8
Medium,15
Low,16
Total,42

CVE ID,Severity,Package Name,Installed Version,Fixed Version,Type,Description
CVE-2021-1234,CRITICAL,openssl,1.1.1a,1.1.1k,OS,Buffer overflow in OpenSSL...
CVE-2021-5678,HIGH,log4j,2.14.0,2.17.1,Library,Remote Code Execution in Log4J...
CVE-2021-9012,MEDIUM,axios,0.21.1,0.27.2,Library,Cross-site Request Forgery in...
... more rows ...
```

## Key Features

### 📋 What's Included
- ✓ All vulnerability details (CVE ID, Severity, Package, Version)
- ✓ Fixed version recommendations
- ✓ Scan metadata and timestamp
- ✓ Severity summary (Critical, High, Medium, Low counts)
- ✓ Project and build information
- ✓ Branch/environment information

### 🎨 PDF Benefits
- Professional formatting
- Suitable for sharing with stakeholders
- Color-coded severity levels
- Print-ready layout
- Landscape orientation for better readability of tables

### 📊 CSV Benefits
- Easy import to Excel or Google Sheets
- Sortable and filterable
- Compatible with most data analysis tools
- Easy to create custom dashboards
- Suitable for further processing

## Keyboard Shortcuts

While the export dropdown is visible, you can also:
- Click directly on any export option to download
- Use browser's "Save As" to choose custom location
- Right-click and select "Save Link As..." for more control

## Troubleshooting

### PDF Download Not Working
- Ensure your browser allows downloads from this domain
- Check if popup/download blocker is enabled
- Try using a different browser
- Check your downloads folder

### CSV File Opens in Text Editor Instead of Excel
- Right-click the CSV file → "Open With" → Select Excel/Spreadsheet App
- Or import the CSV file from within your spreadsheet application

### File Names Are Too Long
- Browser shortens very long filenames automatically
- Full filename is: `vulnerabilities_{project_name}_{build_number}.{format}`
- This follows the pattern: `vulnerabilities_ProjectName_build-XXX.pdf`

## Customization Options

### Change Timezone in Report
Add `timezone` parameter to the export URL:
```
/scan/scan-id/export/vulnerabilities/pdf?timezone=America/New_York
/scan/scan-id/export/vulnerabilities/csv?timezone=Europe/London
```

Supported timezones:
- `Asia/Kolkata` (Default - IST)
- `America/New_York` (EST/EDT)
- `Europe/London` (GMT/BST)
- `America/Los_Angeles` (PST/PDT)
- `Asia/Tokyo` (JST)
- `Australia/Sydney` (AEDT/AEST)
- `UTC`
- Any valid IANA timezone name

---

**Last Updated:** January 17, 2026
