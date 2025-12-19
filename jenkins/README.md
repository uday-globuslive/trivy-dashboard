# Jenkins Pipeline Files

This directory contains Jenkins pipeline files for the Trivy Security Dashboard.

## Files

### `Jenkinsfile.security-report`

A declarative Jenkins pipeline that generates a PDF security report and sends it via email.

## Prerequisites

1. **Jenkins Plugins Required:**
   - Email Extension Plugin (`email-ext`)
   - Pipeline Plugin
   
2. **SMTP Configuration:**
   - Go to **Manage Jenkins** → **Configure System**
   - Configure **Extended E-mail Notification** section:
     - SMTP server
     - Default user email suffix
     - SMTP Authentication (if required)
     - SSL/TLS settings

3. **Trivy Dashboard:**
   - Dashboard must be running and accessible from Jenkins agent
   - Ensure network connectivity between Jenkins and the dashboard

## Usage

### Option 1: Create a Pipeline Job

1. In Jenkins, create a new **Pipeline** job
2. In the Pipeline section, select **Pipeline script from SCM**
3. Configure your SCM (Git) with the repository URL
4. Set **Script Path** to: `jenkins/Jenkinsfile.security-report`
5. Save and run with parameters

### Option 2: Copy Pipeline Script

1. Create a new **Pipeline** job
2. Select **Pipeline script**
3. Copy the contents of `Jenkinsfile.security-report` into the script area
4. Save and run with parameters

## Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `EMAIL_RECIPIENTS` | Yes | - | Comma-separated email addresses |
| `DASHBOARD_URL` | No | `http://localhost:5000` | Trivy Dashboard URL |
| `TIMEZONE` | No | `Asia/Kolkata` | Timezone for report dates |
| `REPORT_NAME` | No | `Security_Vulnerability_Report` | Report filename prefix |
| `ATTACH_REPORT` | No | `true` | Whether to attach PDF to email |

## Example Build with Parameters

```
EMAIL_RECIPIENTS: security-team@company.com,manager@company.com
DASHBOARD_URL: http://trivy-dashboard.internal:5000
TIMEZONE: Asia/Kolkata
REPORT_NAME: Weekly_Security_Report
ATTACH_REPORT: true
```

## Scheduling (Cron)

To run the report automatically on a schedule, configure a **Build Trigger**:

```
# Every Monday at 9 AM
H 9 * * 1

# Every day at 8 AM
H 8 * * *

# Every Friday at 5 PM
H 17 * * 5

# First day of every month at 9 AM
H 9 1 * *
```

## Troubleshooting

### Email Not Sending

1. Check SMTP configuration in Jenkins
2. Verify email addresses are valid
3. Check Jenkins logs for email errors
4. Test SMTP connection with a simple pipeline:
   ```groovy
   emailext(to: 'test@example.com', subject: 'Test', body: 'Test email')
   ```

### Dashboard Connection Failed

1. Verify dashboard is running: `curl http://dashboard-url/api/health`
2. Check network/firewall between Jenkins and dashboard
3. Ensure correct URL (including port) in `DASHBOARD_URL` parameter

### PDF Not Generated

1. Check dashboard logs for errors
2. Verify there are projects/scans in the dashboard
3. Increase timeout values if dealing with large datasets

## Sample Curl Commands (for testing outside Jenkins)

### Basic Usage (saves with auto-generated filename)
```bash
# Default timezone (IST)
curl -O http://localhost:5000/api/report/projects/pdf

# With specific timezone
curl -O "http://localhost:5000/api/report/projects/pdf?timezone=Asia/Kolkata"
curl -O "http://localhost:5000/api/report/projects/pdf?timezone=UTC"
```

### Save with Custom Filename
```bash
# Save with custom filename
curl -o security_report.pdf "http://localhost:5000/api/report/projects/pdf"

# With timestamp in filename
curl -o "security_report_$(date +%Y%m%d_%H%M%S).pdf" "http://localhost:5000/api/report/projects/pdf?timezone=Asia/Kolkata"

# With project name prefix
curl -o "MyProject_vulnerability_report.pdf" "http://localhost:5000/api/report/projects/pdf?timezone=Asia/Kolkata"

# Save to specific directory
curl -o "/reports/security/weekly_report_$(date +%Y%m%d).pdf" "http://localhost:5000/api/report/projects/pdf"
```

### With Authentication (if required)
```bash
# Basic auth
curl -u username:password -o security_report.pdf "http://localhost:5000/api/report/projects/pdf"

# With headers
curl -H "Authorization: Bearer <token>" -o security_report.pdf "http://localhost:5000/api/report/projects/pdf"
```

### With Error Handling (for scripts)
```bash
# Exit on failure, show errors, silent progress
curl -f -s -S -o security_report.pdf "http://localhost:5000/api/report/projects/pdf?timezone=Asia/Kolkata"

# With timeout settings
curl --connect-timeout 30 --max-time 120 -o security_report.pdf "http://localhost:5000/api/report/projects/pdf"

# Full example with all options
curl -f -s -S \
    --connect-timeout 30 \
    --max-time 120 \
    -o "security_report_$(date +%Y%m%d_%H%M%S).pdf" \
    "http://localhost:5000/api/report/projects/pdf?timezone=Asia/Kolkata"
```

### Verify Download
```bash
# Check file was created and has content
if [ -s security_report.pdf ]; then
    echo "✅ Report downloaded successfully ($(stat -c%s security_report.pdf) bytes)"
else
    echo "❌ Failed to download report"
fi
```
