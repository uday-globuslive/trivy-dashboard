# Risk Assessment Guide

## 🎯 Overview

The Trivy Dashboard implements a sophisticated risk assessment system that quantifies security risks based on vulnerability severity and CVSS scores. This guide explains how risk scores are calculated, displayed, and used for security decision-making.

## 🧮 Risk Calculation Methodology

The dashboard uses **dual calculation approaches** to provide accurate risk assessment across different contexts:

### 1. Project-Level Risk Score (Severity Count Based)

Located in `utils/helpers.py`, this method is used for project-level aggregation based on the **latest scan** severity counts:

**Severity Weights:**
```
Critical (C) = 10 points
High (H)     = 7 points  
Medium (M)   = 4 points
Low (L)      = 1 point
```

**Calculation Formula:**
```
Total Weighted Score = (C × 10) + (H × 7) + (M × 4) + (L × 1)
Max Possible Score = Total Vulnerabilities × 10
Risk Score % = (Total Weighted Score / Max Possible Score) × 100
```

**Example Calculation:**
```
Latest Scan: 1 Critical, 49 High, 73 Medium, 15 Low

Total Weighted = (1 × 10) + (49 × 7) + (73 × 4) + (15 × 1)
               = 10 + 343 + 292 + 15
               = 660

Total Vulnerabilities = 1 + 49 + 73 + 15 = 138
Max Possible Score = 138 × 10 = 1380

Risk Score = (660 / 1380) × 100 = 47.83%
```

**Key Characteristics:**
- Based on **latest scan data only** (determined by CreatedAt timestamp from Trivy report)
- Simple and performant calculation
- Easy to understand for stakeholders
- Provides consistent scoring across projects
- Only updated when new scans complete

**Usage Context:**
- Project overview statistics in dashboard
- Project cards displaying risk percentage
- Portfolio-level risk comparisons
- Quick security posture assessment

### 2. Enhanced Scan-Level Risk Score (CVSS Integration)

Located in `services/analytics.py`, this method provides sophisticated scoring incorporating actual CVSS vulnerability scores:

**Calculation Approach:**
```python
for each vulnerability in scan:
    if CVSS_score exists:
        weighted_score = (CVSS_score × severity_weight) / 10
    else:
        weighted_score = severity_weight

total_weighted_score = sum(all weighted_scores)
max_possible_score = total_vulnerabilities × 10
risk_score = (total_weighted_score / max_possible_score) × 100
risk_score = min(risk_score, 100)  # Cap at 100%
```

**Severity Weights:**
```
CRITICAL = 10
HIGH     = 7
MEDIUM   = 4
LOW      = 1
INFO     = 0.5
UNKNOWN  = 2
```

**Key Features:**
- Incorporates actual CVSS scores (0.0-10.0) for granular analysis
- Fallback to severity weights when CVSS unavailable
- More accurate risk representation per individual vulnerability
- Includes all vulnerabilities in detailed scan analysis

**Usage Context:**
- Detailed scan vulnerability analysis
- Per-vulnerability risk contribution analysis
- Advanced analytics and reporting
- Comparison of identical vulnerabilities across scans

### Comparison of Methods

| Aspect | Project-Level | Scan-Level |
|--------|---------------|-----------|
| **Data Source** | Latest scan severity counts | Full vulnerability list with CVSS |
| **Input** | 4 counts (C, H, M, L) | Vulnerability objects |
| **Calculation** | Severity weight × count | CVSS × severity weight / 10 |
| **Precision** | Vulnerability class level | Individual CVSS score level |
| **Performance** | Very fast (simple math) | Slower (iterates vulnerabilities) |
| **Use Case** | Project overview | Detailed analysis |
| **Update Trigger** | New scan complete | On-demand analysis |

## 📊 Risk Score Categories

The system categorizes risk scores into five distinct levels with visual indicators:

| Risk Level | Score Range | Color Code | Action Priority |
|------------|-------------|------------|-----------------|
| 🔴 **Critical** | 80-100% | Red (`#dc3545`) | Immediate action required |
| 🟠 **High** | 60-79% | Orange (`#fd7e14`) | High priority remediation |
| 🟡 **Medium** | 40-59% | Yellow (`#ffc107`) | Moderate concern |
| 🟢 **Low** | 20-39% | Green (`#28a745`) | Low priority |
| 🔵 **Minimal** | 0-19% | Blue (`#17a2b8`) | Acceptable risk |

### Risk Level Descriptions

```python
def get_risk_level_description(risk_score: float) -> str:
    if risk_score >= 80:
        return "Critical - Immediate attention required"
    elif risk_score >= 60:
        return "High - Priority remediation needed"
    elif risk_score >= 40:
        return "Medium - Moderate security concern"
    elif risk_score >= 20:
        return "Low - Minor security issues"
    else:
        return "Minimal - Acceptable security posture"
```

## 🎨 Visual Representation

### Dashboard Display Components

**1. Project Cards (`templates/projects.html`)**
```html
<!-- Progress bar with dynamic color coding -->
<div class="progress">
    <div class="progress-bar bg-{{ 'danger' if project.risk_score >= 80 
                                 else 'warning' if project.risk_score >= 40 
                                 else 'success' }}" 
         style="width: {{ project.risk_score }}%">
    </div>
</div>
<small class="text-muted">Risk Score: {{ project.risk_score }}%</small>
```

**2. Project Detail View (`templates/project.html`)**
```html
<!-- Circular risk indicator -->
<div class="risk-score-circle">
    <div class="risk-score-value" 
         style="color: {{ 'red' if project.risk_score >= 80 
                         else 'orange' if project.risk_score >= 40 
                         else 'green' }}">
        {{ project.risk_score }}%
    </div>
</div>
<h5>Risk Score</h5>
{% if project.risk_score >= 80 %}
    <span class="badge badge-danger">Critical Risk</span>
{% elif project.risk_score >= 40 %}
    <span class="badge badge-warning">Medium Risk</span>
{% else %}
    <span class="badge badge-success">Low Risk</span>
{% endif %}
```

**3. Scan Details (`templates/scan.html`)**
```html
<dt class="col-5">Risk Score:</dt>
<dd class="col-7">{{ scan.risk_score }}%</dd>
```

## 📈 Analytics & Trending

### Time-Based Risk Analysis

The dashboard tracks risk assessment metrics over time:

**7-Day Average Risk Score**
```javascript
// Dashboard analytics display
<div class="h4 mb-0 text-info">${data.last_7_days?.avg_risk_score || 0}%</div>
<small class="text-muted">Avg Risk Score (7 days)</small>
```

**Risk Trend Tracking**
- **Portfolio Risk**: Average risk across all projects
- **Risk Velocity**: Rate of risk score changes
- **Risk Debt**: Cumulative security exposure
- **Improvement Metrics**: Risk reduction over time

### Risk-Based Prioritization

Projects are automatically sorted by risk level for security team prioritization:

```python
# Risk-based project sorting in app.py
projects.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
```

## 🔧 Technical Implementation

### Integration Points

**1. Data Refresh (`app.py` line 148)**
```python
# Calculate risk score during project data refresh
project['risk_score'] = calculate_risk_score(
    project.get('critical', 0),
    project.get('high', 0), 
    project.get('medium', 0),
    project.get('low', 0)
)
```

**2. Scan Analysis (`app.py` line 419)**
```python
# Per-scan risk calculation
scan_data['risk_score'] = analytics.calculate_risk_score(
    vulnerabilities, 
    use_cvss=True
)
```

**3. Analytics Service Integration**
```python
# Enhanced analytics with CVSS integration
from services.analytics import calculate_risk_score

risk_score = calculate_risk_score(
    vulnerabilities=vuln_list,
    use_cvss=True,
    severity_weights=custom_weights  # Optional override
)
```

## 🎯 Practical Examples

### Example 1: Critical Risk Project
```
Vulnerabilities:
- 5 Critical (CVSS 9.0-10.0)
- 12 High (CVSS 7.0-8.9)
- 8 Medium (CVSS 4.0-6.9)
- 3 Low (CVSS 0.1-3.9)

Calculation (Enhanced Method):
- Critical: 5 × (9.5 × 10 / 10) = 47.5
- High: 12 × (7.5 × 7 / 10) = 63.0  
- Medium: 8 × (5.0 × 4 / 10) = 16.0
- Low: 3 × (2.0 × 1 / 10) = 0.6

Total Weighted: 127.1
Max Possible: 28 × 10 = 280
Risk Score: (127.1 / 280) × 100 = 45.4%

Result: 🟡 Medium Risk (45.4%)
```

### Example 2: Low Risk Project
```
Vulnerabilities:
- 0 Critical
- 1 High (CVSS 7.2)
- 3 Medium (CVSS 5.1)
- 8 Low (CVSS 2.3)

Calculation:
- High: 1 × (7.2 × 7 / 10) = 5.04
- Medium: 3 × (5.1 × 4 / 10) = 6.12
- Low: 8 × (2.3 × 1 / 10) = 1.84

Total Weighted: 13.0
Max Possible: 12 × 10 = 120  
Risk Score: (13.0 / 120) × 100 = 10.8%

Result: 🔵 Minimal Risk (10.8%)
```

## 🚀 Best Practices

### For Security Teams

1. **Prioritize Critical Risk Projects (80%+)**
   - Immediate remediation required
   - Block deployments if possible
   - Daily monitoring and updates

2. **Schedule High Risk Projects (60-79%)**
   - Include in next sprint planning
   - Weekly progress reviews
   - Stakeholder communication

3. **Monitor Medium Risk Projects (40-59%)**
   - Monthly security reviews
   - Dependency update planning
   - Trend analysis

4. **Track Low/Minimal Risk Projects (<40%)**
   - Quarterly security assessments
   - Maintain security baseline
   - Process improvement opportunities

### For Development Teams

1. **Use Risk Scores for Planning**
   - Include security debt in technical debt discussions
   - Plan remediation work based on risk levels
   - Set risk reduction targets

2. **Monitor Risk Trends**
   - Track risk changes over time
   - Identify risk introduction patterns
   - Celebrate risk reduction achievements

3. **Integrate with CI/CD**
   - Set risk score thresholds in pipelines
   - Fail builds on critical risk increases
   - Generate risk-based reports

## 📋 Configuration Options

### Customizing Risk Weights

You can modify severity weights in `services/analytics.py`:

```python
# Custom severity weights
severity_weights = {
    'CRITICAL': 15,    # Increase critical impact
    'HIGH': 8,         # Slightly higher high impact
    'MEDIUM': 4,       # Keep medium standard
    'LOW': 0.5,        # Reduce low impact
    'INFO': 0,         # Ignore informational
    'UNKNOWN': 3       # Increase unknown penalty
}
```

### Risk Level Thresholds

Adjust risk level boundaries in template conditions:

```html
<!-- Custom thresholds -->
{% if project.risk_score >= 85 %}        <!-- Critical: 85%+ -->
{% elif project.risk_score >= 65 %}      <!-- High: 65-84% -->
{% elif project.risk_score >= 35 %}      <!-- Medium: 35-64% -->
{% elif project.risk_score >= 15 %}      <!-- Low: 15-34% -->
{% else %}                               <!-- Minimal: <15% -->
```

## 🔍 Troubleshooting

### Common Issues

**1. Risk Scores Appear Too High/Low**
- Verify CVSS scores in SBOM data
- Check severity weight configuration
- Ensure proper vulnerability classification

**2. Inconsistent Risk Calculations**
- Confirm which calculation method is being used
- Check for mixed vulnerability data sources
- Validate SBOM vulnerability data quality

**3. Risk Trends Not Updating**
- Verify scan data timestamps
- Check caching configuration
- Ensure analytics service is running

### Debug Risk Calculations

Enable debug logging to trace risk calculations:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Add debug prints in analytics.py
print(f"Calculating risk for {len(vulnerabilities)} vulnerabilities")
print(f"Total weighted score: {total_weighted_score}")
print(f"Max possible score: {max_possible_score}")  
print(f"Final risk percentage: {risk_percentage}%")
```

## � Interactive Risk Calculation Info Modal

### Overview

An interactive **info icon** (ℹ️) has been added next to the "Risk Assessment" title on relevant pages. When clicked, it opens a detailed modal showing the complete risk calculation methodology, making it easy for product management and stakeholders to understand how risk scores are calculated.

### Where the Modal Appears

**1. Project View** (`/project/<project_name>`)
- Location: Risk Assessment card header
- Trigger: Click the blue ℹ️ info icon next to "Risk Assessment"
- Content: Shows complete risk calculation formula and severity weights

**2. Scan View** (`/scan/<scan_id>`)
- Location: Scan Information section, next to Risk Score value
- Trigger: Click the blue ℹ️ info icon next to the risk score percentage
- Content: Same calculation details as project view

### Modal Content Structure

The modal displays four main sections:

**📊 Methodology**
- Explains that the risk score is based on vulnerability severity distribution
- Describes the weighted scoring system normalized to 0-100%

**⚖️ Severity Weights**
- Visual display of weight assignments with color-coded badges:
  - **Critical** = 10 points (red badge)
  - **High** = 7 points (orange badge)
  - **Medium** = 4 points (yellow badge)
  - **Low** = 1 point (blue badge)

**🧮 Formula**
- Clear mathematical formula displayed in monospace font
- Complete explanation of variables:
  - Total Weighted Score = (Critical × 10) + (High × 7) + (Medium × 4) + (Low × 1)
  - Max Possible Score = Total Vulnerabilities × 10

**🚦 Risk Levels**
- Classification table showing risk level thresholds:
  - **CRITICAL**: 80-100% (red)
  - **HIGH**: 60-79% (orange)
  - **MEDIUM**: 40-59% (yellow)
  - **LOW**: 20-39% (green)
  - **MINIMAL**: 0-19% (blue)

### Technical Implementation

**Bootstrap 5 Compatibility**
```html
<!-- Trigger button -->
<button class="btn btn-sm btn-link p-0" 
        data-bs-toggle="modal" 
        data-bs-target="#riskCalculationModal"
        title="View risk calculation methodology">
    <i class="fas fa-info-circle text-info"></i>
</button>

<!-- Modal -->
<div class="modal fade" id="riskCalculationModal" tabindex="-1" 
     aria-labelledby="riskCalculationModalLabel" aria-hidden="true">
    <!-- Modal content -->
</div>
```

**Key Features:**
- Uses Bootstrap 5 syntax: `data-bs-toggle` and `data-bs-target`
- Font Awesome 6.4.0 icons for visual appeal
- Responsive design: adapts from mobile to desktop
- Color-coded badge system for severity levels
- Professional card-based layout with left borders

### User Experience Benefits

**For Product Management**
1. Click info icon to understand risk percentage calculation
2. See exact formula and severity weights applied
3. Understand risk level classifications
4. No need to access technical documentation

**For Security Teams**
- Quick access to calculation details without leaving current view
- Faster decision-making and stakeholder communication
- Consistent methodology reference across dashboard

### Responsive Design

The modal is fully responsive:
- **Desktop**: Full-width modal with 2-column layout for risk levels
- **Mobile**: Single-column layout with adjusted spacing and font sizes
- **Tablet**: Optimized for mid-size screens with flexible grid

### Files Modified

- `templates/project.html` - Added info icon and modal to Risk Assessment card
- `templates/scan.html` - Added info icon and modal to Risk Score display

### Testing the Modal

**On Project View:**
1. Navigate to `/projects` page
2. Click on any project card to view project details
3. Look for the blue ℹ️ icon next to "Risk Assessment"
4. Click the icon to open the modal
5. Verify all content displays correctly
6. Click "Close" button to dismiss

**On Scan View:**
1. Navigate to `/projects` page
2. Click on any project
3. Click on any scan to view scan details
4. Look for the blue ℹ️ icon next to the risk score percentage
5. Click the icon to open the modal
6. Verify modal content and styling

## �📚 Additional Resources

- **CVSS Calculator**: [https://www.first.org/cvss/calculator/3.1](https://www.first.org/cvss/calculator/3.1)
- **CycloneDX Vulnerability Schema**: [https://cyclonedx.org/](https://cyclonedx.org/)
- **NIST Vulnerability Database**: [https://nvd.nist.gov/](https://nvd.nist.gov/)
- **Trivy Documentation**: [https://trivy.dev/](https://trivy.dev/)

---

*This risk assessment system provides quantitative security metrics to help teams make data-driven decisions about vulnerability remediation and security investments.*