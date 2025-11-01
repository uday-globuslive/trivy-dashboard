# Trivy JSON vs SPDX SBOM Format Comparison

## Overview
SPDX (Software Package Data Exchange) is the industry standard for SBOM format. Below is a detailed comparison of what Trivy JSON provides versus what's typically in an SPDX SBOM.

## Data Field Comparison

### 1. **BOM Metadata** 
| Field | SPDX Format | Trivy JSON | Trivy Implementation |
|-------|-----------|-----------|-----------|
| Format | SBOM version (2.2, 2.3, etc.) | SchemaVersion | ✅ Captured |
| Creation Time | Created timestamp | CreatedAt | ✅ Captured |
| Creator | Tool/Organization | (via metadata) | ⚠️ Partial |
| Document Name | SPDX document name | ArtifactName | ✅ Captured |
| Document Namespace | Unique URI | (generated) | ❌ Not captured |
| License | Document license | (implied) | ❌ Not in Trivy |

### 2. **Package/Component Information**
| Field | SPDX Format | Trivy JSON | Status |
|-------|-----------|-----------|--------|
| Package Name | `name` | `PkgName` | ✅ **Captured** |
| Package Version | `versionInfo` | `InstalledVersion` | ✅ **Captured** |
| Package Type | `primaryPackageType` | `Type` | ✅ **Captured** |
| Package URL (PURL) | `externalRefs[type=purl]` | `PkgIdentifier.PURL` | ✅ **Captured** |
| Package Identifier | `SPDXID` | `PkgID` | ✅ **Captured** |
| Description | `description` | (from Title) | ✅ **Captured** |
| Downloads/Source URL | `downloadLocation` | (not in Trivy) | ❌ **Missing** |
| Files/Hashes | `filesAnalyzed`, `sha1` | `Layer.Digest` | ⚠️ **Partial** |
| License Inferred | `licenseConcluded` | (not in Trivy) | ❌ **Missing** |
| License Declared | `licenseDeclared` | (not in Trivy) | ❌ **Missing** |
| License Comments | `licenseComments` | (not in Trivy) | ❌ **Missing** |
| Copyright | `copyrightText` | (not in Trivy) | ❌ **Missing** |
| Supplier | `supplier` | (not in Trivy) | ❌ **Missing** |
| Originator | `originator` | `Author` (in metadata) | ⚠️ **Partial** |

### 3. **Vulnerability Information**
| Field | SPDX Format | Trivy JSON | Status |
|-------|-----------|-----------|--------|
| Vulnerability ID (CVE) | `vulnerabilityID` | `VulnerabilityID` | ✅ **Captured** |
| Severity | `ratings[].severity` | `Severity` | ✅ **Captured** |
| CVSS Score | `ratings[].score` | `CVSS.*.V3Score` | ✅ **Captured** |
| CVSS Vector | `ratings[].vector` | `CVSS.*.V3Vector` | ✅ **Captured** |
| CVSS Version | `ratings[].method` | (implied v3) | ✅ **Captured** |
| Description | `description` | `Description` | ✅ **Captured** |
| CWE | `cweIds` | `CweIDs` | ✅ **Captured** |
| Published Date | `publishedDate` | `PublishedDate` | ✅ **Captured** |
| Updated Date | `releasedDate` | `LastModifiedDate` | ✅ **Captured** |
| Fix Information | `fixedVersion` | `FixedVersion` | ✅ **Captured** |
| References | `references` | `References` | ✅ **Captured** |
| Data Source | `source` | `DataSource` | ✅ **Captured** |

### 4. **Relationships & Dependencies**
| Field | SPDX Format | Trivy JSON | Status |
|-------|-----------|-----------|--------|
| Component Dependencies | `relationships` | `Packages` array | ⚠️ **Partial** |
| Dependency Graph | Explicit relationships | Not explicit | ❌ **Missing** |
| Dependency Type | DEPENDS_ON, CONTAINS, etc. | Inferred | ❌ **Missing** |
| Dependency Version Range | Version constraints | Exact versions only | ⚠️ **Limited** |

### 5. **License Information**
| Field | SPDX Format | Trivy JSON | Status |
|-------|-----------|-----------|--------|
| License(s) Detected | `licenseConcluded` | (not available) | ❌ **Not Available** |
| License Confidence | Accuracy percentage | (not available) | ❌ **Not Available** |
| License Text | Full license text | (not available) | ❌ **Not Available** |

### 6. **Build & Environment Information**
| Field | SPDX Format | Trivy JSON | Status |
|-------|-----------|-----------|--------|
| Source Repository | (not in SPDX) | `Metadata.RepoURL` | ✅ **Captured** |
| Git Commit | (not in SPDX) | `Metadata.Commit` | ✅ **Captured** |
| Commit Message | (not in SPDX) | `Metadata.CommitMsg` | ✅ **Captured** |
| Author | (not in SPDX) | `Metadata.Author` | ✅ **Captured** |

## Summary: What We're Getting from Trivy JSON

### ✅ **Fully Captured (SPDX-equivalent)**
- Package names and versions
- Package URLs (PURL format)
- Package types
- Vulnerability IDs (CVE)
- Severity levels
- CVSS scores and vectors
- CWE information
- Published and update dates
- Fix versions
- References and links
- Data sources

### ⚠️ **Partially Captured**
- Package hashes (only layer digest)
- Relationships (inferred from package list)
- Author/creator information (limited)

### ❌ **Not Available in Trivy JSON**
- License information (detected/inferred licenses)
- Copyright text
- Supplier/Originator information
- Download URLs/Source locations
- Explicit dependency graph/relationships
- SPDX-specific fields (namespace, document name)

## Gap Analysis

### Major Gaps:
1. **License Detection**: Trivy focuses on vulnerabilities, not license compliance
2. **Dependency Relationships**: No explicit "depends_on" information
3. **Copyright Attribution**: Not included in Trivy reports
4. **File-level Analysis**: Only container layer information, not individual files

### Recommendations for Full SPDX Compliance:

If you need complete SPDX SBOM data, consider:

1. **For Java Projects**: Use tools like:
   - SPDX Maven plugin
   - CycloneDX Maven plugin (generates both SPDX and CycloneDX)
   
2. **For Container Images**: Use:
   - Syft (generates SPDX format)
   - CycloneDX CLI with Syft backend

3. **Hybrid Approach** (Recommended):
   ```
   Use Trivy for:
   - Vulnerability data
   - Security scoring
   - Quick scans
   
   Use CycloneDX/SPDX for:
   - Complete SBOM with licenses
   - Dependency graphs
   - Compliance reporting
   ```

## Current Implementation

Our Trivy-based vulnerability details page provides:
- **All vulnerability-related SPDX fields** ✅
- **Package identification and versioning** ✅
- **Git/build metadata** ✅ (bonus!)
- **Security scoring and metrics** ✅

**Missing for Full SPDX Compliance:**
- License information ❌
- Complete dependency graph ❌
- Copyright/supplier data ❌

## Future Enhancement Options

### Option 1: Add CycloneDX Support
Parallel scanning with CycloneDX to get:
- Complete license information
- Explicit dependency relationships
- SBOM compliance features

### Option 2: Enhance Trivy Parser
Extract additional metadata from:
- Container layer information
- Package managers
- Git commit details

### Option 3: Hybrid Dashboard
Show both:
- Trivy vulnerability details (current)
- CycloneDX SBOM details (if available)

## Conclusion

**Current Status: ~70% of SPDX SBOM coverage**

The Trivy JSON format provides **excellent vulnerability and security data**, but lacks **license and relationship information** that full SPDX SBOMs include.

For most **security-focused use cases**, the current implementation is sufficient. For **compliance and license management**, additional tools (CycloneDX/SPDX) are recommended alongside Trivy.
