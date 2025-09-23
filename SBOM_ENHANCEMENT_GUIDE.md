# CycloneDX SBOM Types and Vulnerability Enhancement Guide

## 📋 Understanding CycloneDX SBOM Types

### 1. **Component-Only SBOMs**
Your current SBOM files likely contain:
- **Components**: List of dependencies, packages, libraries
- **Metadata**: Project information, timestamps, tools used
- **Dependencies**: Relationship between components
- **Licenses**: License information for components

**Example structure:**
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "metadata": { ... },
  "components": [
    {
      "type": "library",
      "name": "spring-boot-starter",
      "version": "2.7.0",
      "purl": "pkg:maven/org.springframework.boot/spring-boot-starter@2.7.0"
    }
  ]
}
```

### 2. **Vulnerability-Enhanced SBOMs**
Enhanced SBOMs additionally contain:
- **Vulnerabilities**: CVE details, CVSS scores, severity ratings
- **Affects**: Which components are affected by each vulnerability
- **Analysis**: Vulnerability analysis state (exploitable, in_triage, etc.)

**Example structure:**
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "metadata": { ... },
  "components": [ ... ],
  "vulnerabilities": [
    {
      "id": "CVE-2022-22965",
      "source": { "name": "NVD", "url": "https://nvd.nist.gov/" },
      "ratings": [
        {
          "source": { "name": "NVD" },
          "score": 9.8,
          "severity": "critical",
          "method": "CVSSv3"
        }
      ],
      "affects": [
        { "ref": "spring-framework-core-5.3.17" }
      ]
    }
  ]
}
```

## 🔧 Enhancing SBOMs with Trivy

### **Method 1: Container Image Scanning**
```bash
# Scan a container image and generate vulnerability-enhanced SBOM
trivy image --format cyclonedx --output enhanced-sbom.json your-image:tag

# Example for McCamish projects
trivy image --format cyclonedx --output AGP_Stellar_SSO-enhanced.json your-registry/agp-stellar-sso:latest
```

### **Method 2: Filesystem/Repository Scanning**
```bash
# Scan local project directory
trivy fs --format cyclonedx --output enhanced-sbom.json /path/to/project

# Scan Git repository
trivy repo --format cyclonedx --output enhanced-sbom.json https://github.com/your/repo
```

### **Method 3: Enhance Existing SBOM**
```bash
# If you have an existing SBOM, enhance it with vulnerability data
trivy sbom --format cyclonedx --output enhanced-sbom.json existing-sbom.json
```

## 📤 Uploading Enhanced SBOMs to McCamish Nexus

### **Manual Upload via cURL**
```bash
# Generate timestamp for version
TIMESTAMP=$(date +%Y%m%d%H%M%S)
PROJECT_NAME="AGP_Stellar_SSO"

# Upload to McCamish Nexus following the existing pattern
curl -u your-username:your-password \
  -X PUT \
  "http://swdlvapp682.mccamish.com:8081/repository/mccamish_sbom/com/mccamish/${PROJECT_NAME}.sbom/1.0.0-${TIMESTAMP}/${PROJECT_NAME}.sbom-1.0.0-${TIMESTAMP}.json" \
  --upload-file enhanced-sbom.json
```

### **Automated Upload Script**
```bash
#!/bin/bash
# enhance-and-upload.sh

PROJECT_NAME=$1
IMAGE_TAG=$2
NEXUS_USERNAME=$3
NEXUS_PASSWORD=$4

if [ -z "$PROJECT_NAME" ] || [ -z "$IMAGE_TAG" ]; then
    echo "Usage: $0 <project-name> <image-tag> [nexus-username] [nexus-password]"
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d%H%M%S)
SBOM_FILE="${PROJECT_NAME}-enhanced-${TIMESTAMP}.json"

echo "🔍 Scanning $IMAGE_TAG for vulnerabilities..."
trivy image --format cyclonedx --output "$SBOM_FILE" "$IMAGE_TAG"

if [ $? -eq 0 ]; then
    echo "✅ SBOM generated: $SBOM_FILE"
    
    if [ -n "$NEXUS_USERNAME" ] && [ -n "$NEXUS_PASSWORD" ]; then
        echo "📤 Uploading to McCamish Nexus..."
        curl -u "$NEXUS_USERNAME:$NEXUS_PASSWORD" \
          -X PUT \
          "http://swdlvapp682.mccamish.com:8081/repository/mccamish_sbom/com/mccamish/${PROJECT_NAME}.sbom/1.0.0-${TIMESTAMP}/${PROJECT_NAME}.sbom-1.0.0-${TIMESTAMP}.json" \
          --upload-file "$SBOM_FILE"
        
        if [ $? -eq 0 ]; then
            echo "✅ Upload successful!"
            echo "🌐 View in dashboard: http://your-dashboard:5000"
        else
            echo "❌ Upload failed"
        fi
    else
        echo "⚠️ Nexus credentials not provided, skipping upload"
        echo "📄 SBOM saved locally: $SBOM_FILE"
    fi
else
    echo "❌ SBOM generation failed"
    exit 1
fi
```

## 🚀 Jenkins Integration

### **Add to Jenkins Pipeline**
```groovy
pipeline {
    agent any
    
    stages {
        stage('Build') {
            steps {
                // Your existing build steps
                sh 'docker build -t ${PROJECT_NAME}:${BUILD_NUMBER} .'
            }
        }
        
        stage('Security Scan') {
            steps {
                script {
                    def timestamp = new Date().format('yyyyMMddHHmmss')
                    def sbomFile = "${PROJECT_NAME}-${timestamp}.json"
                    
                    // Generate vulnerability-enhanced SBOM
                    sh """
                        trivy image --format cyclonedx --output ${sbomFile} ${PROJECT_NAME}:${BUILD_NUMBER}
                    """
                    
                    // Upload to McCamish Nexus
                    sh """
                        curl -u \${NEXUS_USERNAME}:\${NEXUS_PASSWORD} \
                          -X PUT \
                          "http://swdlvapp682.mccamish.com:8081/repository/mccamish_sbom/com/mccamish/${PROJECT_NAME}.sbom/1.0.0-${timestamp}/${PROJECT_NAME}.sbom-1.0.0-${timestamp}.json" \
                          --upload-file ${sbomFile}
                    """
                    
                    // Archive SBOM as artifact
                    archiveArtifacts artifacts: sbomFile, fingerprint: true
                }
            }
        }
    }
}
```

## 📊 Dashboard Benefits with Enhanced SBOMs

### **Current State (Component-Only)**
- ✅ Shows project components and dependencies
- ✅ Displays SBOM metadata and build information
- ❌ No vulnerability information
- ❌ No security risk assessment
- ❌ No compliance reporting

### **Enhanced State (With Vulnerabilities)**
- ✅ Shows project components and dependencies
- ✅ Displays SBOM metadata and build information
- ✅ **Vulnerability analysis with CVE details**
- ✅ **Security risk scoring and trending**
- ✅ **Compliance reporting and alerts**
- ✅ **Exploitability assessments**
- ✅ **Fix recommendations**

## 🎯 Recommended Workflow

1. **Current State Assessment**
   - Use the dashboard's Component Analysis page
   - Identify which projects need enhancement

2. **Enhance SBOMs**
   - Run Trivy scans on your container images
   - Generate vulnerability-enhanced CycloneDX SBOMs
   - Upload to McCamish Nexus following existing naming pattern

3. **Monitor Security**
   - Dashboard will automatically detect enhanced SBOMs
   - View vulnerability trends and security metrics
   - Set up alerts for critical vulnerabilities

4. **Continuous Integration**
   - Integrate Trivy scanning into Jenkins pipelines
   - Automate SBOM generation and upload
   - Monitor security posture over time

## 🔍 Verification

After uploading enhanced SBOMs, you can verify they're working by:

1. **Debug Endpoint**: `GET /debug/nexus`
   - Shows SBOM analysis and content types
   - Confirms vulnerability data is present

2. **Component Analysis Page**: `/components`
   - Shows mixed SBOM types
   - Provides recommendations for enhancement

3. **Main Dashboard**: `/`
   - Displays vulnerability metrics when available
   - Shows security trends and risk assessments

## 📞 Support

If you need help with:
- Setting up Trivy scanning
- Integrating with Jenkins pipelines  
- Troubleshooting SBOM uploads
- Configuring the dashboard

Please refer to the debug endpoints and logs for detailed information about your current setup.
