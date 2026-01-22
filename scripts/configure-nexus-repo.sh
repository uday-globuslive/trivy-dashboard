#!/bin/bash

# Configure Nexus repository to support long filenames and paths
# This script updates the erwindm_sbom repository settings

NEXUS_URL="${NEXUS_URL:-http://10.11.53.20:8081}"
NEXUS_USERNAME="${NEXUS_USERNAME:-sv-sbom}"
NEXUS_PASSWORD="${NEXUS_PASSWORD:-sbom@sbom}"
NEXUS_REPOSITORY="${NEXUS_REPOSITORY:-erwindm_sbom}"

echo "📦 Configuring Nexus Repository: $NEXUS_REPOSITORY"
echo "🔗 Nexus URL: $NEXUS_URL"

# Create base64 encoded credentials
CREDENTIALS=$(echo -n "$NEXUS_USERNAME:$NEXUS_PASSWORD" | base64)

# Repository configuration JSON
REPO_CONFIG=$(cat <<EOF
{
  "name": "$NEXUS_REPOSITORY",
  "format": "raw",
  "type": "hosted",
  "online": true,
  "storage": {
    "blobStoreName": "default",
    "strictContentTypeValidation": false,
    "writePolicy": "ALLOW"
  }
}
EOF
)

echo "📝 Repository Configuration:"
echo "$REPO_CONFIG"
echo ""

# Update repository via REST API
echo "🔄 Sending configuration to Nexus..."
RESPONSE=$(curl -s -X PUT \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $CREDENTIALS" \
  -d "$REPO_CONFIG" \
  "$NEXUS_URL/service/rest/v1/repositories/raw/hosted/$NEXUS_REPOSITORY")

# Check response
if [[ $RESPONSE == *"error"* ]] || [[ $RESPONSE == *"Error"* ]]; then
  echo "❌ Error configuring repository:"
  echo "$RESPONSE"
  exit 1
elif [ -z "$RESPONSE" ]; then
  echo "✅ Repository configured successfully!"
  exit 0
else
  echo "Response: $RESPONSE"
  echo "✅ Repository configuration updated!"
  exit 0
fi
