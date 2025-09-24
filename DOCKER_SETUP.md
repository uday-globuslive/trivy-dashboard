# Docker Hub Setup Guide

This guide helps you set up GitHub Actions to automatically build and push Docker images to Docker Hub.

## Prerequisites

1. **Docker Hub Account**: Create an account at [hub.docker.com](https://hub.docker.com)
2. **GitHub Repository**: Your dashboard code should be in a GitHub repository

## Step 1: Create Docker Hub Repository

1. Log in to Docker Hub
2. Click "Create Repository"
3. Repository name: `trivy-security-dashboard`
4. Set visibility (Public or Private)
5. Click "Create"

## Step 2: Generate Docker Hub Access Token

1. Go to Docker Hub → Account Settings → Security
2. Click "New Access Token"
3. Description: `github-actions-trivy-dashboard`
4. Permissions: `Read, Write, Delete`
5. Copy the generated token (you won't see it again!)

## Step 3: Configure GitHub Secrets

In your GitHub repository, go to Settings → Secrets and variables → Actions

Add these repository secrets:

| Secret Name | Value | Description |
|-------------|--------|-------------|
| `DOCKERHUB_USERNAME` | Your Docker Hub username | Used for authentication |
| `DOCKERHUB_TOKEN` | Access token from Step 2 | Used for authentication |

### Adding Secrets:
1. Click "New repository secret"
2. Name: `DOCKERHUB_USERNAME`
3. Secret: Your Docker Hub username
4. Click "Add secret"
5. Repeat for `DOCKERHUB_TOKEN`

## Step 4: Workflow Triggers

The workflow will trigger on:

- **Push to main/develop**: Builds and pushes image with branch name as tag
- **Git tags (v*)**: Builds and pushes with semantic version tags
- **Pull requests**: Builds image but doesn't push (testing only)

## Step 5: Image Tags

The workflow creates multiple tags:

| Trigger | Tags Created |
|---------|--------------|
| Push to `main` | `latest`, `main` |
| Push to `develop` | `develop` |
| Tag `v1.2.3` | `v1.2.3`, `1.2.3`, `1.2`, `1` |
| Pull request | No push (build only) |

## Step 6: Using the Docker Image

Once built, you can use your image:

```bash
# Pull the latest version
docker pull yourusername/trivy-security-dashboard:latest

# Run the container with Trivy report configuration
docker run -d \
  -p 5000:5000 \
  -e NEXUS_URL=http://your-nexus:8081 \
  -e NEXUS_USERNAME=admin \
  -e NEXUS_PASSWORD=password \
  -e NEXUS_REPOSITORY=your-repository \
  -e NEXUS_ARTIFACT_SUFFIX=-trivy-report \
  yourusername/trivy-security-dashboard:latest
```

## Step 7: Docker Compose with Your Image

Update your `docker-compose.yml`:

```yaml
version: '3.8'

services:
  trivy-dashboard:
    image: yourusername/trivy-security-dashboard:latest
    container_name: trivy-dashboard
    ports:
      - "5000:5000"
    environment:
      - NEXUS_URL=${NEXUS_URL:-http://localhost:8081}
      - NEXUS_USERNAME=${NEXUS_USERNAME:-admin}
      - NEXUS_PASSWORD=${NEXUS_PASSWORD:-admin123}
      - NEXUS_REPOSITORY=${NEXUS_REPOSITORY:-trivy-reports}
      - NEXUS_ARTIFACT_SUFFIX=${NEXUS_ARTIFACT_SUFFIX:--trivy-report}
    restart: unless-stopped
```

## Workflow Features

### 🔒 Security Scanning
- **Trivy vulnerability scanning** of built images
- **SARIF upload** to GitHub Security tab
- **Security reports** as artifacts

### 🏗️ Multi-Architecture
- Builds for `linux/amd64` and `linux/arm64`
- Compatible with Intel and ARM processors

### ⚡ Performance
- **Docker layer caching** for faster builds
- **GitHub Actions cache** optimization

### 📚 Documentation
- **Auto-sync README** to Docker Hub
- **Build provenance** attestation

## Troubleshooting

### Build Failures

1. **Docker Hub authentication failed**
   - Check `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` secrets
   - Verify token has correct permissions

2. **Multi-platform build issues**
   - May need to remove `linux/arm64` for some base images
   - Check Dockerfile for platform-specific dependencies

3. **Resource limits**
   - Large builds may hit GitHub Actions limits
   - Consider optimizing Dockerfile layers

### Security Scan Issues

1. **Trivy scan failures**
   - High/Critical vulnerabilities may cause warnings
   - Update base image or dependencies

2. **SARIF upload errors**
   - Check repository has security features enabled
   - Verify proper permissions in workflow

## Monitoring

### GitHub Actions
- Monitor builds in the "Actions" tab
- Check for failed workflows and errors
- Review security scan results

### Docker Hub
- View download statistics
- Monitor image size and layers
- Check automated builds status

## Best Practices

1. **Use specific base image tags** (not `latest`)
2. **Keep secrets secure** and rotate tokens regularly
3. **Monitor security scans** and address vulnerabilities
4. **Tag releases** with semantic versioning
5. **Test images** before deploying to production

## Example Release Process

1. **Development**: Push to `develop` branch
   - Builds `yourusername/trivy-security-dashboard:develop`

2. **Testing**: Create pull request to `main`
   - Builds image for testing (no push)

3. **Release**: Merge to `main` and create git tag
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```
   - Builds multiple tags: `v1.0.0`, `1.0.0`, `1.0`, `1`, `latest`

This setup provides automated, secure, and scalable Docker image builds for your Trivy Security Dashboard!
