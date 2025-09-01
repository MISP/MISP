# MISP Helm Chart

A Helm chart for deploying [MISP (Malware Information Sharing Platform)](https://www.misp-project.org/) on Kubernetes.

## Overview

MISP is an open source software solution for collecting, storing, distributing and sharing cyber security indicators and threats about cyber security incidents analysis and malware analysis. This Helm chart provides a complete Kubernetes deployment solution for MISP.

## Features

- **Complete MISP Stack**: Includes MISP application, MySQL database, Redis cache, and worker pods
- **Production Ready**: Configurable resource limits, health checks, and security contexts
- **Persistent Storage**: Configurable persistent volumes for data, database, and cache
- **Security**: Non-root containers, secrets management for GPG/SMIME keys
- **Scalability**: Configurable replica counts and horizontal pod autoscaling
- **Monitoring**: Built-in health checks and optional Prometheus metrics
- **Flexible Configuration**: Extensive values.yaml configuration options

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+
- PV provisioner support in the underlying infrastructure
- StorageClass for persistent volumes (optional)

## Quick Start

### 1. Add the Helm Repository

```bash
helm repo add misp https://charts.misp-project.org
helm repo update
```

### 2. Install MISP

```bash
# Install with default values
helm install my-misp misp/misp

# Install with custom values
helm install my-misp misp/misp --values custom-values.yaml
```

### 3. Access MISP

```bash
# Port forward to access MISP
kubectl port-forward svc/my-misp-app 8080:80

# Access at http://localhost:8080
```

## Configuration

### Basic Configuration

Create a `values.yaml` file with your custom configuration:

```yaml
# Basic MISP configuration
misp:
  env:
    MISP_BASEURL: "https://misp.yourdomain.com"
    MISP_ORG: "Your Organization"
    MISP_EMAIL: "admin@yourdomain.com"

# Database configuration
database:
  mysql:
    auth:
      rootPassword: "your-root-password"
      password: "your-misp-password"

# Ingress configuration
misp:
  ingress:
    enabled: true
    hosts:
      - host: misp.yourdomain.com
        paths:
          - path: /
            pathType: Prefix
    tls:
      - secretName: misp-tls
        hosts:
          - misp.yourdomain.com
```

### Advanced Configuration

#### Resource Limits

```yaml
misp:
  resources:
    limits:
      cpu: 2000m
      memory: 4Gi
    requests:
      cpu: 1000m
      memory: 2Gi

workers:
  replicaCount: 3
  resources:
    limits:
      cpu: 1000m
      memory: 2Gi
    requests:
      cpu: 500m
      memory: 1Gi
```

#### Persistent Storage

```yaml
misp:
  persistence:
    enabled: true
    storageClass: "fast-ssd"
    size: 20Gi

database:
  mysql:
    primary:
      persistence:
        enabled: true
        storageClass: "fast-ssd"
        size: 10Gi

redis:
  master:
    persistence:
      enabled: true
      storageClass: "fast-ssd"
      size: 2Gi
```

#### Security Configuration

```yaml
# Enable GPG/SMIME encryption
secrets:
  create: true
  gpgKey: "base64-encoded-gpg-key"
  smimeCert: "base64-encoded-smime-cert"
  smimeKey: "base64-encoded-smime-key"

# Security contexts
misp:
  securityContext:
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
  podSecurityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
```

## Architecture

The Helm chart deploys the following components:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   MISP App      │    │   MISP Workers  │    │   Ingress       │
│   (PHP/Apache)  │    │   (Background)  │    │   (Optional)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
         ┌─────────────────┐    ┌─────────────────┐
         │   MySQL DB      │    │   Redis Cache   │
         │   (Primary)     │    │   (Sessions)    │
         └─────────────────┘    └─────────────────┘
```

## Components

### MISP Application
- **Image**: `misp/misp:2.5`
- **Port**: 80
- **Health Checks**: HTTP probes on `/`
- **Persistence**: Configurable PVC for MISP data

### MySQL Database
- **Image**: `mysql:8.0`
- **Port**: 3306
- **Health Checks**: MySQL ping
- **Persistence**: Configurable PVC for database data

### Redis Cache
- **Image**: `redis:7-alpine`
- **Port**: 6379
- **Health Checks**: Redis ping
- **Persistence**: Configurable PVC for cache data

### MISP Workers
- **Image**: `misp/misp:2.5`
- **Purpose**: Background task processing
- **Replicas**: Configurable (default: 2)
- **Shared Storage**: Uses same PVC as main app

## Security Considerations

### Container Security
- All containers run as non-root users
- Security contexts configured for minimal privileges
- Read-only root filesystem where possible

### Network Security
- Services use ClusterIP by default
- Ingress can be configured with TLS
- Network policies can be applied

### Secrets Management
- Database passwords stored in Kubernetes secrets
- GPG/SMIME keys can be mounted from secrets
- No hardcoded credentials in containers

## Monitoring

### Health Checks
- Liveness probes ensure containers are restarted if unhealthy
- Readiness probes ensure traffic is only sent to healthy pods
- Startup probes handle slow-starting containers

### Metrics (Optional)
```yaml
monitoring:
  metrics:
    enabled: true
    serviceMonitor:
      enabled: true
```

## Backup and Recovery

### Automated Backups
```yaml
backup:
  enabled: true
  schedule: "0 2 * * *"  # Daily at 2 AM
  retention: 7  # Keep 7 days of backups
  storage:
    enabled: true
    storageClass: "backup-storage"
    size: 10Gi
```

### Manual Backup
```bash
# Backup MISP data
kubectl exec -it deployment/my-misp-app -- tar czf /tmp/misp-backup.tar.gz /var/www/MISP

# Backup database
kubectl exec -it deployment/my-misp-mysql -- mysqldump -u root -p misp > misp-db-backup.sql
```

## Troubleshooting

### Common Issues

#### Pod Not Starting
```bash
# Check pod status
kubectl get pods -l app.kubernetes.io/name=misp

# Check pod logs
kubectl logs deployment/my-misp-app
kubectl logs deployment/my-misp-mysql
kubectl logs deployment/my-misp-redis
```

#### Database Connection Issues
```bash
# Check database connectivity
kubectl exec -it deployment/my-misp-app -- mysql -h my-misp-mysql -u misp -p

# Check database logs
kubectl logs deployment/my-misp-mysql
```

#### Storage Issues
```bash
# Check PVC status
kubectl get pvc -l app.kubernetes.io/name=misp

# Check storage class
kubectl get storageclass
```

### Logs
```bash
# Application logs
kubectl logs -f deployment/my-misp-app

# Database logs
kubectl logs -f deployment/my-misp-mysql

# Redis logs
kubectl logs -f deployment/my-misp-redis

# Worker logs
kubectl logs -f deployment/my-misp-workers
```

## Upgrading

### Helm Upgrade
```bash
# Update repository
helm repo update

# Upgrade release
helm upgrade my-misp misp/misp --values custom-values.yaml
```

### Database Migration
MISP includes automatic database migrations. The application will handle schema updates automatically.

## Contributing

This Helm chart is part of the MISP project. Contributions are welcome!

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This Helm chart is licensed under the same license as MISP: [GNU Affero General Public License version 3](http://www.gnu.org/licenses/agpl-3.0.html).

## Support

- **Documentation**: [MISP Documentation](https://www.circl.lu/doc/misp/)
- **Community**: [MISP Community](https://www.misp-project.org/community/)
- **Issues**: [GitHub Issues](https://github.com/MISP/MISP/issues)
- **Discussions**: [GitHub Discussions](https://github.com/MISP/MISP/discussions)

## Changelog

### Version 0.1.0
- Initial release
- Complete MISP stack deployment
- MySQL and Redis support
- Worker pods for background tasks
- Persistent storage configuration
- Security contexts and non-root containers
- Ingress support
- Comprehensive documentation
