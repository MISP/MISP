# MISP Kubernetes Deployment Guide

This guide provides comprehensive instructions for deploying MISP (Malware Information Sharing Platform) on Kubernetes using the provided Helm chart and deployment scripts.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Quick Start](#quick-start)
4. [Helm Chart Deployment](#helm-chart-deployment)
5. [Manual Kubernetes Deployment](#manual-kubernetes-deployment)
6. [Configuration](#configuration)
7. [Security Considerations](#security-considerations)
8. [Monitoring and Logging](#monitoring-and-logging)
9. [Backup and Recovery](#backup-and-recovery)
10. [Troubleshooting](#troubleshooting)
11. [Production Deployment](#production-deployment)
12. [Contributing](#contributing)

## Overview

MISP is a comprehensive threat intelligence sharing platform used by security professionals worldwide. This guide provides multiple deployment options for running MISP on Kubernetes:

- **Helm Chart**: Complete, production-ready deployment
- **Manual Deployment**: Step-by-step Kubernetes manifests
- **Automated Scripts**: Easy deployment with `k8s-deploy.sh`

## Prerequisites

### Required Tools

- **Kubernetes Cluster**: v1.19+ (local or cloud)
- **kubectl**: v1.19+
- **Helm**: v3.0+
- **Docker**: For building images (optional)

### Cluster Requirements

- **CPU**: Minimum 4 cores (2 for MISP, 1 for MySQL, 1 for Redis)
- **Memory**: Minimum 8GB RAM
- **Storage**: 20GB+ available for persistent volumes
- **Network**: Internet access for image pulling

### Local Development Setup

```bash
# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Install Helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Install Minikube (for local testing)
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube
```

## Quick Start

### Option 1: Automated Deployment Script

```bash
# Clone the repository
git clone https://github.com/MISP/MISP.git
cd MISP

# Run the deployment script
./k8s-deploy.sh

# Access MISP
kubectl port-forward -n misp svc/misp-app 8080:80
# Visit: http://localhost:8080
```

### Option 2: Helm Chart Deployment

```bash
# Install using Helm
helm install my-misp ./helm-charts/misp \
  --namespace misp \
  --create-namespace \
  --set database.mysql.auth.rootPassword=your-root-password \
  --set database.mysql.auth.password=your-misp-password

# Access MISP
kubectl port-forward -n misp svc/my-misp-app 8080:80
```

## Helm Chart Deployment

### Basic Installation

```bash
# Create namespace
kubectl create namespace misp

# Install with default values
helm install misp ./helm-charts/misp --namespace misp

# Check deployment status
kubectl get pods -n misp
```

### Custom Configuration

Create a `values.yaml` file:

```yaml
# Production values.yaml
misp:
  env:
    MISP_BASEURL: "https://misp.yourdomain.com"
    MISP_ORG: "Your Security Team"
    MISP_EMAIL: "admin@yourdomain.com"
  
  resources:
    limits:
      cpu: 2000m
      memory: 4Gi
    requests:
      cpu: 1000m
      memory: 2Gi
  
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

database:
  mysql:
    auth:
      rootPassword: "your-secure-root-password"
      password: "your-secure-misp-password"
    primary:
      persistence:
        enabled: true
        storageClass: "fast-ssd"
        size: 20Gi

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

Install with custom values:

```bash
helm install misp ./helm-charts/misp \
  --namespace misp \
  --values values.yaml
```

### Advanced Configuration

#### High Availability Setup

```yaml
misp:
  replicaCount: 3
  autoscaling:
    enabled: true
    minReplicas: 2
    maxReplicas: 10
    targetCPUUtilizationPercentage: 70
    targetMemoryUtilizationPercentage: 80

workers:
  replicaCount: 5
  autoscaling:
    enabled: true
    minReplicas: 3
    maxReplicas: 15
    targetCPUUtilizationPercentage: 70

database:
  mysql:
    primary:
      persistence:
        enabled: true
        storageClass: "fast-ssd"
        size: 50Gi
    readReplicas:
      enabled: true
      replicaCount: 2
```

#### Security Hardening

```yaml
# Security contexts
misp:
  securityContext:
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
    readOnlyRootFilesystem: true
    allowPrivilegeEscalation: false
    capabilities:
      drop:
        - ALL
  
  podSecurityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault

# Network policies
networkPolicy:
  enabled: true
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: ingress-nginx
      ports:
        - protocol: TCP
          port: 80
```

## Manual Kubernetes Deployment

### Step 1: Create Namespace

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: misp
  labels:
    name: misp
```

### Step 2: Create Secrets

```yaml
# secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: misp-secrets
  namespace: misp
type: Opaque
data:
  mysql-root-password: <base64-encoded-password>
  mysql-password: <base64-encoded-password>
  redis-password: <base64-encoded-password>
```

### Step 3: Create Persistent Volumes

```yaml
# pvc.yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: misp-data
  namespace: misp
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
  storageClassName: fast-ssd
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: misp-mysql
  namespace: misp
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 8Gi
  storageClassName: fast-ssd
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: misp-redis
  namespace: misp
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
  storageClassName: fast-ssd
```

### Step 4: Deploy Database

```yaml
# mysql-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: misp-mysql
  namespace: misp
spec:
  replicas: 1
  selector:
    matchLabels:
      app: misp-mysql
  template:
    metadata:
      labels:
        app: misp-mysql
    spec:
      containers:
      - name: mysql
        image: mysql:8.0
        ports:
        - containerPort: 3306
        env:
        - name: MYSQL_ROOT_PASSWORD
          valueFrom:
            secretKeyRef:
              name: misp-secrets
              key: mysql-root-password
        - name: MYSQL_DATABASE
          value: misp
        - name: MYSQL_USER
          value: misp
        - name: MYSQL_PASSWORD
          valueFrom:
            secretKeyRef:
              name: misp-secrets
              key: mysql-password
        volumeMounts:
        - name: mysql-data
          mountPath: /var/lib/mysql
      volumes:
      - name: mysql-data
        persistentVolumeClaim:
          claimName: misp-mysql
---
apiVersion: v1
kind: Service
metadata:
  name: misp-mysql
  namespace: misp
spec:
  selector:
    app: misp-mysql
  ports:
  - port: 3306
    targetPort: 3306
```

### Step 5: Deploy Redis

```yaml
# redis-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: misp-redis
  namespace: misp
spec:
  replicas: 1
  selector:
    matchLabels:
      app: misp-redis
  template:
    metadata:
      labels:
        app: misp-redis
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        ports:
        - containerPort: 6379
        volumeMounts:
        - name: redis-data
          mountPath: /data
      volumes:
      - name: redis-data
        persistentVolumeClaim:
          claimName: misp-redis
---
apiVersion: v1
kind: Service
metadata:
  name: misp-redis
  namespace: misp
spec:
  selector:
    app: misp-redis
  ports:
  - port: 6379
    targetPort: 6379
```

### Step 6: Deploy MISP Application

```yaml
# misp-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: misp-app
  namespace: misp
spec:
  replicas: 1
  selector:
    matchLabels:
      app: misp-app
  template:
    metadata:
      labels:
        app: misp-app
    spec:
      containers:
      - name: misp
        image: misp/misp:2.5
        ports:
        - containerPort: 80
        env:
        - name: MISP_BASEURL
          value: "https://misp.local"
        - name: MISP_ORG
          value: "MISP Organization"
        - name: MISP_EMAIL
          value: "admin@misp.local"
        - name: DB_HOST
          value: misp-mysql
        - name: DB_PORT
          value: "3306"
        - name: DB_NAME
          value: misp
        - name: DB_USER
          value: misp
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: misp-secrets
              key: mysql-password
        - name: REDIS_HOST
          value: misp-redis
        - name: REDIS_PORT
          value: "6379"
        volumeMounts:
        - name: misp-data
          mountPath: /var/www/MISP
      volumes:
      - name: misp-data
        persistentVolumeClaim:
          claimName: misp-data
---
apiVersion: v1
kind: Service
metadata:
  name: misp-app
  namespace: misp
spec:
  selector:
    app: misp-app
  ports:
  - port: 80
    targetPort: 80
```

### Step 7: Deploy Workers

```yaml
# workers-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: misp-workers
  namespace: misp
spec:
  replicas: 2
  selector:
    matchLabels:
      app: misp-workers
  template:
    metadata:
      labels:
        app: misp-workers
    spec:
      containers:
      - name: workers
        image: misp/misp:2.5
        command:
        - /bin/bash
        - -c
        - |
          cd /var/www/MISP
          exec php /var/www/MISP/app/Console/worker/start_workers.php
        env:
        - name: MISP_BASEURL
          value: "https://misp.local"
        - name: MISP_ORG
          value: "MISP Organization"
        - name: MISP_EMAIL
          value: "admin@misp.local"
        - name: DB_HOST
          value: misp-mysql
        - name: DB_PORT
          value: "3306"
        - name: DB_NAME
          value: misp
        - name: DB_USER
          value: misp
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: misp-secrets
              key: mysql-password
        - name: REDIS_HOST
          value: misp-redis
        - name: REDIS_PORT
          value: "6379"
        volumeMounts:
        - name: misp-data
          mountPath: /var/www/MISP
      volumes:
      - name: misp-data
        persistentVolumeClaim:
          claimName: misp-data
```

### Step 8: Apply All Manifests

```bash
kubectl apply -f namespace.yaml
kubectl apply -f secrets.yaml
kubectl apply -f pvc.yaml
kubectl apply -f mysql-deployment.yaml
kubectl apply -f redis-deployment.yaml
kubectl apply -f misp-deployment.yaml
kubectl apply -f workers-deployment.yaml
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MISP_BASEURL` | Base URL for MISP | `https://misp.local` |
| `MISP_ORG` | Organization name | `MISP Organization` |
| `MISP_EMAIL` | Admin email | `admin@misp.local` |
| `DB_HOST` | Database host | `misp-mysql` |
| `DB_PORT` | Database port | `3306` |
| `DB_NAME` | Database name | `misp` |
| `DB_USER` | Database user | `misp` |
| `REDIS_HOST` | Redis host | `misp-redis` |
| `REDIS_PORT` | Redis port | `6379` |

### Resource Requirements

#### Minimum Requirements
- **CPU**: 4 cores total
- **Memory**: 8GB total
- **Storage**: 20GB total

#### Recommended Requirements
- **CPU**: 8 cores total
- **Memory**: 16GB total
- **Storage**: 50GB total

### Storage Configuration

#### Storage Classes
```yaml
# Example storage class configuration
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: fast-ssd
provisioner: kubernetes.io/aws-ebs  # or your provisioner
parameters:
  type: gp3
  iops: "3000"
  throughput: "125"
```

#### Persistent Volume Claims
```yaml
# MISP data
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: misp-data
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 20Gi
  storageClassName: fast-ssd

# Database
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: misp-mysql
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
  storageClassName: fast-ssd

# Redis
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: misp-redis
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 2Gi
  storageClassName: fast-ssd
```

## Security Considerations

### Container Security

1. **Non-root Containers**
   ```yaml
   securityContext:
     runAsUser: 1000
     runAsGroup: 1000
     fsGroup: 1000
     readOnlyRootFilesystem: true
   ```

2. **Network Policies**
   ```yaml
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: misp-network-policy
   spec:
     podSelector:
       matchLabels:
         app: misp-app
     policyTypes:
     - Ingress
     - Egress
     ingress:
     - from:
       - namespaceSelector:
           matchLabels:
             name: ingress-nginx
       ports:
       - protocol: TCP
         port: 80
   ```

3. **Secrets Management**
   - Use Kubernetes secrets for sensitive data
   - Rotate passwords regularly
   - Use external secret management (HashiCorp Vault, AWS Secrets Manager)

### TLS Configuration

```yaml
# TLS secret
apiVersion: v1
kind: Secret
metadata:
  name: misp-tls
  namespace: misp
type: kubernetes.io/tls
data:
  tls.crt: <base64-encoded-certificate>
  tls.key: <base64-encoded-private-key>

# Ingress with TLS
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: misp-ingress
  namespace: misp
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - misp.yourdomain.com
    secretName: misp-tls
  rules:
  - host: misp.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: misp-app
            port:
              number: 80
```

## Monitoring and Logging

### Health Checks

```yaml
livenessProbe:
  httpGet:
    path: /
    port: 80
  initialDelaySeconds: 30
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /
    port: 80
  initialDelaySeconds: 5
  periodSeconds: 5
  timeoutSeconds: 3
  failureThreshold: 3
```

### Prometheus Metrics

```yaml
# ServiceMonitor for Prometheus
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: misp-monitor
  namespace: misp
spec:
  selector:
    matchLabels:
      app: misp-app
  endpoints:
  - port: http
    path: /metrics
    interval: 30s
```

### Logging

```yaml
# Fluentd configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: fluentd-config
  namespace: misp
data:
  fluent.conf: |
    <source>
      @type tail
      path /var/log/containers/*.log
      pos_file /var/log/fluentd-containers.log.pos
      tag kubernetes.*
      read_from_head true
      <parse>
        @type json
        time_key time
        time_format %Y-%m-%dT%H:%M:%S.%NZ
      </parse>
    </source>
```

## Backup and Recovery

### Automated Backups

```yaml
# CronJob for database backup
apiVersion: batch/v1
kind: CronJob
metadata:
  name: misp-backup
  namespace: misp
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: mysql:8.0
            command:
            - /bin/bash
            - -c
            - |
              mysqldump -h misp-mysql -u misp -p$MYSQL_PASSWORD misp > /backup/misp-$(date +%Y%m%d).sql
            env:
            - name: MYSQL_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: misp-secrets
                  key: mysql-password
            volumeMounts:
            - name: backup-volume
              mountPath: /backup
          volumes:
          - name: backup-volume
            persistentVolumeClaim:
              claimName: misp-backup
          restartPolicy: OnFailure
```

### Manual Backup

```bash
# Backup database
kubectl exec -it deployment/misp-mysql -- mysqldump -u root -p misp > misp-backup.sql

# Backup MISP data
kubectl exec -it deployment/misp-app -- tar czf /tmp/misp-data-backup.tar.gz /var/www/MISP

# Copy backup from pod
kubectl cp misp/misp-app-xxx:/tmp/misp-data-backup.tar.gz ./misp-data-backup.tar.gz
```

### Recovery

```bash
# Restore database
kubectl exec -i deployment/misp-mysql -- mysql -u root -p misp < misp-backup.sql

# Restore MISP data
kubectl cp ./misp-data-backup.tar.gz misp/misp-app-xxx:/tmp/
kubectl exec -it deployment/misp-app -- tar xzf /tmp/misp-data-backup.tar.gz -C /
```

## Troubleshooting

### Common Issues

#### Pod Not Starting

```bash
# Check pod status
kubectl get pods -n misp

# Check pod logs
kubectl logs -n misp deployment/misp-app
kubectl logs -n misp deployment/misp-mysql
kubectl logs -n misp deployment/misp-redis

# Check events
kubectl get events -n misp --sort-by='.lastTimestamp'
```

#### Database Connection Issues

```bash
# Test database connectivity
kubectl exec -it deployment/misp-app -- mysql -h misp-mysql -u misp -p

# Check database logs
kubectl logs -n misp deployment/misp-mysql

# Check database status
kubectl exec -it deployment/misp-mysql -- mysqladmin -u root -p status
```

#### Storage Issues

```bash
# Check PVC status
kubectl get pvc -n misp

# Check storage class
kubectl get storageclass

# Check persistent volumes
kubectl get pv
```

#### Network Issues

```bash
# Check services
kubectl get svc -n misp

# Test service connectivity
kubectl exec -it deployment/misp-app -- curl misp-mysql:3306
kubectl exec -it deployment/misp-app -- curl misp-redis:6379

# Check network policies
kubectl get networkpolicy -n misp
```

### Debug Commands

```bash
# Get detailed pod information
kubectl describe pod -n misp <pod-name>

# Check resource usage
kubectl top pods -n misp

# Check node resources
kubectl top nodes

# Check cluster events
kubectl get events --all-namespaces --sort-by='.lastTimestamp'
```

## Production Deployment

### High Availability Setup

1. **Multi-zone Deployment**
   ```yaml
   affinity:
     podAntiAffinity:
       preferredDuringSchedulingIgnoredDuringExecution:
       - weight: 100
         podAffinityTerm:
           labelSelector:
             matchExpressions:
             - key: app
               operator: In
               values:
               - misp-app
           topologyKey: kubernetes.io/hostname
   ```

2. **Load Balancing**
   ```yaml
   service:
     type: LoadBalancer
     annotations:
       service.beta.kubernetes.io/aws-load-balancer-type: nlb
   ```

3. **Auto Scaling**
   ```yaml
   apiVersion: autoscaling/v2
   kind: HorizontalPodAutoscaler
   metadata:
     name: misp-hpa
   spec:
     scaleTargetRef:
       apiVersion: apps/v1
       kind: Deployment
       name: misp-app
     minReplicas: 2
     maxReplicas: 10
     metrics:
     - type: Resource
       resource:
         name: cpu
         target:
           type: Utilization
           averageUtilization: 70
   ```

### Disaster Recovery

1. **Multi-cluster Setup**
   - Deploy across multiple Kubernetes clusters
   - Use federation or multi-cluster management tools
   - Implement cross-cluster backup and restore

2. **Backup Strategy**
   - Daily automated backups
   - Point-in-time recovery capability
   - Off-site backup storage

3. **Monitoring and Alerting**
   - Comprehensive monitoring setup
   - Alerting for critical issues
   - SLA monitoring and reporting

## Contributing

This deployment guide is part of the MISP project. Contributions are welcome!

### How to Contribute

1. **Fork the repository**
2. **Create a feature branch**
3. **Make your changes**
4. **Test thoroughly**
5. **Submit a pull request**

### Areas for Contribution

- **Helm Chart Improvements**: Add new features, fix bugs
- **Documentation**: Improve guides, add examples
- **Testing**: Add test cases, improve CI/CD
- **Security**: Security hardening, best practices
- **Monitoring**: Add monitoring configurations
- **Automation**: Improve deployment scripts

### Testing

```bash
# Test Helm chart
helm lint ./helm-charts/misp
helm template ./helm-charts/misp | kubectl apply --dry-run=client -f -

# Test deployment script
./k8s-deploy.sh -d

# Test in local cluster
minikube start
./k8s-deploy.sh
```

## Support

- **Documentation**: [MISP Documentation](https://www.circl.lu/doc/misp/)
- **Community**: [MISP Community](https://www.misp-project.org/community/)
- **Issues**: [GitHub Issues](https://github.com/MISP/MISP/issues)
- **Discussions**: [GitHub Discussions](https://github.com/MISP/MISP/discussions)

## License

This deployment guide is licensed under the same license as MISP: [GNU Affero General Public License version 3](http://www.gnu.org/licenses/agpl-3.0.html).
