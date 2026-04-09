# KUROKAMI Production Deployment Guide

This guide covers deploying KUROKAMI in production environments.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Environment Configuration](#environment-configuration)
- [Docker Deployment](#docker-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Database Setup](#database-setup)
- [Security Hardening](#security-hardening)
- [Monitoring & Logging](#monitoring--logging)
- [Backup & Recovery](#backup--recovery)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements

- **OS**: Linux (Ubuntu 20.04+, Debian 11+, or RHEL 8+)
- **CPU**: 4+ cores recommended
- **RAM**: 8GB minimum, 16GB recommended
- **Disk**: 50GB+ for data storage
- **Network**: Outbound internet access for tool updates

### Software Requirements

- Docker 24.0+ and Docker Compose 2.0+
- PostgreSQL 15+ (for production database)
- Ollama (for AI/LLM features)

## Environment Configuration

### 1. Create Environment File

Copy the example environment file:

```bash
cp .env.example .env
```

### 2. Configure Critical Settings

Edit `.env` and set the following:

```bash
# Environment
KUROKAMI_ENV=production

# Database (use PostgreSQL in production)
DATABASE_URL=postgresql://kurokami:STRONG_PASSWORD@localhost:5432/kurokami

# Security
ALLOW_EXPLOITS=false
WORKSPACE_ENCRYPTION=true
FERNET_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
API_KEY=$(openssl rand -hex 32)

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json

# Rate Limiting
RATE_LIMIT_ENABLED=true
MAX_SCANS_PER_HOUR=10
MAX_CONCURRENT_SCANS=3
```

### 3. Secure the Environment File

```bash
chmod 600 .env
chown kurokami:kurokami .env
```

## Docker Deployment

### Quick Start

```bash
# Build and start all services
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f kurokami
```

### Production Configuration

1. **Update docker-compose.yml** with production settings:

```yaml
services:
  kurokami:
    restart: always
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 8G
        reservations:
          cpus: '2'
          memory: 4G
```

2. **Set database password**:

```bash
export DB_PASSWORD=$(openssl rand -base64 32)
echo "DB_PASSWORD=$DB_PASSWORD" >> .env
```

3. **Start services**:

```bash
docker-compose up -d
```

### Verify Deployment

```bash
# Check health
docker-compose exec kurokami python -c "from core.database import init_db; init_db(); print('OK')"

# Run a test scan
docker-compose exec kurokami python -m core.cli scan --target example.com
```

## Kubernetes Deployment

### 1. Create Namespace

```bash
kubectl create namespace kurokami
```

### 2. Create Secrets

```bash
kubectl create secret generic kurokami-secrets \
  --from-literal=db-password=$(openssl rand -base64 32) \
  --from-literal=api-key=$(openssl rand -hex 32) \
  --from-literal=fernet-key=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())") \
  -n kurokami
```

### 3. Deploy PostgreSQL

```bash
kubectl apply -f k8s/postgres.yaml -n kurokami
```

### 4. Deploy KUROKAMI

```bash
kubectl apply -f k8s/kurokami.yaml -n kurokami
```

### 5. Verify Deployment

```bash
kubectl get pods -n kurokami
kubectl logs -f deployment/kurokami -n kurokami
```

## Database Setup

### PostgreSQL Production Setup

1. **Install PostgreSQL**:

```bash
sudo apt-get install postgresql-15
```

2. **Create database and user**:

```sql
CREATE DATABASE kurokami;
CREATE USER kurokami WITH ENCRYPTED PASSWORD 'STRONG_PASSWORD';
GRANT ALL PRIVILEGES ON DATABASE kurokami TO kurokami;
```

3. **Run migrations**:

```bash
alembic upgrade head
```

4. **Configure connection pooling** (recommended for high load):

```python
# In core/database.py
engine = create_engine(
    DATABASE_URL,
    pool_size=20,
    max_overflow=40,
    pool_pre_ping=True,
    pool_recycle=3600
)
```

### Database Backup

Set up automated backups:

```bash
# Add to crontab
0 2 * * * pg_dump -U kurokami kurokami | gzip > /backup/kurokami_$(date +\%Y\%m\%d).sql.gz
```

## Security Hardening

### 1. Firewall Configuration

```bash
# Allow only necessary ports
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 443/tcp   # HTTPS (if exposing API)
sudo ufw enable
```

### 2. Enable Encryption

```bash
# Generate Fernet key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Add to .env
WORKSPACE_ENCRYPTION=true
FERNET_KEY=<generated-key>
```

### 3. Configure TLS/SSL

For API access, use a reverse proxy (nginx/traefik) with Let's Encrypt:

```nginx
server {
    listen 443 ssl http2;
    server_name kurokami.example.com;
    
    ssl_certificate /etc/letsencrypt/live/kurokami.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/kurokami.example.com/privkey.pem;
    
    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 4. Implement Authentication

Add API key authentication for CLI access:

```bash
# Set in .env
API_KEY=your-secret-api-key

# Use in requests
kurokami scan --target example.com --api-key $API_KEY
```

## Monitoring & Logging

### Centralized Logging

Configure log aggregation with ELK stack or similar:

```yaml
# docker-compose.yml
services:
  kurokami:
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

### Metrics Collection

Enable Prometheus metrics:

```bash
# In .env
ENABLE_METRICS=true
METRICS_PORT=9090
```

### Health Checks

Monitor service health:

```bash
# Check application health
curl http://localhost:8000/health

# Check database connectivity
docker-compose exec kurokami python -c "from core.database import get_session; get_session()"
```

### Alerting

Set up alerts for:
- Failed scans
- High error rates
- Resource exhaustion
- Security events (exploit attempts, validation failures)

## Backup & Recovery

### Automated Backup Script

```bash
#!/bin/bash
# backup.sh

BACKUP_DIR="/backup/kurokami"
DATE=$(date +%Y%m%d_%H%M%S)

# Backup database
pg_dump -U kurokami kurokami | gzip > "$BACKUP_DIR/db_$DATE.sql.gz"

# Backup data directory
tar -czf "$BACKUP_DIR/data_$DATE.tar.gz" data/

# Backup configuration
cp .env "$BACKUP_DIR/env_$DATE"
cp kurokami.conf "$BACKUP_DIR/conf_$DATE"

# Cleanup old backups (keep 30 days)
find "$BACKUP_DIR" -name "*.gz" -mtime +30 -delete

echo "Backup completed: $DATE"
```

### Recovery Procedure

```bash
# 1. Stop services
docker-compose down

# 2. Restore database
gunzip < backup/db_20260410.sql.gz | psql -U kurokami kurokami

# 3. Restore data
tar -xzf backup/data_20260410.tar.gz

# 4. Restore configuration
cp backup/env_20260410 .env
cp backup/conf_20260410 kurokami.conf

# 5. Start services
docker-compose up -d
```

## Troubleshooting

### Common Issues

#### Database Connection Errors

```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Test connection
psql -U kurokami -h localhost -d kurokami

# Check logs
docker-compose logs postgres
```

#### Ollama Not Responding

```bash
# Check Ollama status
docker-compose logs ollama

# Restart Ollama
docker-compose restart ollama

# Pull required model
docker-compose exec ollama ollama pull qwen2.5:14b
```

#### High Memory Usage

```bash
# Check resource usage
docker stats

# Adjust limits in docker-compose.yml
deploy:
  resources:
    limits:
      memory: 4G
```

#### Rate Limit Issues

```bash
# Check rate limit status
# Adjust in .env
MAX_SCANS_PER_HOUR=20
MAX_CONCURRENT_SCANS=5
```

### Debug Mode

Enable debug logging:

```bash
# In .env
LOG_LEVEL=DEBUG

# Restart services
docker-compose restart kurokami
```

### Support

For issues not covered here:
1. Check logs: `docker-compose logs -f`
2. Review audit trail: `cat data/logs/audit.log`
3. Open GitHub issue with logs and configuration (redact secrets!)

## Performance Tuning

### Database Optimization

```sql
-- Create indexes for common queries
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_session_target ON findings(session_id, target_id);
CREATE INDEX idx_sessions_status ON sessions(status);
```

### Caching

Consider adding Redis for caching:

```yaml
services:
  redis:
    image: redis:7-alpine
    volumes:
      - redis-data:/data
```

### Resource Allocation

Adjust based on workload:

```yaml
services:
  kurokami:
    deploy:
      resources:
        limits:
          cpus: '8'
          memory: 16G
```

## Maintenance

### Regular Tasks

- **Daily**: Check logs for errors
- **Weekly**: Review audit trail, update security tools
- **Monthly**: Update dependencies, review performance metrics
- **Quarterly**: Security audit, disaster recovery test

### Updates

```bash
# Pull latest code
git pull origin main

# Rebuild containers
docker-compose build --no-cache

# Run migrations
docker-compose exec kurokami alembic upgrade head

# Restart services
docker-compose up -d
```
