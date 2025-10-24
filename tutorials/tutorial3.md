# Tutorial 3: Production Deployment & Operations

**Estimated Time:** 6-8 hours
**Difficulty:** Advanced
**Prerequisites:** Tutorials 1 & 2 completed, basic DevOps knowledge, access to a cloud provider

This tutorial covers everything needed to deploy and operate your imageboard in production: containerization, orchestration, monitoring, logging, backups, and CI/CD.

---

## Table of Contents

1. [Docker Containerization (60 min)](#1-docker-containerization)
2. [Production Infrastructure Setup (90 min)](#2-production-infrastructure-setup)
3. [Monitoring & Alerting (60 min)](#3-monitoring--alerting)
4. [Structured Logging (45 min)](#4-structured-logging)
5. [Backup & Disaster Recovery (45 min)](#5-backup--disaster-recovery)
6. [CI/CD Pipeline (60 min)](#6-cicd-pipeline)
7. [SSL/TLS & Security Headers (30 min)](#7-ssltls--security-headers)
8. [Load Testing & Optimization (45 min)](#8-load-testing--optimization)

---

## 1. Docker Containerization

### Why This Matters

**Benefits of containerization:**
- Consistent environment (dev == staging == prod)
- Easy deployment and rollback
- Resource isolation and limits
- Scalability (run multiple containers)
- Simplified dependency management

### Step 1: Create Multi-Stage Dockerfile

Create `Dockerfile`:

```dockerfile
# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev

WORKDIR /build

# Copy go mod files and download dependencies (cached layer)
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
# CGO_ENABLED=0 creates a static binary (no C dependencies)
# -ldflags="-w -s" strips debug info (smaller binary)
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o imageboard .

# Runtime stage
FROM alpine:latest

# Install CA certificates for HTTPS calls
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user for security
RUN addgroup -g 1000 appgroup && \
    adduser -D -u 1000 -G appgroup appuser

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/imageboard .

# Copy templates (needed at runtime)
COPY --from=builder /build/templates ./templates

# Create uploads directory and set permissions
RUN mkdir -p /app/uploads && \
    chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/ || exit 1

# Run the application
CMD ["./imageboard"]
```

**Understanding the Dockerfile:**

- **Multi-stage build**: Separates build tools from runtime (smaller image)
- **Builder stage**: Uses golang image with all build tools
- **Runtime stage**: Uses minimal alpine image (5MB vs 800MB)
- **Non-root user**: Security best practice
- **Health check**: Lets Docker/orchestrators monitor application health

### Step 2: Create .dockerignore

```
# .dockerignore - files to exclude from Docker build

.git
.github
.env
.env.example
*.md
.DS_Store
.idea
.vscode

# Binaries
*.exe
imageboard

# Logs
*.log

# Docker files
docker-compose*.yml
Dockerfile

# Development files
tutorials/
migrations/
```

### Step 3: Create Production docker-compose.yml

Create `docker-compose.prod.yml`:

```yaml
version: '3.8'

services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
    image: imageboard:latest
    container_name: imageboard-app
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      - DB_HOST=postgres
      - DB_PORT=5432
      - DB_USER=imageboard
      - DB_PASSWORD=${DB_PASSWORD}
      - DB_NAME=imageboard
      - REDIS_ADDR=redis:6379
      - REDIS_PASSWORD=${REDIS_PASSWORD}
      - REDIS_DB=0
      - PORT=8080
      - RECAPTCHA_SECRET_KEY=${RECAPTCHA_SECRET_KEY}
      - CSRF_KEY=${CSRF_KEY}
      - R2_ACCESS_KEY=${R2_ACCESS_KEY}
      - R2_SECRET_KEY=${R2_SECRET_KEY}
      - R2_ACCOUNT_ID=${R2_ACCOUNT_ID}
      - R2_BUCKET_NAME=${R2_BUCKET_NAME}
      - ENVIRONMENT=production
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - imageboard-network
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 256M

  postgres:
    image: postgres:14-alpine
    container_name: imageboard-postgres
    restart: unless-stopped
    environment:
      POSTGRES_USER: imageboard
      POSTGRES_PASSWORD: ${DB_PASSWORD}
      POSTGRES_DB: imageboard
      PGDATA: /var/lib/postgresql/data/pgdata
    volumes:
      - postgres-data:/var/lib/postgresql/data
      - ./backups/postgres:/backups
    networks:
      - imageboard-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U imageboard"]
      interval: 10s
      timeout: 5s
      retries: 5
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          cpus: '1.0'
          memory: 1G

  redis:
    image: redis:7-alpine
    container_name: imageboard-redis
    restart: unless-stopped
    command: >
      redis-server
      --requirepass ${REDIS_PASSWORD}
      --maxmemory 512mb
      --maxmemory-policy allkeys-lru
      --save 900 1
      --save 300 10
      --save 60 10000
      --appendonly yes
    volumes:
      - redis-data:/data
      - ./backups/redis:/backups
    networks:
      - imageboard-network
    healthcheck:
      test: ["CMD", "redis-cli", "--raw", "incr", "ping"]
      interval: 10s
      timeout: 3s
      retries: 5
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 256M

  nginx:
    image: nginx:alpine
    container_name: imageboard-nginx
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
      - nginx-cache:/var/cache/nginx
    depends_on:
      - app
    networks:
      - imageboard-network
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 256M

  # Prometheus for metrics
  prometheus:
    image: prom/prometheus:latest
    container_name: imageboard-prometheus
    restart: unless-stopped
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--storage.tsdb.retention.time=30d'
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus-data:/prometheus
    ports:
      - "9090:9090"
    networks:
      - imageboard-network

  # Grafana for dashboards
  grafana:
    image: grafana/grafana:latest
    container_name: imageboard-grafana
    restart: unless-stopped
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
      - GF_SERVER_ROOT_URL=http://localhost:3000
    volumes:
      - grafana-data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning:ro
    ports:
      - "3000:3000"
    depends_on:
      - prometheus
    networks:
      - imageboard-network

volumes:
  postgres-data:
    driver: local
  redis-data:
    driver: local
  nginx-cache:
    driver: local
  prometheus-data:
    driver: local
  grafana-data:
    driver: local

networks:
  imageboard-network:
    driver: bridge
```

### Step 4: Build and Test Docker Image

```bash
# Build the image
docker build -t imageboard:latest .

# Check image size
docker images imageboard:latest

# Should see something like:
# REPOSITORY   TAG       SIZE
# imageboard   latest    20MB  (multi-stage build is small!)

# Test the image
docker run --rm -p 8080:8080 \
  -e DB_HOST=localhost \
  -e REDIS_ADDR=localhost:6379 \
  imageboard:latest

# Test health check
docker inspect --format='{{.State.Health.Status}}' imageboard-app
# Should show: healthy
```

### Step 5: Create Production Environment File

Create `.env.production`:

```bash
# Database
DB_PASSWORD=<strong-random-password>

# Redis
REDIS_PASSWORD=<strong-random-password>

# Application
RECAPTCHA_SECRET_KEY=<your-recaptcha-key>
CSRF_KEY=<32-byte-random-key>

# Storage
R2_ACCESS_KEY=<your-r2-access-key>
R2_SECRET_KEY=<your-r2-secret-key>
R2_ACCOUNT_ID=<your-r2-account-id>
R2_BUCKET_NAME=imageboard-images

# Monitoring
GRAFANA_PASSWORD=<strong-random-password>
```

**Generate strong passwords:**
```bash
# Generate random passwords
openssl rand -base64 32
```

### Step 6: Deploy with Docker Compose

```bash
# Create necessary directories
mkdir -p backups/postgres backups/redis ssl

# Deploy
docker-compose -f docker-compose.prod.yml --env-file .env.production up -d

# Check status
docker-compose -f docker-compose.prod.yml ps

# View logs
docker-compose -f docker-compose.prod.yml logs -f app

# Check health
docker-compose -f docker-compose.prod.yml exec app wget -q -O- http://localhost:8080/
```

### What You Learned

✅ Multi-stage Docker builds for smaller images
✅ Security best practices (non-root user, minimal base image)
✅ Health checks for container orchestration
✅ Resource limits to prevent resource exhaustion
✅ Docker Compose for multi-container applications

---

## 2. Production Infrastructure Setup

### Step 1: Create nginx Configuration

Create `nginx.conf`:

```nginx
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
    use epoll;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Logging
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for" '
                    'rt=$request_time uct="$upstream_connect_time" '
                    'uht="$upstream_header_time" urt="$upstream_response_time"';

    access_log /var/log/nginx/access.log main;

    # Performance
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    client_max_body_size 10M;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript
               application/json application/javascript application/xml+rss
               application/rss+xml font/truetype font/opentype
               application/vnd.ms-fontobject image/svg+xml;

    # Rate limiting zones
    limit_req_zone $binary_remote_addr zone=general:10m rate=30r/m;
    limit_req_zone $binary_remote_addr zone=posts:10m rate=5r/m;
    limit_req_zone $binary_remote_addr zone=login:10m rate=3r/m;

    # Upstream (app servers)
    upstream imageboard_app {
        least_conn; # Load balancing method
        server app:8080 max_fails=3 fail_timeout=30s;
        # Add more servers for horizontal scaling:
        # server app2:8080 max_fails=3 fail_timeout=30s;
        # server app3:8080 max_fails=3 fail_timeout=30s;
    }

    # Cache configuration
    proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=imageboard_cache:10m
                     max_size=1g inactive=60m use_temp_path=off;

    # HTTP server (redirect to HTTPS)
    server {
        listen 80;
        server_name yourdomain.com www.yourdomain.com;

        # ACME challenge for Let's Encrypt
        location /.well-known/acme-challenge/ {
            root /var/www/certbot;
        }

        # Redirect everything else to HTTPS
        location / {
            return 301 https://$server_name$request_uri;
        }
    }

    # HTTPS server
    server {
        listen 443 ssl http2;
        server_name yourdomain.com www.yourdomain.com;

        # SSL configuration
        ssl_certificate /etc/nginx/ssl/fullchain.pem;
        ssl_certificate_key /etc/nginx/ssl/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 10m;

        # Security headers
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;

        # Static files (if you have any in /static)
        location /static/ {
            alias /app/static/;
            expires 1y;
            add_header Cache-Control "public, immutable";
        }

        # Images (cached)
        location /images/ {
            proxy_pass http://imageboard_app;
            proxy_cache imageboard_cache;
            proxy_cache_valid 200 1d;
            proxy_cache_valid 404 1m;
            add_header X-Cache-Status $upstream_cache_status;
            expires 1d;
        }

        # Login endpoint (strict rate limiting)
        location /login {
            limit_req zone=login burst=5 nodelay;
            proxy_pass http://imageboard_app;
            include /etc/nginx/proxy_params.conf;
        }

        # Post creation endpoints (moderate rate limiting)
        location ~ ^/(new-thread|new-post) {
            limit_req zone=posts burst=10 nodelay;
            proxy_pass http://imageboard_app;
            include /etc/nginx/proxy_params.conf;
        }

        # General endpoints (light rate limiting)
        location / {
            limit_req zone=general burst=50 nodelay;
            proxy_pass http://imageboard_app;
            include /etc/nginx/proxy_params.conf;
        }
    }
}
```

Create `proxy_params.conf`:

```nginx
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;

proxy_connect_timeout 60s;
proxy_send_timeout 60s;
proxy_read_timeout 60s;

proxy_buffering on;
proxy_buffer_size 4k;
proxy_buffers 8 4k;
proxy_busy_buffers_size 8k;
```

### Step 2: Set Up SSL with Let's Encrypt

```bash
# Install certbot
sudo apt-get update
sudo apt-get install certbot python3-certbot-nginx

# Get certificate
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com

# Copy certificates to project
sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem ./ssl/
sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem ./ssl/

# Set up auto-renewal
sudo certbot renew --dry-run

# Add renewal to crontab
sudo crontab -e
# Add line:
0 0 * * * certbot renew --quiet --post-hook "docker-compose -f /path/to/docker-compose.prod.yml restart nginx"
```

### Step 3: Database Replication (PostgreSQL)

**Primary-Replica setup for high availability:**

Add to `docker-compose.prod.yml`:

```yaml
services:
  postgres-replica:
    image: postgres:14-alpine
    container_name: imageboard-postgres-replica
    restart: unless-stopped
    environment:
      POSTGRES_USER: imageboard
      POSTGRES_PASSWORD: ${DB_PASSWORD}
      PGDATA: /var/lib/postgresql/data/pgdata
    command: >
      postgres
      -c wal_level=replica
      -c hot_standby=on
      -c max_wal_senders=10
      -c max_replication_slots=10
      -c hot_standby_feedback=on
    volumes:
      - postgres-replica-data:/var/lib/postgresql/data
    networks:
      - imageboard-network
    depends_on:
      - postgres

volumes:
  postgres-replica-data:
    driver: local
```

**Configure replication on primary:**

```bash
# Connect to primary
docker exec -it imageboard-postgres psql -U imageboard

# Create replication user
CREATE USER replicator WITH REPLICATION ENCRYPTED PASSWORD 'repl_password';

# Edit pg_hba.conf to allow replication
# Add line:
host replication replicator postgres-replica md5
```

### Step 4: Redis Sentinel for High Availability

Add to `docker-compose.prod.yml`:

```yaml
  redis-replica:
    image: redis:7-alpine
    container_name: imageboard-redis-replica
    restart: unless-stopped
    command: redis-server --slaveof redis 6379 --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis-replica-data:/data
    networks:
      - imageboard-network
    depends_on:
      - redis

  sentinel:
    image: redis:7-alpine
    container_name: imageboard-sentinel
    restart: unless-stopped
    command: redis-sentinel /etc/redis/sentinel.conf
    volumes:
      - ./sentinel.conf:/etc/redis/sentinel.conf
    networks:
      - imageboard-network
    depends_on:
      - redis
      - redis-replica

volumes:
  redis-replica-data:
    driver: local
```

Create `sentinel.conf`:

```
sentinel monitor mymaster redis 6379 2
sentinel auth-pass mymaster ${REDIS_PASSWORD}
sentinel down-after-milliseconds mymaster 5000
sentinel parallel-syncs mymaster 1
sentinel failover-timeout mymaster 10000
```

### What You Learned

✅ nginx as reverse proxy and load balancer
✅ SSL/TLS termination
✅ Database replication for high availability
✅ Redis Sentinel for automatic failover
✅ Layer-7 load balancing strategies

---

## 3. Monitoring & Alerting

### Step 1: Add Metrics Endpoint to Application

Create `metrics.go`:

```go
package main

import (
	"fmt"
	"net/http"
	"runtime"
	"time"
)

var (
	startTime = time.Now()
	requestCount int64
	errorCount int64
)

// MetricsHandler exposes Prometheus-compatible metrics
func MetricsHandler(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	fmt.Fprintf(w, "# HELP imageboard_uptime_seconds Application uptime in seconds\n")
	fmt.Fprintf(w, "# TYPE imageboard_uptime_seconds counter\n")
	fmt.Fprintf(w, "imageboard_uptime_seconds %d\n", int64(time.Since(startTime).Seconds()))

	fmt.Fprintf(w, "# HELP imageboard_requests_total Total number of requests\n")
	fmt.Fprintf(w, "# TYPE imageboard_requests_total counter\n")
	fmt.Fprintf(w, "imageboard_requests_total %d\n", requestCount)

	fmt.Fprintf(w, "# HELP imageboard_errors_total Total number of errors\n")
	fmt.Fprintf(w, "# TYPE imageboard_errors_total counter\n")
	fmt.Fprintf(w, "imageboard_errors_total %d\n", errorCount)

	fmt.Fprintf(w, "# HELP imageboard_memory_bytes Memory usage in bytes\n")
	fmt.Fprintf(w, "# TYPE imageboard_memory_bytes gauge\n")
	fmt.Fprintf(w, "imageboard_memory_bytes %d\n", m.Alloc)

	fmt.Fprintf(w, "# HELP imageboard_goroutines Number of goroutines\n")
	fmt.Fprintf(w, "# TYPE imageboard_goroutines gauge\n")
	fmt.Fprintf(w, "imageboard_goroutines %d\n", runtime.NumGoroutine())

	// Database pool stats
	stats := db.Stats()
	fmt.Fprintf(w, "# HELP imageboard_db_connections_open Open database connections\n")
	fmt.Fprintf(w, "# TYPE imageboard_db_connections_open gauge\n")
	fmt.Fprintf(w, "imageboard_db_connections_open %d\n", stats.OpenConnections)

	fmt.Fprintf(w, "# HELP imageboard_db_connections_in_use Database connections in use\n")
	fmt.Fprintf(w, "# TYPE imageboard_db_connections_in_use gauge\n")
	fmt.Fprintf(w, "imageboard_db_connections_in_use %d\n", stats.InUse)

	w.Header().Set("Content-Type", "text/plain")
}

// MetricsMiddleware tracks request metrics
func MetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w}

		next.ServeHTTP(wrapped, r)

		if wrapped.status >= 400 {
			errorCount++
		}
	})
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (w *responseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
```

**Add to main.go:**

```go
// Metrics endpoint (should not be publicly accessible)
http.HandleFunc("/metrics", MetricsHandler)

// Wrap with metrics middleware
handler = MetricsMiddleware(handler)
```

### Step 2: Configure Prometheus

Create `prometheus.yml`:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  # Imageboard application
  - job_name: 'imageboard'
    static_configs:
      - targets: ['app:8080']
    metrics_path: /metrics

  # PostgreSQL exporter (optional - requires postgres_exporter)
  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres-exporter:9187']

  # Redis exporter (optional - requires redis_exporter)
  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']

  # nginx exporter (optional)
  - job_name: 'nginx'
    static_configs:
      - targets: ['nginx-exporter:9113']
```

### Step 3: Create Grafana Dashboard

Create `grafana/provisioning/dashboards/imageboard.json`:

```json
{
  "dashboard": {
    "title": "Imageboard Monitoring",
    "panels": [
      {
        "title": "Request Rate",
        "targets": [
          {
            "expr": "rate(imageboard_requests_total[5m])"
          }
        ]
      },
      {
        "title": "Error Rate",
        "targets": [
          {
            "expr": "rate(imageboard_errors_total[5m])"
          }
        ]
      },
      {
        "title": "Memory Usage",
        "targets": [
          {
            "expr": "imageboard_memory_bytes"
          }
        ]
      },
      {
        "title": "Database Connections",
        "targets": [
          {
            "expr": "imageboard_db_connections_open",
            "legendFormat": "Open"
          },
          {
            "expr": "imageboard_db_connections_in_use",
            "legendFormat": "In Use"
          }
        ]
      }
    ]
  }
}
```

### Step 4: Set Up Alerting

Create `prometheus-alerts.yml`:

```yaml
groups:
  - name: imageboard
    interval: 30s
    rules:
      # High error rate
      - alert: HighErrorRate
        expr: rate(imageboard_errors_total[5m]) > 0.05
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value }} errors/sec"

      # Application down
      - alert: ApplicationDown
        expr: up{job="imageboard"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Application is down"
          description: "Imageboard application has been down for more than 1 minute"

      # High memory usage
      - alert: HighMemoryUsage
        expr: imageboard_memory_bytes > 400000000  # 400MB
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage"
          description: "Memory usage is {{ humanize $value }} bytes"

      # Database connection pool exhaustion
      - alert: DatabaseConnectionsHigh
        expr: imageboard_db_connections_in_use / imageboard_db_connections_open > 0.8
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Database connection pool near exhaustion"
          description: "{{ $value | humanizePercentage }} of connections in use"
```

**Update prometheus.yml:**

```yaml
rule_files:
  - /etc/prometheus/prometheus-alerts.yml

alerting:
  alertmanagers:
    - static_configs:
        - targets: ['alertmanager:9093']
```

### What You Learned

✅ Exposing application metrics in Prometheus format
✅ Scraping metrics with Prometheus
✅ Visualizing metrics with Grafana dashboards
✅ Setting up alerts for critical conditions
✅ Monitoring application health and performance

---

## 4. Structured Logging

### Step 1: Install Logging Library

```bash
go get go.uber.org/zap
```

### Step 2: Create Logger

Create `logger.go`:

```go
package main

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logger *zap.Logger

// InitLogger initializes the application logger
func InitLogger() error {
	var err error

	// Production config
	config := zap.NewProductionConfig()

	// Set log level from environment
	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "info"
	}

	var level zapcore.Level
	switch logLevel {
	case "debug":
		level = zapcore.DebugLevel
	case "info":
		level = zapcore.InfoLevel
	case "warn":
		level = zapcore.WarnLevel
	case "error":
		level = zapcore.ErrorLevel
	default:
		level = zapcore.InfoLevel
	}

	config.Level = zap.NewAtomicLevelAt(level)

	// JSON encoding for production (easier to parse)
	config.Encoding = "json"

	// Add caller info
	config.EncoderConfig.CallerKey = "caller"

	// Build logger
	logger, err = config.Build(zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
	if err != nil {
		return err
	}

	// Replace global logger
	zap.ReplaceGlobals(logger)

	return nil
}

// LogRequest logs HTTP request with structured fields
func LogRequest(method, path, ip string, status int, duration int64) {
	logger.Info("request",
		zap.String("method", method),
		zap.String("path", path),
		zap.String("ip", ip),
		zap.Int("status", status),
		zap.Int64("duration_ms", duration),
	)
}

// LogError logs errors with context
func LogError(message string, err error, fields ...zap.Field) {
	allFields := append(fields, zap.Error(err))
	logger.Error(message, allFields...)
}

// LogInfo logs informational messages
func LogInfo(message string, fields ...zap.Field) {
	logger.Info(message, fields...)
}

// LogWarning logs warnings
func LogWarning(message string, fields ...zap.Field) {
	logger.Warn(message, fields...)
}

// LogDebug logs debug information
func LogDebug(message string, fields ...zap.Field) {
	logger.Debug(message, fields...)
}

// Sync flushes any buffered log entries
func LoggerSync() {
	if logger != nil {
		logger.Sync()
	}
}
```

### Step 3: Add Request Logging Middleware

```go
// LoggingMiddleware logs all HTTP requests
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		wrapped := &loggingResponseWriter{
			ResponseWriter: w,
			statusCode:     200,
		}

		// Process request
		next.ServeHTTP(wrapped, r)

		// Log request
		duration := time.Since(start).Milliseconds()
		ip := getIPAddress(r)

		LogRequest(r.Method, r.URL.Path, ip, wrapped.statusCode, duration)
	})
}

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *loggingResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}
```

### Step 4: Update Application

**In main.go:**

```go
func main() {
	// Initialize logger first
	err := InitLogger()
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer LoggerSync()

	LogInfo("Starting imageboard application")

	// ... existing initialization ...

	// Wrap with logging middleware
	handler = LoggingMiddleware(handler)

	LogInfo("Server starting", zap.String("port", port))
	log.Fatal(http.ListenAndServe(":"+port, handler))
}
```

**Replace all log.Printf with structured logging:**

```go
// Before:
log.Printf("Connected to PostgreSQL database successfully")

// After:
LogInfo("Database connected", zap.String("host", dbHost))

// Before:
log.Printf("Error creating thread: %v", err)

// After:
LogError("Failed to create thread", err,
	zap.Int("board_id", boardID),
	zap.String("title", title),
)
```

### Step 5: Log Aggregation (Optional)

**Send logs to centralized system (e.g., Loki, Elasticsearch):**

Add to `docker-compose.prod.yml`:

```yaml
  loki:
    image: grafana/loki:latest
    container_name: imageboard-loki
    restart: unless-stopped
    ports:
      - "3100:3100"
    volumes:
      - ./loki-config.yml:/etc/loki/local-config.yaml
      - loki-data:/loki
    networks:
      - imageboard-network

  promtail:
    image: grafana/promtail:latest
    container_name: imageboard-promtail
    restart: unless-stopped
    volumes:
      - /var/log:/var/log
      - /var/lib/docker/containers:/var/lib/docker/containers:ro
      - ./promtail-config.yml:/etc/promtail/config.yml
    command: -config.file=/etc/promtail/config.yml
    networks:
      - imageboard-network
    depends_on:
      - loki

volumes:
  loki-data:
    driver: local
```

### Example Log Output

**Development (console):**
```
2024-01-15T10:30:45.123Z  INFO  request  method=GET path=/ ip=192.168.1.1 status=200 duration_ms=15
```

**Production (JSON):**
```json
{
  "level": "info",
  "ts": 1705316445.123,
  "caller": "main/handlers.go:123",
  "msg": "request",
  "method": "GET",
  "path": "/",
  "ip": "192.168.1.1",
  "status": 200,
  "duration_ms": 15
}
```

### What You Learned

✅ Structured logging vs unstructured logging
✅ Log levels and when to use them (debug, info, warn, error)
✅ Contextual logging with key-value pairs
✅ Centralized log aggregation
✅ Performance impact of logging

---

## 5. Backup & Disaster Recovery

### Step 1: PostgreSQL Backups

Create `scripts/backup-postgres.sh`:

```bash
#!/bin/bash

# Configuration
BACKUP_DIR="/backups/postgres"
RETENTION_DAYS=30
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/imageboard_$DATE.sql.gz"

# Create backup directory if it doesn't exist
mkdir -p $BACKUP_DIR

# Create backup
docker exec imageboard-postgres pg_dump -U imageboard imageboard | gzip > $BACKUP_FILE

# Check if backup was successful
if [ $? -eq 0 ]; then
    echo "Backup successful: $BACKUP_FILE"

    # Upload to S3 (optional)
    # aws s3 cp $BACKUP_FILE s3://your-backup-bucket/postgres/

    # Delete old backups
    find $BACKUP_DIR -name "imageboard_*.sql.gz" -mtime +$RETENTION_DAYS -delete
    echo "Deleted backups older than $RETENTION_DAYS days"
else
    echo "Backup failed!"
    exit 1
fi
```

Make executable:
```bash
chmod +x scripts/backup-postgres.sh
```

**Set up cron job:**
```bash
# Run daily at 2 AM
0 2 * * * /path/to/scripts/backup-postgres.sh >> /var/log/postgres-backup.log 2>&1
```

### Step 2: Redis Backups

Create `scripts/backup-redis.sh`:

```bash
#!/bin/bash

BACKUP_DIR="/backups/redis"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/dump_$DATE.rdb"

mkdir -p $BACKUP_DIR

# Trigger Redis save
docker exec imageboard-redis redis-cli SAVE

# Copy RDB file
docker cp imageboard-redis:/data/dump.rdb $BACKUP_FILE

if [ $? -eq 0 ]; then
    echo "Redis backup successful: $BACKUP_FILE"
    gzip $BACKUP_FILE

    # Upload to S3 (optional)
    # aws s3 cp $BACKUP_FILE.gz s3://your-backup-bucket/redis/

    # Delete old backups
    find $BACKUP_DIR -name "dump_*.rdb.gz" -mtime +7 -delete
else
    echo "Redis backup failed!"
    exit 1
fi
```

### Step 3: Application State Backup

Create `scripts/full-backup.sh`:

```bash
#!/bin/bash

# Full system backup

BACKUP_DIR="/backups/full"
DATE=$(date +%Y%m%d)
BACKUP_NAME="imageboard_full_$DATE"

mkdir -p $BACKUP_DIR/$BACKUP_NAME

# Backup PostgreSQL
./scripts/backup-postgres.sh

# Backup Redis
./scripts/backup-redis.sh

# Backup environment config (without secrets)
cp .env.production $BACKUP_DIR/$BACKUP_NAME/.env.backup

# Create tarball
tar -czf $BACKUP_DIR/$BACKUP_NAME.tar.gz -C $BACKUP_DIR $BACKUP_NAME

# Upload to S3
aws s3 cp $BACKUP_DIR/$BACKUP_NAME.tar.gz s3://your-backup-bucket/full/

# Clean up
rm -rf $BACKUP_DIR/$BACKUP_NAME

echo "Full backup complete: $BACKUP_NAME.tar.gz"
```

### Step 4: Restore Procedures

Create `scripts/restore-postgres.sh`:

```bash
#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 <backup_file.sql.gz>"
    exit 1
fi

BACKUP_FILE=$1

# Stop application to prevent writes
docker-compose -f docker-compose.prod.yml stop app

# Drop and recreate database
docker exec imageboard-postgres psql -U imageboard -c "DROP DATABASE IF EXISTS imageboard;"
docker exec imageboard-postgres psql -U imageboard -c "CREATE DATABASE imageboard;"

# Restore from backup
gunzip -c $BACKUP_FILE | docker exec -i imageboard-postgres psql -U imageboard imageboard

# Restart application
docker-compose -f docker-compose.prod.yml start app

echo "Restore complete!"
```

### Step 5: Disaster Recovery Plan

Create `DISASTER_RECOVERY.md`:

```markdown
# Disaster Recovery Plan

## Recovery Time Objective (RTO): 1 hour
## Recovery Point Objective (RPO): 24 hours

### Scenario 1: Database Corruption

1. Stop application:
   ```bash
   docker-compose -f docker-compose.prod.yml stop app
   ```

2. Restore from latest backup:
   ```bash
   ./scripts/restore-postgres.sh /backups/postgres/latest.sql.gz
   ```

3. Verify data integrity
4. Restart application

### Scenario 2: Complete Server Failure

1. Provision new server
2. Install Docker and Docker Compose
3. Clone repository
4. Download latest backup from S3:
   ```bash
   aws s3 cp s3://backup-bucket/full/latest.tar.gz .
   ```
5. Extract and restore
6. Update DNS to point to new server

### Scenario 3: Data Center Outage

1. Failover to secondary data center
2. Promote read replica to primary
3. Update application config
4. Update DNS

### Regular Testing

- Monthly: Test database restore
- Quarterly: Full disaster recovery drill
- Annually: Data center failover test
```

### What You Learned

✅ Automated backup strategies
✅ Backup retention policies
✅ Point-in-time recovery
✅ Disaster recovery planning
✅ RTO and RPO concepts

---

## 6. CI/CD Pipeline

### Step 1: Create GitHub Actions Workflow

Create `.github/workflows/deploy.yml`:

```yaml
name: Build and Deploy

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'

      - name: Run tests
        run: go test -v ./...

      - name: Run linter
        uses: golangci/golangci-lint-action@v3
        with:
          version: latest

  build:
    needs: test
    runs-on: ubuntu-latest
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'

    steps:
      - uses: actions/checkout@v3

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v2

      - name: Login to Docker Hub
        uses: docker/login-action@v2
        with:
          username: ${{ secrets.DOCKER_USERNAME }}
          password: ${{ secrets.DOCKER_PASSWORD }}

      - name: Build and push
        uses: docker/build-push-action@v4
        with:
          context: .
          push: true
          tags: |
            yourusername/imageboard:latest
            yourusername/imageboard:${{ github.sha }}
          cache-from: type=registry,ref=yourusername/imageboard:latest
          cache-to: type=inline

  deploy:
    needs: build
    runs-on: ubuntu-latest
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'

    steps:
      - name: Deploy to production
        uses: appleboy/ssh-action@master
        with:
          host: ${{ secrets.PRODUCTION_HOST }}
          username: ${{ secrets.PRODUCTION_USER }}
          key: ${{ secrets.SSH_PRIVATE_KEY }}
          script: |
            cd /opt/imageboard
            docker-compose -f docker-compose.prod.yml pull
            docker-compose -f docker-compose.prod.yml up -d
            docker system prune -f
```

### Step 2: Add GitHub Secrets

In GitHub repository settings, add secrets:

- `DOCKER_USERNAME`: Docker Hub username
- `DOCKER_PASSWORD`: Docker Hub token
- `PRODUCTION_HOST`: Server IP address
- `PRODUCTION_USER`: SSH username
- `SSH_PRIVATE_KEY`: SSH private key for deployment

### Step 3: Add Tests

Create `main_test.go`:

```go
package main

import (
	"testing"
)

func TestSanitizeContent(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "Normal text",
			expected: "Normal text",
		},
		{
			input:    "<script>alert('XSS')</script>",
			expected: "", // Should be stripped
		},
		{
			input:    "Hello <b>world</b>",
			expected: "Hello world",
		},
	}

	for _, tt := range tests {
		result := SanitizeContent(tt.input)
		if result != tt.expected {
			t.Errorf("SanitizeContent(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestGenerateUserID(t *testing.T) {
	ip := "192.168.1.1"
	threadID := 123

	// Should generate consistent ID for same IP+thread
	id1 := GenerateUserID(ip, threadID)
	id2 := GenerateUserID(ip, threadID)

	if id1 != id2 {
		t.Errorf("GenerateUserID should be deterministic")
	}

	// Should generate different ID for different thread
	id3 := GenerateUserID(ip, 456)
	if id1 == id3 {
		t.Errorf("GenerateUserID should vary by thread")
	}

	// Should be 8 characters
	if len(id1) != 8 {
		t.Errorf("UserID length = %d, want 8", len(id1))
	}
}
```

### Step 4: Add Pre-commit Hooks

Create `.githooks/pre-commit`:

```bash
#!/bin/bash

echo "Running pre-commit checks..."

# Run tests
echo "Running tests..."
go test ./...
if [ $? -ne 0 ]; then
    echo "Tests failed. Commit aborted."
    exit 1
fi

# Run linter
echo "Running linter..."
golangci-lint run
if [ $? -ne 0 ]; then
    echo "Linter failed. Commit aborted."
    exit 1
fi

# Check formatting
echo "Checking formatting..."
unformatted=$(gofmt -l .)
if [ -n "$unformatted" ]; then
    echo "Code is not formatted. Run 'gofmt -w .' and commit again."
    echo "Unformatted files:"
    echo "$unformatted"
    exit 1
fi

echo "All checks passed!"
exit 0
```

**Install git hooks:**
```bash
chmod +x .githooks/pre-commit
git config core.hooksPath .githooks
```

### What You Learned

✅ Continuous Integration with GitHub Actions
✅ Automated testing in CI pipeline
✅ Docker image building and caching
✅ Automated deployment strategies
✅ Pre-commit hooks for code quality

---

## Summary

### Production Architecture

```
                    ┌─────────────┐
                    │  CloudFlare │  (CDN + DDoS)
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │    nginx    │  (SSL + Load Balancer)
                    └──────┬──────┘
                           │
            ┌──────────────┼──────────────┐
            │              │              │
       ┌────▼───┐     ┌───▼────┐    ┌───▼────┐
       │ App 1  │     │ App 2  │    │ App 3  │  (Horizontal scaling)
       └────┬───┘     └───┬────┘    └───┬────┘
            │             │              │
            └─────────────┼──────────────┘
                          │
         ┌────────────────┼────────────────┐
         │                │                │
    ┌────▼─────┐    ┌────▼─────┐    ┌────▼─────┐
    │PostgreSQL│    │  Redis   │    │  S3/R2   │
    │(Primary +│    │(Sentinel)│    │ (Images) │
    │ Replicas)│    │          │    │          │
    └──────────┘    └──────────┘    └──────────┘
         │                │                │
    ┌────▼─────┐    ┌────▼─────┐    ┌────▼─────┐
    │  Backups │    │  Backups │    │  Backups │
    └──────────┘    └──────────┘    └──────────┘
```

### Deployment Checklist

Before going to production:

- [ ] All environment variables configured
- [ ] SSL certificates obtained and installed
- [ ] Database backups automated and tested
- [ ] Monitoring and alerting configured
- [ ] Log aggregation set up
- [ ] Rate limiting enabled
- [ ] CSRF protection enabled
- [ ] XSS protection enabled
- [ ] Images migrated to S3/R2
- [ ] Database connection pooling configured
- [ ] Health checks working
- [ ] Load testing completed
- [ ] Disaster recovery plan documented
- [ ] CI/CD pipeline functional
- [ ] Security headers configured
- [ ] DNS configured correctly

### Performance Targets

- **Page load**: < 1 second (uncached)
- **API response**: < 100ms (cached), < 500ms (uncached)
- **Uptime**: 99.9% (8.7 hours downtime per year)
- **Database queries**: < 50ms average
- **Memory usage**: < 512MB per app instance

### Cost Estimate (1000 daily active users)

- **Server (2x medium instances)**: $40/month
- **PostgreSQL (managed)**: $50/month
- **Redis**: $10/month
- **S3/R2 (100GB images)**: $1.50/month
- **Monitoring (Grafana Cloud)**: $0 (free tier)
- **CDN (CloudFlare)**: $0 (free tier)
- **Backups (S3)**: $2/month

**Total: ~$104/month**

### Scaling Roadmap

**0-1K users**: Single server, current setup
**1K-10K users**: Add read replicas, CDN, Redis cluster
**10K-100K users**: Kubernetes, multi-region, dedicated cache layer
**100K+ users**: Microservices, event-driven architecture, global CDN

### Resources

- [The Twelve-Factor App](https://12factor.net/)
- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [PostgreSQL High Availability](https://www.postgresql.org/docs/current/high-availability.html)
- [Redis Sentinel Documentation](https://redis.io/docs/manual/sentinel/)
- [Prometheus Best Practices](https://prometheus.io/docs/practices/)
- [nginx Performance Tuning](https://www.nginx.com/blog/tuning-nginx/)

---

**Congratulations! You now have a production-ready imageboard application!**
