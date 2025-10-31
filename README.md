# Gokku Nginx Plugin

A Gokku plugin that provides nginx as a service for load balancing, reverse proxy, and static file serving.

## Features

- **Load Balancing**: Distribute traffic across multiple backend services
- **Reverse Proxy**: Route requests to different applications
- **Path-based Routing**: Route different paths to different apps on the same domain
- **Microservices Support**: Configure multiple services with different paths
- **SSL Termination**: Handle SSL certificates and HTTPS
- **Static File Serving**: Serve static assets efficiently
- **Health Checks**: Monitor backend service health
- **Configuration Management**: Easy nginx configuration updates

## Installation

```bash
gokku plugins:add gokku-nginx
```

or 

```bash
gokku plugins:add nginx https://github.com/gokku-vm/gokku-nginx.git
```

## Usage

### Create Nginx Service

```bash
# Create a new nginx service
gokku services:create nginx --name nginx-lb

# Link to an application
gokku services:link nginx-lb -a api
```

### Domain Management

```bash
# Add domain for an app
gokku nginx:add-domain nginx-lb api api.example.com

# List all configured domains
gokku nginx:list-domains nginx-lb

# Get domain for specific app
gokku nginx:get-domain nginx-lb api

# Remove domain for an app
gokku nginx:remove-domain nginx-lb api
```

### Upstream Management

```bash
# Add upstream for an app
gokku nginx:add-upstream nginx-lb api

# Scale app processes
gokku nginx:scale nginx-lb api web 4

# Remove upstream for an app
gokku nginx:remove-upstream nginx-lb api
```

### Location Management

Manage multiple routes/paths on the same domain:

```bash
# Add a location (path) to a domain pointing to an app
gokku nginx:add-location nginx-lb api.example.com /users user-service
gokku nginx:add-location nginx-lb api.example.com /orders order-service

# List all locations for a domain
gokku nginx:list-locations nginx-lb api.example.com

# Remove a location
gokku nginx:remove-location nginx-lb api.example.com /users
```

**Use Cases:**
- **Microservices**: Different paths route to different services
- **API Versioning**: Version your API with different paths (e.g., `/v1`, `/v2`)
- **Service Separation**: Separate admin, public, and internal routes

### Service Management

```bash
# Show service information
gokku nginx:info nginx-lb

# View service logs
gokku nginx:logs nginx-lb

# Reload nginx configuration
gokku nginx:reload nginx-lb

# Check nginx status
gokku nginx:status nginx-lb

# Test nginx configuration
gokku nginx:test nginx-lb

# Show nginx configuration
gokku nginx:config nginx-lb
```

## Configuration

The nginx service creates a configuration directory at `/opt/gokku/services/<service-name>/` with:

- `nginx.conf` - Main nginx configuration
- `conf.d/upstreams/` - Upstream configurations (one per app)
- `conf.d/servers/` - Server block configurations (one per domain)
- `conf.d/` - Legacy configurations (backward compatibility)
- `metadata.json` - Metadata for tracking upstreams and locations
- `ssl/` - SSL certificates directory

### Example Configuration

The plugin now uses a separated architecture:

```nginx
# /opt/gokku/services/nginx-lb/conf.d/upstreams/api.conf
upstream api {
    server api:8080;
    server api:8081;
}

# /opt/gokku/services/nginx-lb/conf.d/servers/api.example.com.conf
server {
    listen 80;
    server_name api.example.com;
    
    location / {
        proxy_pass http://api;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Environment Variables

Set nginx-specific environment variables:

```bash
# Set nginx worker processes
gokku config set NGINX_WORKER_PROCESSES=auto -a nginx-lb

# Set worker connections
gokku config set NGINX_WORKER_CONNECTIONS=1024 -a nginx-lb

# Set keepalive timeout
gokku config set NGINX_KEEPALIVE_TIMEOUT=65 -a nginx-lb
```

## SSL Configuration

To enable SSL, place your certificates in the service directory:

```bash
# Copy SSL certificates
cp server.crt /opt/gokku/services/nginx-lb/ssl/
cp server.key /opt/gokku/services/nginx-lb/ssl/

# Reload nginx to apply SSL configuration
gokku nginx:reload nginx-lb
```

## Load Balancing Methods

Configure different load balancing methods in your upstream blocks:

```nginx
# Round Robin (default)
upstream backend {
    server app1:8080;
    server app2:8080;
}

# Least Connections
upstream backend {
    least_conn;
    server app1:8080;
    server app2:8080;
}

# IP Hash
upstream backend {
    ip_hash;
    server app1:8080;
    server app2:8080;
}
```

## Health Checks

Configure health checks for your backends:

```nginx
upstream backend {
    server app1:8080 max_fails=3 fail_timeout=30s;
    server app2:8080 max_fails=3 fail_timeout=30s;
}
```

## Logging

Access logs are available through the plugin:

```bash
# View access logs
gokku nginx:logs nginx-lb

# View error logs
docker exec nginx-lb tail -f /var/log/nginx/error.log
```

## Troubleshooting

### Check Configuration

```bash
# Test nginx configuration
gokku nginx:test nginx-lb

# Show current configuration
gokku nginx:config nginx-lb
```

### Common Issues

1. **Port conflicts**: The plugin automatically assigns available ports
2. **Configuration errors**: Use `nginx:test` to validate configuration
3. **Backend connectivity**: Check if backend services are running
4. **SSL issues**: Verify certificate paths and permissions

## Complete Example

### Basic Setup

Here's a complete example of setting up nginx as a load balancer:

```bash
# 1. Install the plugin
gokku plugins:add thadeu/gokku-nginx

# 2. Create nginx service
gokku services:create nginx --name nginx-lb

# 3. Add domains for apps
gokku nginx:add-domain nginx-lb api api.example.com
gokku nginx:add-domain nginx-lb web www.example.com

# 4. Add upstreams for apps
gokku nginx:add-upstream nginx-lb api
gokku nginx:add-upstream nginx-lb web

# 5. Scale apps
gokku scale api web=4
gokku scale web web=2

# 6. Check configuration
gokku nginx:info nginx-lb
gokku nginx:list-domains nginx-lb

# 7. Test configuration
gokku nginx:test nginx-lb
```

This will create:
- `api.example.com` → 4 containers on ports 8080-8083
- `www.example.com` → 2 containers on ports 8080-8081

### Advanced Setup with Multiple Paths

Example of a microservices architecture:

```bash
# 1. Setup main API domain
gokku nginx:add-domain nginx-lb api api.example.com
gokku nginx:add-upstream nginx-lb api

# 2. Setup microservices
gokku nginx:add-upstream nginx-lb user-service
gokku nginx:add-upstream nginx-lb order-service
gokku nginx:add-upstream nginx-lb payment-service

# 3. Add routes for microservices
gokku nginx:add-location nginx-lb api.example.com /users user-service
gokku nginx:add-location nginx-lb api.example.com /orders order-service
gokku nginx:add-location nginx-lb api.example.com /payments payment-service

# 4. List all routes
gokku nginx:list-locations nginx-lb api.example.com

# 5. Test configuration
gokku nginx:test nginx-lb
```

This routes:
- `api.example.com/` → `api` app (main API)
- `api.example.com/users/` → `user-service` app
- `api.example.com/orders/` → `order-service` app
- `api.example.com/payments/` → `payment-service` app

## Examples

### Simple Reverse Proxy

```bash
# Setup basic reverse proxy
gokku nginx:add-domain nginx-lb myapp myapp.example.com
gokku nginx:add-upstream nginx-lb myapp
```

This creates:
```nginx
upstream myapp {
    server myapp:8080;
    server myapp:8081;
}

server {
    listen 80;
    server_name myapp.example.com;
    
    location / {
        proxy_pass http://myapp;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Microservices Architecture

Route different paths to different services:

```bash
# Setup main API domain
gokku nginx:add-domain nginx-lb api api.example.com
gokku nginx:add-upstream nginx-lb api

# Add microservices routes
gokku nginx:add-location nginx-lb api.example.com /users user-service
gokku nginx:add-location nginx-lb api.example.com /orders order-service
gokku nginx:add-location nginx-lb api.example.com /payments payment-service
```

This creates:
```nginx
upstream api {
    server api:8080;
}

upstream user-service {
    server user-service:8080;
}

upstream order-service {
    server order-service:8080;
}

upstream payment-service {
    server payment-service:8080;
}

server {
    listen 80;
    server_name api.example.com;
    
    location / {
        proxy_pass http://api;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    location /users/ {
        proxy_pass http://user-service;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    location /orders/ {
        proxy_pass http://order-service;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    location /payments/ {
        proxy_pass http://payment-service;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### API Versioning

Route different API versions to different apps:

```bash
# Setup versioned API
gokku nginx:add-domain nginx-lb api api.example.com

# Add API versions
gokku nginx:add-location nginx-lb api.example.com /v1 api-v1
gokku nginx:add-location nginx-lb api.example.com /v2 api-v2
gokku nginx:add-location nginx-lb api.example.com /admin admin-app
```

This routes:
- `api.example.com/v1/` → `api-v1` app
- `api.example.com/v2/` → `api-v2` app
- `api.example.com/admin/` → `admin-app` app

### Load Balancer with Health Checks

```nginx
upstream myapp {
    server myapp-1:8080 max_fails=3 fail_timeout=30s;
    server myapp-2:8080 max_fails=3 fail_timeout=30s;
}

server {
    listen 80;
    server_name myapp.example.com;
    
    location / {
        proxy_pass http://myapp;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Static File Serving

```nginx
server {
    listen 80;
    server_name static.example.com;
    root /var/www/static;
    
    location / {
        try_files $uri $uri/ =404;
    }
}
```

## License

MIT License - see LICENSE file for details.
