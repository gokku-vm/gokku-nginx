#!/bin/bash

source /opt/gokku/plugins/nginx/lib/ssl.sh
source /opt/gokku/plugins/nginx/lib/metadata.sh

# Get running container ports by app name
# Usage: get_ports_by_name APP_NAME
# Returns: array of ports in global PORTS variable (declare -a PORTS)
get_ports_by_name() {
    local app_name="$1"
    PORTS=()
    
    # Try multiple patterns to find containers
    # Pattern 1: Exact match (app-name)
    # Pattern 2: Starts with app-name (app-name-web-1, app-name-worker-1, etc)
    local ports_temp=$(docker ps --filter "status=running" --format json 2>/dev/null | while IFS= read -r container_json; do
        if [ -n "$container_json" ]; then
            local container_name=$(echo "$container_json" | jq -r '.Names' 2>/dev/null)
            local state=$(echo "$container_json" | jq -r '.State' 2>/dev/null)
            local ports_field=$(echo "$container_json" | jq -r '.Ports' 2>/dev/null)
            
            # Check if container name matches app name (exact or starts with)
            if [ "$state" = "running" ] && [[ "$container_name" =~ ^${app_name}(-|$) ]]; then
                if [ -n "$ports_field" ] && [ "$ports_field" != "null" ] && [ "$ports_field" != "" ]; then
                    # Parse ports from format "0.0.0.0:3001->3001/tcp" or "0.0.0.0:3001->3001/tcp, [::]:3001->3001/tcp"
                    # Extract host port (before ->) - format: IP:PORT->CONTAINER_PORT/tcp
                    echo "$ports_field" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+->[0-9]+/tcp' | sed 's/.*://' | sed 's/->.*//'
                fi
            fi
        fi
    done | sort -u)
    
    # Populate PORTS array
    if [ -n "$ports_temp" ]; then
        while IFS= read -r port; do
            if [ -n "$port" ] && [[ "$port" =~ ^[0-9]+$ ]]; then
                PORTS+=("$port")
            fi
        done <<< "$ports_temp"
    fi
}

# Check if nginx container is in host network mode
# Usage: is_host_network SERVICE_NAME
# Returns: 0 if host network, 1 if bridge network
is_host_network() {
    local service_name="$1"
    networkMode=$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$service_name" 2>/dev/null)
    if [ "$networkMode" = "host" ]; then
        return 0
    fi
    return 1
}

# Write nginx upstream configuration file (upstream only)
# Usage: nginx_upstream_only UPSTREAM_FILE UPSTREAM_NAME [SERVICE_NAME]
# Expects: PORTS array to be populated with ports
# If SERVICE_NAME is provided and nginx is in host network, uses 127.0.0.1:PORT
nginx_upstream_only() {
    local upstream_file="$1"
    local upstream_name="$2"
    local service_name="$3"
    
    # Create directory if it doesn't exist
    mkdir -p "$(dirname "$upstream_file")"
    
    # Determine server address based on network mode
    local server_addr
    if [ -n "$service_name" ] && is_host_network "$service_name"; then
        # Host network mode: use localhost with host port
        server_addr="127.0.0.1"
    else
        # Bridge network mode: use container name (will be resolved at runtime)
        server_addr="$upstream_name"
    fi
    
    # Generate upstream config with all running containers
    if [ ${#PORTS[@]} -eq 0 ]; then
        # No ports available - create upstream with backup or fail
        cat > "$upstream_file" << EOF
upstream $upstream_name {
    # No servers available - upstream will return 502/504
    server 127.0.0.1:65535 down;
}
EOF
    else
        cat > "$upstream_file" << EOF
upstream $upstream_name {
$(for port in "${PORTS[@]}"; do
    echo "    server $server_addr:$port;"
done)
}
EOF
    fi
}

# Generate locations block
# Usage: generate_locations_block OUTPUT_FILE LOCATIONS_JSON
generate_locations_block() {
    local output_file="$1"
    local locations_json="$2"
    
    echo "$locations_json" | while IFS= read -r location_obj; do
        local path=$(echo "$location_obj" | jq -r '.path')
        local upstream=$(echo "$location_obj" | jq -r '.upstream')
        
        cat >> "$output_file" << EOF
    location $path {
        proxy_pass http://$upstream;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 60s;
        proxy_send_timeout 0;
        proxy_read_timeout 0;
        proxy_buffering off;
    }

EOF
    done
}

# Generate server block from metadata
# Usage: nginx_generate_server_block SERVICE_NAME DOMAIN
nginx_generate_server_block() {
    local service_name="$1"
    local domain="$2"
    local server_file="/opt/gokku/services/$service_name/conf.d/servers/${domain}.conf"
    
    load_metadata "$service_name"
    
    # Get locations count for this domain
    local locations_count=$(echo "$METADATA" | jq ".domains[\"$domain\"].locations | length" 2>/dev/null)
    
    if [ -z "$locations_count" ] || [ "$locations_count" = "null" ] || [ "$locations_count" = "0" ]; then
        # No locations configured - remove server block
        # Default server block will handle and block requests
        rm -f "$server_file"
        return
    fi
    
    # Create directory if it doesn't exist
    mkdir -p "$(dirname "$server_file")"
    
    # Check if SSL certificates exist
    local has_ssl=0
    local ssl_cert_file=""
    local ssl_key_file=""
    
    if check_ssl_certificates "$service_name" "$domain"; then
        has_ssl=1
        ssl_cert_file="$SSL_CERT_FILE"
        ssl_key_file="$SSL_KEY_FILE"
    fi
    
    # Get locations JSON
    local locations_json=$(echo "$METADATA" | jq -c ".domains[\"$domain\"].locations[]" 2>/dev/null)
    
    # Generate server block(s)
    if [ "$has_ssl" -eq 1 ]; then
        # Convert absolute host paths to container paths
        # Volume mounts:
        #   -v "$SERVICE_DIR/ssl:/etc/nginx/ssl:ro"
        #   -v "/opt/gokku/plugins/letsencrypt:/opt/gokku/plugins/letsencrypt:ro"
        # Plugin creates symlinks: $NGINX_SSL_DIR/$DOMAIN.crt -> $PLUGIN_DIR/live/$DOMAIN/fullchain.pem
        # The live/ directory contains symlinks to archive/ with current certificate versions
        local ssl_cert_container_path=""
        local ssl_key_container_path=""
        
        # Check if files are from Let's Encrypt plugin directory
        if [[ "$ssl_cert_file" == /opt/gokku/plugins/letsencrypt/* ]]; then
            # Files from plugin directory: use same path in container (volume mount preserves path)
            ssl_cert_container_path="$ssl_cert_file"
            ssl_key_container_path="$ssl_key_file"
        elif [[ "$ssl_cert_file" == /opt/gokku/services/* ]]; then
            # Files from service directory: convert to /etc/nginx/... (volume mount maps service dir)
            local service_base_path="/opt/gokku/services/$service_name"
            local cert_rel_path="${ssl_cert_file#$service_base_path/}"
            local key_rel_path="${ssl_key_file#$service_base_path/}"
            ssl_cert_container_path="/etc/nginx/$cert_rel_path"
            ssl_key_container_path="/etc/nginx/$key_rel_path"
        else
            # Fallback: use file path as-is
            ssl_cert_container_path="$ssl_cert_file"
            ssl_key_container_path="$ssl_key_file"
        fi
        
        # SSL enabled - HTTPS only (port 80 left free for Let's Encrypt HTTP-01 challenge)
        # Modern browsers will upgrade to HTTPS automatically via HSTS
        cat > "$server_file" << EOF
# HTTPS server block
server {
    listen 443 ssl;
    http2 on;
    server_name $domain;
    
    ssl_certificate $ssl_cert_container_path;
    ssl_certificate_key $ssl_key_container_path;
    
    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 30m;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

EOF
        # Add deny/allow rules if there are deny IPs
        generate_deny_rules "$server_file"
        
        # Add locations to HTTPS block
        generate_locations_block "$server_file" "$locations_json"
        
        # Close HTTPS server block
        echo "}" >> "$server_file"
    else
        # No SSL - create HTTP-only block
        cat > "$server_file" << EOF
server {
    listen 80;
    server_name $domain;

EOF
        # Add deny/allow rules if there are deny IPs
        generate_deny_rules "$server_file"
        
        # Add locations
        generate_locations_block "$server_file" "$locations_json"
        
        # Close server block
        echo "}" >> "$server_file"
    fi
}

# Write nginx upstream configuration file (legacy - for backward compatibility)
# Usage: nginx_upstream_config CONFIG_FILE UPSTREAM_NAME DOMAIN
# Expects: PORTS array to be populated with ports
nginx_upstream_config() {
    local config_file="$1"
    local upstream_name="$2"
    local domain="$3"
    
    # Create conf.d directory if it doesn't exist
    mkdir -p "$(dirname "$config_file")"
    
    # Generate upstream config with all running containers
    cat > "$config_file" << EOF
upstream $upstream_name {
$(for port in "${PORTS[@]}"; do
    echo "    server $upstream_name:$port;"
done)
}

server {
    listen 80;
    server_name $domain;

    location / {
        proxy_pass http://$upstream_name;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 0;
        proxy_send_timeout 0;
        proxy_read_timeout 0;
    }
}
EOF
}

# Update nginx.conf with required settings if missing
# Usage: update_nginx_conf_if_needed SERVICE_NAME
update_nginx_conf_if_needed() {
    local service_name="$1"
    local nginx_conf="/opt/gokku/services/$service_name/nginx.conf"
    
    if [ ! -f "$nginx_conf" ]; then
        echo "-----> Warning: nginx.conf not found at $nginx_conf"
        return 1
    fi
    
    # Check if server_names_hash_bucket_size is already configured
    if grep -q "server_names_hash_bucket_size" "$nginx_conf" 2>/dev/null; then
        return 0
    fi
    
    # Add server_names_hash settings after types_hash_max_size
    if ! grep -q "types_hash_max_size" "$nginx_conf" 2>/dev/null; then
        echo "-----> Warning: types_hash_max_size not found in nginx.conf"
        echo "-----> Cannot auto-update nginx.conf, please add server_names_hash_bucket_size 128; manually"
        return 1
    fi
    
    echo "-----> Updating nginx.conf to support long domain names"
    
    # Use sed to add the lines after types_hash_max_size
    # Try sed first (Linux)
    if sed -i.bak '/types_hash_max_size/a\
    server_names_hash_bucket_size 128;\
    server_names_hash_max_size 4096;
' "$nginx_conf" 2>/dev/null; then
        rm -f "${nginx_conf}.bak" 2>/dev/null || true
        echo "-----> nginx.conf updated successfully (using sed)"
    else
        # Fallback if sed -i doesn't work (macOS or when sed fails)
        echo "-----> Using fallback method to update nginx.conf"
        local temp_file=$(mktemp)
        local found=0
        while IFS= read -r line || [ -n "$line" ]; do
            echo "$line" >> "$temp_file"
            if [[ "$line" =~ types_hash_max_size ]]; then
                echo "    server_names_hash_bucket_size 128;" >> "$temp_file"
                echo "    server_names_hash_max_size 4096;" >> "$temp_file"
                found=1
            fi
        done < "$nginx_conf"
        
        if [ "$found" -eq 1 ]; then
            mv "$temp_file" "$nginx_conf"
            echo "-----> nginx.conf updated successfully (using fallback)"
        else
            rm -f "$temp_file"
            echo "-----> Error: Could not find types_hash_max_size in nginx.conf"
            return 1
        fi
    fi
    
    # Verify the update worked
    if ! grep -q "server_names_hash_bucket_size" "$nginx_conf" 2>/dev/null; then
        echo "-----> Error: Failed to update nginx.conf - verification failed"
        return 1
    fi
    
    echo "-----> Verification: nginx.conf now contains server_names_hash_bucket_size"
    return 0
}

# Ensure nginx container is running and up to date
# Usage: ensure_nginx_running SERVICE_NAME
ensure_nginx_running() {
    local service_name="$1"
    
    # Update nginx.conf if needed (for long domain names)
    update_nginx_conf_if_needed "$service_name"
    
    if ! container_exists "$service_name"; then
        echo "-----> Container $service_name does not exist"
        return 1
    fi
    
    if ! container_is_running "$service_name"; then
        echo "-----> Starting nginx container: $service_name"
        docker start "$service_name"
        
        echo "-----> Waiting for nginx to start..."
        wait_for_container "$service_name" 30
        
        if ! container_is_running "$service_name"; then
            echo "-----> Failed to start nginx container"
            return 1
        fi
    fi
    
    return 0
}

# Validate IP address or CIDR notation
# Usage: validate_ip_or_cidr IP
# Returns: 0 if valid, 1 if invalid
validate_ip_or_cidr() {
    local ip="$1"
    
    # Check if it's a valid IP address (IPv4)
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        # Validate each octet
        IFS='.' read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if [ "$octet" -gt 255 ]; then
                return 1
            fi
        done
        return 0
    fi
    
    # Check if it's a valid CIDR notation
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        # Extract IP and prefix
        local ip_part="${ip%/*}"
        local prefix="${ip#*/}"
        
        # Validate IP part
        if ! validate_ip_or_cidr "$ip_part"; then
            return 1
        fi
        
        # Validate prefix (0-32)
        if [ "$prefix" -gt 32 ]; then
            return 1
        fi
        
        return 0
    fi
    
    return 1
}

# Generate deny/allow rules for server block
# Usage: generate_deny_rules OUTPUT_FILE
# Expects: METADATA variable to be set with deny_ips array
generate_deny_rules() {
    local output_file="$1"
    
    # Get deny IPs from metadata
    local deny_ips=$(echo "$METADATA" | jq -r ".deny_ips[]?" 2>/dev/null)
    
    if [ -n "$deny_ips" ]; then
        # Add deny rules
        while IFS= read -r ip; do
            if [ -n "$ip" ]; then
                echo "    deny $ip;" >> "$output_file"
            fi
        done <<< "$deny_ips"
        
        # Add allow all after deny rules
        echo "    allow all;" >> "$output_file"
    fi
}

# Regenerate all server blocks
# Usage: regenerate_all_server_blocks SERVICE_NAME
regenerate_all_server_blocks() {
    local service_name="$1"
    
    load_metadata "$service_name"
    
    # Get all domains
    local domains=$(echo "$METADATA" | jq -r ".domains | keys[]" 2>/dev/null)
    
    if [ -n "$domains" ]; then
        while IFS= read -r domain; do
            if [ -n "$domain" ]; then
                nginx_generate_server_block "$service_name" "$domain"
            fi
        done <<< "$domains"
    fi
}


# Generate default server block that blocks IP access
# Usage: regenerate_default_server_block SERVICE_NAME
regenerate_default_server_block() {
    local service_name="$1"
    local default_server_file="/opt/gokku/services/$service_name/conf.d/servers/default.conf"
    
    load_metadata "$service_name"
    
    # Check if there are any domains configured
    local domains_count=$(echo "$METADATA" | jq ".domains | length" 2>/dev/null)
    
    if [ -z "$domains_count" ] || [ "$domains_count" = "null" ] || [ "$domains_count" = "0" ]; then
        # No domains configured, remove default server block
        rm -f "$default_server_file"
        return
    fi
    
    # Create directory if it doesn't exist
    mkdir -p "$(dirname "$default_server_file")"
    
    # Check if any domain has SSL configured
    local has_ssl_domain=0
    local domains=$(echo "$METADATA" | jq -r ".domains | keys[]" 2>/dev/null)
    if [ -n "$domains" ]; then
        while IFS= read -r domain; do
            if [ -n "$domain" ]; then
                if check_ssl_certificates "$service_name" "$domain"; then
                    has_ssl_domain=1
                    break
                fi
            fi
        done < <(echo "$domains")
    fi
    
    # Generate default server block that blocks access via IP
    if [ "$has_ssl_domain" -eq 1 ]; then
        # Block HTTPS via IP using ssl_reject_handshake (nginx 1.19.1+)
        # This rejects SSL handshake without needing a certificate
        cat > "$default_server_file" << 'EOF'
# Default server block - blocks access via IP
# This catches all HTTP and HTTPS requests that don't match any server_name
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    
    # Return 444 (connection closed without response) for all requests
    return 444;
}

server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;
    
    # Reject SSL handshake without certificate (nginx 1.19.1+)
    ssl_reject_handshake on;
}
EOF
    else
        # No SSL domains, only block HTTP
        cat > "$default_server_file" << 'EOF'
# Default server block - blocks access via IP
# This catches all HTTP requests that don't match any server_name
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    
    # Return 444 (connection closed without response) for all requests
    return 444;
}
EOF
    fi
}

