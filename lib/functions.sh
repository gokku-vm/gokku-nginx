#!/bin/bash

# Get running container ports by app name
# Usage: get_ports_by_name APP_NAME
# Returns: array of ports in global PORTS variable (declare -a PORTS)
get_ports_by_name() {
    local app_name="$1"
    PORTS=()
    
    # Get running containers for this app by name and extract ports
    local ports_temp=$(docker ps --filter "name=^${app_name}$" --filter "status=running" --format json 2>/dev/null | while IFS= read -r container_json; do
        if [ -n "$container_json" ]; then
            local state=$(echo "$container_json" | jq -r '.State' 2>/dev/null)
            local ports_field=$(echo "$container_json" | jq -r '.Ports' 2>/dev/null)
            
            if [ "$state" = "running" ] && [ -n "$ports_field" ] && [ "$ports_field" != "null" ] && [ "$ports_field" != "" ]; then
                # Parse ports from format "0.0.0.0:3001->3001/tcp" or "0.0.0.0:3001->3001/tcp, [::]:3001->3001/tcp"
                # Extract host port (before ->) - format: IP:PORT->CONTAINER_PORT/tcp
                echo "$ports_field" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+->[0-9]+/tcp' | sed 's/.*://' | sed 's/->.*//'
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
    cat > "$upstream_file" << EOF
upstream $upstream_name {
$(for port in "${PORTS[@]}"; do
    echo "    server $server_addr:$port;"
done)
}
EOF
}

# Get metadata file path
# Usage: get_metadata_file SERVICE_NAME
# Returns: path to metadata.json
get_metadata_file() {
    local service_name="$1"
    echo "/opt/gokku/services/$service_name/metadata.json"
}

# Load metadata
# Usage: load_metadata SERVICE_NAME
# Returns: JSON in METADATA variable
# Note: Creates metadata.json if it doesn't exist (for backward compatibility)
load_metadata() {
    local service_name="$1"
    local metadata_file=$(get_metadata_file "$service_name")
    
    if [ -f "$metadata_file" ]; then
        METADATA=$(cat "$metadata_file" 2>/dev/null || echo '{"domains":{},"upstreams":{}}')
    else
        # File doesn't exist - create it with empty structure for backward compatibility
        METADATA='{"domains":{},"upstreams":{}}'
        mkdir -p "$(dirname "$metadata_file")"
        echo "$METADATA" | jq . > "$metadata_file" 2>/dev/null || echo "$METADATA" > "$metadata_file"
    fi
}

# Save metadata
# Usage: save_metadata SERVICE_NAME
# Expects: METADATA variable to be set
save_metadata() {
    local service_name="$1"
    local metadata_file=$(get_metadata_file "$service_name")
    
    mkdir -p "$(dirname "$metadata_file")"
    echo "$METADATA" | jq . > "$metadata_file" 2>/dev/null || echo "$METADATA" > "$metadata_file"
}

# Add upstream to metadata
# Usage: metadata_add_upstream SERVICE_NAME UPSTREAM_NAME APP_NAME
metadata_add_upstream() {
    local service_name="$1"
    local upstream_name="$2"
    local app_name="$3"
    
    load_metadata "$service_name"
    METADATA=$(echo "$METADATA" | jq ".upstreams[\"$upstream_name\"] = {\"app\": \"$app_name\"}")
    save_metadata "$service_name"
}

# Remove upstream from metadata
# Usage: metadata_remove_upstream SERVICE_NAME UPSTREAM_NAME
metadata_remove_upstream() {
    local service_name="$1"
    local upstream_name="$2"
    
    load_metadata "$service_name"
    METADATA=$(echo "$METADATA" | jq "del(.upstreams[\"$upstream_name\"])")
    save_metadata "$service_name"
}

# Add location to domain metadata
# Usage: metadata_add_location SERVICE_NAME DOMAIN PATH UPSTREAM_NAME APP_NAME
metadata_add_location() {
    local service_name="$1"
    local domain="$2"
    local path="$3"
    local upstream_name="$4"
    local app_name="$5"
    
    load_metadata "$service_name"
    
    # Ensure domain exists
    if ! echo "$METADATA" | jq -e ".domains[\"$domain\"]" >/dev/null 2>&1; then
        METADATA=$(echo "$METADATA" | jq ".domains[\"$domain\"] = {\"locations\": []}")
    fi
    
    # Remove existing location with same path if exists
    METADATA=$(echo "$METADATA" | jq ".domains[\"$domain\"].locations = (.domains[\"$domain\"].locations | map(select(.path != \"$path\")))")
    
    # Add new location
    METADATA=$(echo "$METADATA" | jq ".domains[\"$domain\"].locations += [{\"path\": \"$path\", \"app\": \"$app_name\", \"upstream\": \"$upstream_name\"}]")
    
    # Sort locations by path length (longer/more specific first)
    METADATA=$(echo "$METADATA" | jq ".domains[\"$domain\"].locations = (.domains[\"$domain\"].locations | sort_by(-(.path | length)))")
    
    save_metadata "$service_name"
}

# Remove location from domain metadata
# Usage: metadata_remove_location SERVICE_NAME DOMAIN PATH
metadata_remove_location() {
    local service_name="$1"
    local domain="$2"
    local path="$3"
    
    load_metadata "$service_name"
    METADATA=$(echo "$METADATA" | jq ".domains[\"$domain\"].locations = (.domains[\"$domain\"].locations | map(select(.path != \"$path\")))")
    save_metadata "$service_name"
}

# Check if SSL certificates exist for a domain
# Usage: check_ssl_certificates SERVICE_NAME DOMAIN
# Returns: 0 if SSL exists, 1 if not
# Sets: SSL_CERT_FILE and SSL_KEY_FILE if found
check_ssl_certificates() {
    local service_name="$1"
    local domain="$2"
    local ssl_dir="/opt/gokku/services/$service_name/ssl"
    
    SSL_CERT_FILE=""
    SSL_KEY_FILE=""
    
    # Check for Let's Encrypt format (fullchain.pem, privkey.pem)
    if [ -f "$ssl_dir/${domain}/fullchain.pem" ] && [ -f "$ssl_dir/${domain}/privkey.pem" ]; then
        SSL_CERT_FILE="$ssl_dir/${domain}/fullchain.pem"
        SSL_KEY_FILE="$ssl_dir/${domain}/privkey.pem"
        return 0
    fi
    
    # Check for domain-specific files (domain.crt, domain.key)
    # These are symlinks created by Let's Encrypt plugin pointing to live/ directory:
    # ln -sf "$PLUGIN_DIR/live/$DOMAIN/fullchain.pem" "$NGINX_SSL_DIR/$DOMAIN.crt"
    # ln -sf "$PLUGIN_DIR/live/$DOMAIN/privkey.pem" "$NGINX_SSL_DIR/$DOMAIN.key"
    # The live/ directory contains symlinks to archive/ with current certificate versions
    # Verify that symlinks exist and can be resolved (check if target exists)
    if [ -L "$ssl_dir/${domain}.crt" ] && [ -L "$ssl_dir/${domain}.key" ]; then
        # Check if symlink targets are readable (will fail if target doesn't exist)
        if [ -r "$ssl_dir/${domain}.crt" ] && [ -r "$ssl_dir/${domain}.key" ]; then
            SSL_CERT_FILE="$ssl_dir/${domain}.crt"
            SSL_KEY_FILE="$ssl_dir/${domain}.key"
            return 0
        fi
    fi
    # Fallback: check if files exist (regular files or symlinks)
    if [ -f "$ssl_dir/${domain}.crt" ] && [ -f "$ssl_dir/${domain}.key" ]; then
        SSL_CERT_FILE="$ssl_dir/${domain}.crt"
        SSL_KEY_FILE="$ssl_dir/${domain}.key"
        return 0
    fi
    
    # Check for Let's Encrypt in ssl directory root (links from plugin)
    if [ -f "$ssl_dir/${domain}-fullchain.pem" ] && [ -f "$ssl_dir/${domain}-privkey.pem" ]; then
        SSL_CERT_FILE="$ssl_dir/${domain}-fullchain.pem"
        SSL_KEY_FILE="$ssl_dir/${domain}-privkey.pem"
        return 0
    fi
    
    # Check for any .crt and .key files matching domain pattern
    if [ -d "$ssl_dir" ]; then
        for cert_file in "$ssl_dir"/*.crt "$ssl_dir"/*.pem; do
            # Skip if glob didn't match any files
            [ ! -f "$cert_file" ] && continue
            
            local cert_basename=$(basename "$cert_file" .crt)
            cert_basename=$(basename "$cert_basename" .pem)
            
            # Try to match domain in filename
            if [[ "$cert_basename" == *"$domain"* ]] || [[ "$cert_basename" == "fullchain" ]] || [[ "$cert_basename" == "${domain}-fullchain" ]]; then
                local key_file=""
                if [[ "$cert_file" == *.crt ]]; then
                    key_file="${cert_file%.crt}.key"
                elif [[ "$cert_file" == *fullchain.pem ]]; then
                    key_file="${cert_file/fullchain.pem/privkey.pem}"
                fi
                
                if [ -f "$key_file" ]; then
                    SSL_CERT_FILE="$cert_file"
                    SSL_KEY_FILE="$key_file"
                    return 0
                fi
            fi
        done
    fi
    
    return 1
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
        # No locations, remove server block if exists
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
        # Host: /opt/gokku/services/nginx-lb/ssl/domain.crt
        # Container: /etc/nginx/ssl/domain.crt
        # Volume mounts:
        #   -v "$SERVICE_DIR/ssl:/etc/nginx/ssl:ro"
        #   -v "/opt/gokku/plugins/letsencrypt:/opt/gokku/plugins/letsencrypt:ro"
        # Plugin creates symlinks: $NGINX_SSL_DIR/$DOMAIN.crt -> $PLUGIN_DIR/live/$DOMAIN/fullchain.pem
        # The live/ directory contains symlinks to archive/ with current certificate versions
        local service_base_path="/opt/gokku/services/$service_name"
        local ssl_cert_container_path="${ssl_cert_file#$service_base_path/}"
        local ssl_key_container_path="${ssl_key_file#$service_base_path/}"
        
        # SSL enabled - create HTTP redirect + HTTPS block
        cat > "$server_file" << EOF
# HTTP redirect to HTTPS
server {
    listen 80;
    server_name $domain;
    
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}

# HTTPS server block
server {
    listen 443 ssl;
    http2 on;
    server_name $domain;
    
    ssl_certificate /etc/nginx/$ssl_cert_container_path;
    ssl_certificate_key /etc/nginx/$ssl_key_container_path;
    
    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

EOF
        
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
    }
    }
EOF
}

# Ensure nginx container is running and up to date
# Usage: ensure_nginx_running SERVICE_NAME
ensure_nginx_running() {
    local service_name="$1"
    
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

