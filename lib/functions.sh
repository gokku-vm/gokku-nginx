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
        METADATA=$(cat "$metadata_file" 2>/dev/null || echo '{"domains":{},"upstreams":{},"deny_ips":[]}')
        # Ensure deny_ips field exists (backward compatibility)
        if ! echo "$METADATA" | jq -e ".deny_ips" >/dev/null 2>&1; then
            METADATA=$(echo "$METADATA" | jq '. + {"deny_ips": []}')
        fi
    else
        # File doesn't exist - create it with empty structure for backward compatibility
        METADATA='{"domains":{},"upstreams":{},"deny_ips":[]}'
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
    local letsencrypt_live="/opt/gokku/plugins/letsencrypt/live/${domain}"
    
    SSL_CERT_FILE=""
    SSL_KEY_FILE=""
    
    # First, check directly in Let's Encrypt live directory (most reliable)
    if [ -f "${letsencrypt_live}/fullchain.pem" ] && [ -f "${letsencrypt_live}/privkey.pem" ]; then
        # Verify symlinks can be resolved (they point to archive/)
        if [ -r "${letsencrypt_live}/fullchain.pem" ] && [ -r "${letsencrypt_live}/privkey.pem" ]; then
            SSL_CERT_FILE="${letsencrypt_live}/fullchain.pem"
            SSL_KEY_FILE="${letsencrypt_live}/privkey.pem"
            return 0
        fi
    fi
    
    # Check for symlinks in ssl directory (created by plugin)
    # Plugin creates: $NGINX_SSL_DIR/$DOMAIN.crt -> $PLUGIN_DIR/live/$DOMAIN/fullchain.pem
    if [ -L "$ssl_dir/${domain}.crt" ] && [ -L "$ssl_dir/${domain}.key" ]; then
        # Verify symlink targets are readable (will fail if target doesn't exist)
        if [ -r "$ssl_dir/${domain}.crt" ] && [ -r "$ssl_dir/${domain}.key" ]; then
            SSL_CERT_FILE="$ssl_dir/${domain}.crt"
            SSL_KEY_FILE="$ssl_dir/${domain}.key"
            return 0
        fi
    fi
    
    # Fallback: check if .crt/.key files exist (regular files or symlinks)
    if [ -f "$ssl_dir/${domain}.crt" ] && [ -f "$ssl_dir/${domain}.key" ]; then
        SSL_CERT_FILE="$ssl_dir/${domain}.crt"
        SSL_KEY_FILE="$ssl_dir/${domain}.key"
        return 0
    fi
    
    # Check for Let's Encrypt format in subdirectory (fullchain.pem, privkey.pem)
    if [ -f "$ssl_dir/${domain}/fullchain.pem" ] && [ -f "$ssl_dir/${domain}/privkey.pem" ]; then
        SSL_CERT_FILE="$ssl_dir/${domain}/fullchain.pem"
        SSL_KEY_FILE="$ssl_dir/${domain}/privkey.pem"
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
        proxy_connect_timeout 0;
        proxy_send_timeout 0;
        proxy_read_timeout 0;
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

# Add deny IP to metadata
# Usage: metadata_add_deny_ip SERVICE_NAME IP
metadata_add_deny_ip() {
    local service_name="$1"
    local ip="$2"
    
    load_metadata "$service_name"
    
    # Check if IP already exists
    if echo "$METADATA" | jq -e ".deny_ips[] | select(. == \"$ip\")" >/dev/null 2>&1; then
        echo "-----> IP '$ip' is already in deny list"
        return 0
    fi
    
    # Add IP to deny list
    METADATA=$(echo "$METADATA" | jq ".deny_ips += [\"$ip\"]")
    save_metadata "$service_name"
}

# Remove deny IP from metadata
# Usage: metadata_remove_deny_ip SERVICE_NAME IP
# If IP is empty, removes all deny IPs
metadata_remove_deny_ip() {
    local service_name="$1"
    local ip="$2"
    
    load_metadata "$service_name"
    
    if [ -z "$ip" ]; then
        # Remove all deny IPs
        METADATA=$(echo "$METADATA" | jq ".deny_ips = []")
        save_metadata "$service_name"
        return 0
    fi
    
    # Check if IP exists
    if ! echo "$METADATA" | jq -e ".deny_ips[] | select(. == \"$ip\")" >/dev/null 2>&1; then
        echo "-----> IP '$ip' is not in deny list"
        return 0
    fi
    
    # Remove IP from deny list
    METADATA=$(echo "$METADATA" | jq ".deny_ips = (.deny_ips | map(select(. != \"$ip\")))")
    save_metadata "$service_name"
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
    
    # Generate default server block that blocks access via IP
    # This block catches requests that don't match any server_name
    # Note: HTTPS access via IP is automatically blocked since nginx requires
    # matching server_name with valid SSL certificate
    cat > "$default_server_file" << 'EOF'
# Default server block - blocks access via IP
# This catches all HTTP requests that don't match any server_name
# HTTPS requests without matching server_name are automatically rejected by nginx
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    
    # Return 444 (connection closed without response) for all requests
    return 444;
}
EOF
}

