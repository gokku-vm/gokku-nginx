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

# Write nginx upstream configuration file (upstream only)
# Usage: nginx_upstream_only UPSTREAM_FILE UPSTREAM_NAME
# Expects: PORTS array to be populated with ports
nginx_upstream_only() {
    local upstream_file="$1"
    local upstream_name="$2"
    
    # Create directory if it doesn't exist
    mkdir -p "$(dirname "$upstream_file")"
    
    # Generate upstream config with all running containers
    cat > "$upstream_file" << EOF
upstream $upstream_name {
$(for port in "${PORTS[@]}"; do
    echo "    server $upstream_name:$port;"
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
    
    # Generate server block header
    cat > "$server_file" << EOF
server {
    listen 80;
    server_name $domain;

EOF
    
    # Add each location - collect all first, then write
    local locations_json=$(echo "$METADATA" | jq -c ".domains[\"$domain\"].locations[]" 2>/dev/null)
    
    echo "$locations_json" | while IFS= read -r location_obj; do
        local path=$(echo "$location_obj" | jq -r '.path')
        local upstream=$(echo "$location_obj" | jq -r '.upstream')
        
        cat >> "$server_file" << EOF
    location $path {
        proxy_pass http://$upstream;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

EOF
    done
    
    # Close server block
    echo "}" >> "$server_file"
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

