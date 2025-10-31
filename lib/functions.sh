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

# Write nginx upstream configuration file
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

