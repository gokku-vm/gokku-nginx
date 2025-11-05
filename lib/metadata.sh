#!/bin/bash

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
