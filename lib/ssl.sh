#!/bin/bash

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