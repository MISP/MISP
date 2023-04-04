#!/bin/bash

set -e

# Generate SSL certificate and key
SSL_KEY_FILE=/etc/nginx/certs/server.key
CERT_FILE=/etc/nginx/certs/server.crt

if [ ! -f "$SSL_KEY_FILE" ]; then
    echo "Generating self-signed certificate..."
    openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
        -subj "/C=US/ST=California/L=San Francisco/O=My Company/CN=localhost" \
        -keyout $SSL_KEY_FILE \
        -out $CERT_FILE
fi


# Start nginx
nginx -g "daemon off;"
