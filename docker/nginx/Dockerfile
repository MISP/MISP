FROM nginx:1.23

# Copy nginx.conf to container
COPY docker/nginx/nginx.conf /etc/nginx/nginx.conf

# Set entrypoint script and make it executable
COPY docker/nginx/entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh

# Copy application code
COPY . /var/www/html/

# Set working directory
WORKDIR /var/www/html

# Expose ports
EXPOSE 80
EXPOSE 443

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
