# Base image with necessary extensions and configurations
FROM php:8.2-fpm AS base
ARG MISP_TAG_OR_BRANCH


USER root

# Install additional PHP extensions
RUN apt-get -y update \
    && apt-get install -y libicu-dev libpq-dev \
    && docker-php-ext-configure intl \
    && docker-php-ext-configure pgsql -with-pgsql=/usr/local/pgsql \
    && docker-php-ext-install intl pdo pdo_mysql mysqli

# Copy custom php-fpm config file
COPY docker/misp/config/php-fpm.conf /usr/local/etc/php-fpm.conf

# Set working directory
WORKDIR /var/www/html

# Install Composer
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

# Set permissions for log file
RUN touch /var/run/php-fpm.pid /var/log/php-fpm.error.log /var/log/php-fpm.slow.log \
    && chown www-data:www-data /var/run/php-fpm.pid /var/log/php-fpm.error.log /var/log/php-fpm.slow.log

# Create tmp directory
RUN mkdir /var/www/html/tmp\
    && chown -R www-data:www-data /var/www/html/tmp

# Copy entrypoint script and make it executable
COPY docker/misp/entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 9000

# Development image with additional packages and dependencies
FROM base AS dev
USER root

# Change user and group id to match host user
ARG UID=1000
ARG GID=1000
RUN groupmod --gid $GID www-data
RUN usermod --uid $UID --gid $GID www-data

# Copy application code
COPY . /var/www/html/

# Install development dependencies
RUN pecl install -f xdebug \
    && docker-php-ext-enable xdebug

# Install additional packages
RUN apt-get update \
    && apt-get install -y \
    git

# Write Xdebug configuration
RUN echo "xdebug.mode=debug" >> /usr/local/etc/php/conf.d/docker-php-ext-xdebug.ini \
    && echo "xdebug.start_with_request=debug" >> /usr/local/etc/php/conf.d/docker-php-ext-xdebug.ini \
    && echo "xdebug.client_host=host.docker.internal" >> /usr/local/etc/php/conf.d/docker-php-ext-xdebug.ini \
    && echo "xdebug.client_port=9003" >> /usr/local/etc/php/conf.d/docker-php-ext-xdebug.ini \
    && echo "xdebug.discover_client_host=1" >> /usr/local/etc/php/conf.d/docker-php-ext-xdebug.ini

# Copy dev php.ini file
COPY docker/misp/config/php.dev.ini /usr/local/etc/php/php.ini

RUN chown -R www-data:www-data /var/www/html

# Install dependencies
USER www-data
RUN composer install --dev --no-cache

USER root
CMD ["php-fpm", "-F"]

# Production image with only necessary packages and dependencies
FROM base AS prod
USER root

# Install additional packages
RUN apt-get update \
    && apt-get install -y \
    git

# Clone MISP repository
RUN git clone --branch ${MISP_TAG_OR_BRANCH} --depth 1 https://github.com/MISP/MISP.git /var/www/html
WORKDIR /var/www/html
RUN git submodule update --init --recursive .;

USER www-data

# Copy prod php.ini file
COPY docker/misp/config/php.ini /usr/local/etc/php/php.ini

# Install only production dependencies
RUN composer install --no-dev --optimize-autoloader --no-cache --no-interaction --no-progress --no-suggest --no-scripts

CMD ["php-fpm", "-F"]
