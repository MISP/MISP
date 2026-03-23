#!/bin/bash
# MISP 2.5 installation for Ubuntu 24.04 LTS

# This guide is meant to be a simply installation of MISP on a pristine Ubuntu 24.04 LTS server.
# Keep in mind that whilst this installs the software along with all of its dependencies, it's up to you to properly secure it.

# This guide liberally borrows from three sources:
# - The previous iterations of the official MISP installation guide, which can be found at: https://misp.github.io/MISP
# - The automisp install guide by @da667, which can be found at: https://github.com/da667/AutoMISP/blob/master/auto-MISP-ubuntu.sh
# - MISP-docker by @ostefano, which can be found at: https://github.com/MISP/MISP-docker
# Thanks to both Tony Robinson (@da667), Stefano Ortolani (@ostefano) and Steve Clement (@SteveClement) for their awesome work!

# This installation script assumes that you are installing as root, or a user with sudo access.

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    exec sudo -E bash "$0" "$@"
fi

random_string() {
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1
}

# Configure the following variables in advance for your environment
## required settings - please change all of these, failing to do so will result in a non-working installation or a highly insecure installation
: "${PASSWORD:=$(random_string)}"
: "${MISP_DOMAIN:=misp.local}"
: "${MISP_BASEURL:=https://${MISP_DOMAIN}}"
: "${PATH_TO_SSL_CERT:=}"
: "${PATH_TO_SSL_KEY:=}"
: "${INSTALL_SSDEEP:=n}" # y/n, if you want to install ssdeep, set to 'y', however, this will require the installation of make

## optional settings
: "${MISP_PATH:=/var/www/MISP}"
: "${APACHE_USER:=www-data}"

### DB settings, if you want to use a different DB host, name, user, or password, please change these
: "${DBHOST:=localhost}"
: "${DBUSER_ADMIN:=root}"
: "${DBPASSWORD_ADMIN:=}" # Default on Ubuntu is a passwordless root account, if you have changed it, please set it here
: "${DBNAME:=misp}"
: "${DBPORT:=3306}"
: "${DBUSER_MISP:=misp}"
: "${DBPASSWORD_MISP:=$(random_string)}"

### Supervisor settings
: "${SUPERVISOR_USER:=supervisor}"
: "${SUPERVISOR_PASSWORD:=$(random_string)}"

### PHP settings
: "${upload_max_filesize:=50M}"
: "${post_max_size:=50M}"
: "${max_execution_time:=300}"
: "${max_input_time:=300}"
: "${memory_limit:=2048M}"

## GPG
: "${GPG_EMAIL_ADDRESS:=admin@admin.test}"
: "${GPG_PASSPHRASE:=$(random_string)}"

### Only needed if no SSL CERT is provided
: "${OPENSSL_C:=LU}"
: "${OPENSSL_ST:=Luxembourg}"
: "${OPENSSL_L:=Luxembourg}"
: "${OPENSSL_O:=MISP}"
: "${OPENSSL_OU:=MISP}"
: "${OPENSSL_CN:=${MISP_DOMAIN}}"
: "${OPENSSL_EMAILADDRESS:=misp@${MISP_DOMAIN}}"

# Some helper functions shamelessly copied from @da667's automisp install script.

logfile=/var/log/misp_install.log
mkfifo ${logfile}.pipe
tee <${logfile}.pipe $logfile &
exec &>${logfile}.pipe
rm ${logfile}.pipe

function install_packages() {
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" &>>$logfile
    error_check "$* installation"
}

function error_check {

    if [ $? -eq 0 ]; then
        print_ok "$1 successfully completed."
    else
        print_error "$1 failed. Please check $logfile for more details."
        exit 1
    fi
}

function error_check_soft {
    if [ $? -eq 0 ]; then
        print_ok "$1 successfully completed."
    else
        print_error "$1 failed. Please check $logfile for more details. This is not a blocking failure though, proceeding..."
    fi
}

function print_status() {
    echo -e "\x1B[01;34m[STATUS]\x1B[0m $1"
}

function print_ok() {
    echo -e "\x1B[01;32m[OK]\x1B[0m $1"
}

function print_error() {
    echo -e "\x1B[01;31m[ERROR]\x1B[0m $1"
}

function print_notification() {
    echo -e "\x1B[01;33m[NOTICE]\x1B[0m $1"
}

function os_version_check() {
    # Check if we're on Ubuntu 24.04 as expected:
    UBUNTU_VERSION=$(sh -c '. /etc/os-release && echo $VERSION_ID')
    if [[ "$UBUNTU_VERSION" != "24.04" ]]; then
        print_error "This upgrade tool expects you to be running Ubuntu 24.04. If you are on a prior upgrade of Ubuntu, please make sure that you upgrade your distribution first, then execute this script again."
        exit 1
    fi
}

function set_misp_setting() {
    if [ "$#" -ne 2 ]; then
        print_error "Misp setting require a value and parameter"
        exit 1
    fi
    sudo -u "${APACHE_USER}" "${MISP_PATH}/app/Console/cake" Admin setSetting "$1" "$2" &>>$logfile
}

BLUE="\033[1;34m"
NC="\033[0m"
echo -e "${BLUE}███╗   ███╗${NC}██╗███████╗██████╗ "
echo -e "${BLUE}████╗ ████║${NC}██║██╔════╝██╔══██╗"
echo -e "${BLUE}██╔████╔██║${NC}██║███████╗██████╔╝"
echo -e "${BLUE}██║╚██╔╝██║${NC}██║╚════██║██╔═══╝ "
echo -e "${BLUE}██║ ╚═╝ ██║${NC}██║███████║██║     "
echo -e "${BLUE}╚═╝     ╚═╝${NC}╚═╝╚══════╝╚═╝     "
echo -e "v2.5 Setup on Ubuntu 24.04 LTS"

os_version_check

save_settings() {
    settings_file=/root/misp_settings.txt

    cat >"${settings_file}" <<SETTINGS_EOF
[$(date)] MISP installation

[MISP admin user]
- Admin Username: admin@admin.test
- Admin Password: ${PASSWORD}
- Admin API key: ${MISP_USER_KEY}

[MYSQL ADMIN]
- Username: ${DBUSER_ADMIN}
- Password: ${DBPASSWORD_ADMIN}

[MYSQL MISP]
- Username: ${DBUSER_MISP}
- Password: ${DBPASSWORD_MISP}

[MISP internal]
- Path: ${MISP_PATH}
- Apache user: ${APACHE_USER}
- GPG Email: ${GPG_EMAIL_ADDRESS}
- GPG Passphrase: ${GPG_PASSPHRASE}
- SUPERVISOR_USER: ${SUPERVISOR_USER}
- SUPERVISOR_PASSWORD: ${SUPERVISOR_PASSWORD}
SETTINGS_EOF

    chmod 600 "${settings_file}"
    print_notification "Sensitive settings saved to ${settings_file} (mode 600, root only)"
}

print_status "Updating base system..."
apt-get update &>>$logfile
apt-get upgrade -y &>>$logfile
error_check "Base system update"

print_status "Installing apt packages (git curl python3 python3-pip python3-virtualenv apache2 zip gcc sudo binutils openssl supervisor)..."
declare -a packages=(git curl python3 python3-pip python3-virtualenv apache2 zip gcc sudo binutils openssl supervisor)
install_packages "${packages[@]}"
error_check "Basic dependencies installation"

print_status "Installing MariaDB..."
declare -a packages=(mariadb-server mariadb-client)
install_packages "${packages[@]}"
error_check "MariaDB installation"

print_status "Installing PHP and the list of required extensions..."
declare -a packages=(redis-server php8.3 php8.3-cli php8.3-dev php8.3-xml php8.3-mysql php8.3-opcache php8.3-readline php8.3-mbstring php8.3-zip
    php8.3-intl php8.3-bcmath php8.3-gd php8.3-redis php8.3-gnupg php8.3-apcu libapache2-mod-php8.3 php8.3-curl)
install_packages "${packages[@]}"
PHP_ETC_BASE=/etc/php/8.3
PHP_INI=${PHP_ETC_BASE}/apache2/php.ini
error_check "PHP and required extensions installation."

# Install composer and the composer dependencies of MISP

print_status "Installing composer..."

## make pip and composer happy
mkdir -p /var/www/.cache/
chown -R "${APACHE_USER}:${APACHE_USER}" /var/www/.cache/

curl -sS https://getcomposer.org/installer -o /tmp/composer-setup.php &>>$logfile
COMPOSER_HASH=$(curl -sS https://composer.github.io/installer.sig)
php -r "if (hash_file('SHA384', '/tmp/composer-setup.php') === '${COMPOSER_HASH}') { exit(0); } unlink('/tmp/composer-setup.php'); exit(1);" &>>$logfile
error_check "Composer installer verification"
php /tmp/composer-setup.php --install-dir=/usr/local/bin --filename=composer &>>$logfile
error_check "Composer installation"

print_status "Configuring php and MySQL configs..."
for key in upload_max_filesize post_max_size max_execution_time max_input_time memory_limit; do
    sed -i "s/^\($key\).*/\1 = $(eval echo \$\{$key\})/" $PHP_INI
done
sed -i "s/^\(session.sid_length\).*/\1 = 32/" $PHP_INI
sed -i "s/^\(session.use_strict_mode\).*/\1 = 1/" $PHP_INI
sed -i "s/^\(session.save_handler\).*/\1 = redis/" $PHP_INI
if grep -q "^session.save_path =" "$PHP_INI"; then
    sed -i "s|^session.save_path =.*|session.save_path = 'tcp://localhost:6379'|" "$PHP_INI"
else
    sed -i "/session.save_handler/a session.save_path = 'tcp:\/\/localhost:6379'" "$PHP_INI"
fi

MYCNF="/etc/mysql/mariadb.conf.d/z-misp.cnf"
# We go for an innodb buffer pool size of 50% of the available memory

# Check for cgroup memory limits, don't rely on /proc/meminfo in an LXC container with unbound memory limits
# Thanks to Sascha Rommelfangen (@rommelfs) for the hint
CGROUPMEMORYHIGHPATH="/sys/fs/cgroup/memory.high"
if [ -f "$CGROUPMEMORYHIGHPATH" ]; then
    CGROUPMEMORYHIGH="$(cat "$CGROUPMEMORYHIGHPATH")"
    if [ "$CGROUPMEMORYHIGH" = "max" ]; then
        INNODBBUFFERPOOLSIZE='2048M'
    else
        INNODBBUFFERPOOLSIZE="$((CGROUPMEMORYHIGH / 1024 / 1024 / 2))M"
    fi
else
    INNODBBUFFERPOOLSIZE="$(grep MemTotal /proc/meminfo | awk '{print int($2 / 2048)}')M"
fi

cat <<MARIADB_EOF | tee "$MYCNF" >/dev/null
[mariadb]
innodb_buffer_pool_size = ${INNODBBUFFERPOOLSIZE}
innodb_io_capacity = 1000
innodb_read_io_threads = 16
MARIADB_EOF

service apache2 restart
error_check "Apache restart"
systemctl restart mariadb
error_check "MariaDB restart"

print_ok "PHP and MySQL configured..."

print_status "Installing PECL extensions..."

pecl channel-update pecl.php.net &>>$logfile || echo "Continuing despite error in updating PECL channel"
pecl install brotli &>>$logfile
error_check_soft "PECL brotli extension installation" || echo "Continuing despite error in installing PECL brotli extension"
pecl install simdjson &>>$logfile
error_check_soft "PECL simdjson extension installation" || echo "Continuing despite error in installing PECL simdjson extension"
pecl install zstd &>>$logfile
error_check_soft "PECL zstd extension installation" || echo "Continuing despite error in installing PECL zstd extension"

if [ "$INSTALL_SSDEEP" == "y" ]; then
    apt install make -y &>>$logfile
    error_check "The installation of make" || echo "Continuing despite error in installing make"

    # Install libfuzzy-dev and link the .so to somewhere ./configure can pick it up
    apt install -y libfuzzy-dev
    ln -sf /usr/lib/x86_64-linux-gnu/libfuzzy.so /usr/lib/libfuzzy.so
    git clone --recursive --depth=1 https://github.com/JakubOnderka/pecl-text-ssdeep.git /tmp/pecl-text-ssdeep
    error_check "Jakub Onderka's PHP8 SSDEEP extension cloning" || echo "Continuing despite error in cloning SSDEEP extension"

    cd /tmp/pecl-text-ssdeep && phpize && ./configure && make && make install
    error_check "Jakub Onderka's PHP8 SSDEEP extension compilation and installation" || echo "Continuing despite error in SSDEEP compilation and installation"
fi

print_status "Cloning MISP"
if [ -d "$MISP_PATH" ]; then
    if [ -d "$MISP_PATH/.git" ]; then
        # We have already a repository, ensure it is up to date, this doesn't check it's a MISP one, this allow to have custom git repository installed by the user
        pushd "$MISP_PATH" &>>$logfile && git pull &>>$logfile || exit 1
        error_check "MISP updating"
        popd &>>$logfile || exit 1
    else
        print_error "Directory exists, aborting, please use an non existing repository"
        exit 1
    fi
else
    git clone -b 2.5 https://github.com/MISP/MISP.git "${MISP_PATH}" &>>$logfile
    error_check "MISP cloning"
fi

cd "${MISP_PATH}" || exit 1
git fetch origin 2.5 &>>$logfile
error_check "Fetching 2.5 branch"
git checkout 2.5 &>>$logfile
error_check "Checking out 2.5 branch"

print_status "Cloning MISP submodules..."
if ! git config --global --get-all safe.directory 2>/dev/null | grep -Fxq "${MISP_PATH}"; then
    git config --global --add safe.directory "${MISP_PATH}" &>>$logfile
fi
git -C "${MISP_PATH}" submodule update --init --recursive &>>$logfile
error_check "MISP submodules cloning"
git -C "${MISP_PATH}" submodule foreach --recursive git config core.filemode false &>>$logfile
chown -R "${APACHE_USER}:${APACHE_USER}" "${MISP_PATH}" &>>$logfile
chown -R "${APACHE_USER}:${APACHE_USER}" "${MISP_PATH}/.git" &>>$logfile
print_ok "MISP's submodules cloned."

print_status "Installing MISP composer dependencies..."
cd "${MISP_PATH}/app" || exit 1
sudo -u "${APACHE_USER}" composer install --no-dev --no-interaction --prefer-dist &>>$logfile
error_check "MISP composer dependencies installation"

print_status "Create DB and user for MISP as well as importing the basic MISP schema..."
declare -a DBUSER_ADMIN_STRING
if [ "$DBUSER_ADMIN" != 'root' ]; then
    DBUSER_ADMIN_STRING=("-u" "${DBUSER_ADMIN}")
fi

DBPASSWORD_ADMIN_STRING=''
if [ ! -z "${DBPASSWORD_ADMIN}" ]; then
    DBPASSWORD_ADMIN_STRING='-p'"${DBPASSWORD_ADMIN}"
fi

DBUSER_MISP_STRING=()
if [ ! -z "${DBUSER_MISP}" ]; then
    DBUSER_MISP_STRING=('-u' "${DBUSER_MISP}")
fi

DBPASSWORD_MISP_STRING=''
if [ -f "Config/database.php" ]; then
    pushd Config &>>$logfile || exit 1
    print_status "Using existing misp password for database"
    DBPASSWORD_MISP=$(php -r 'include "database.php"; $a = new DATABASE_CONFIG(); echo $a->default["password"];')
    error_check "Existing user pasword"
    popd &>>$logfile || exit 1
fi
if [ ! -z "${DBPASSWORD_MISP}" ]; then
    DBPASSWORD_MISP_STRING='-p'"${DBPASSWORD_MISP}"
fi

DBHOST_STRING=()
if [ ! -z "$DBHOST" ] && [ "$DBHOST" != "localhost" ]; then
    DBHOST_STRING=("-h" "${DBHOST}")
fi

DBPORT_STRING=()
if [ "$DBPORT" != 3306 ]; then
    DBPORT_STRING=("--port" "${DBPORT}")
fi
DBCONN_ADMIN_STRING=("${DBPORT_STRING[@]}" "${DBHOST_STRING[@]}" "${DBUSER_ADMIN_STRING[@]}" "${DBPASSWORD_ADMIN_STRING}")

DBCONN_MISP_STRING=("${DBPORT_STRING[@]}" "${DBHOST_STRING[@]}" "${DBUSER_MISP_STRING[@]}" "${DBPASSWORD_MISP_STRING}")

mysql "${DBCONN_ADMIN_STRING[@]}" -e "CREATE DATABASE IF NOT EXISTS ${DBNAME};" &>>$logfile
mysql "${DBCONN_ADMIN_STRING[@]}" -e "CREATE USER IF NOT EXISTS '${DBUSER_MISP}'@'localhost' IDENTIFIED BY '${DBPASSWORD_MISP}';" &>>$logfile
mysql "${DBCONN_ADMIN_STRING[@]}" -e "GRANT USAGE ON *.* to '${DBUSER_MISP}'@'localhost';" &>>$logfile
mysql "${DBCONN_ADMIN_STRING[@]}" -e "GRANT ALL PRIVILEGES on ${DBNAME}.* to '${DBUSER_MISP}'@'localhost';" &>>$logfile
mysql "${DBCONN_ADMIN_STRING[@]}" -e "FLUSH PRIVILEGES;" &>>$logfile

if [ "$(mysql -Nse "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = '$DBNAME';")" -eq 0 ]; then
    mysql "${DBCONN_MISP_STRING[@]}" "$DBNAME" <"${MISP_PATH}/INSTALL/MYSQL.sql" &>>$logfile
    error_check "MISP database schema import"
fi

# get the current gpg passphrase if already set before the config files are overriden
if gpg_existing_pass=$(sudo -u "${APACHE_USER}" "${MISP_PATH}/app/Console/cake" Admin getSetting "GnuPG.password" 2>/dev/null | grep value | cut -d'"' -f 4) && [ -n "$gpg_existing_pass" ]; then
    print_notification "Reusing existing PGP passphrase"
    GPG_PASSPHRASE="$gpg_existing_pass"
fi
print_status "Moving and configuring MISP php config files.."

cd "${MISP_PATH}/app/Config" || exit 1
cp -a bootstrap.default.php bootstrap.php
cp -a database.default.php database.php
cp -a core.default.php core.php
cp -a config.default.php config.php
sed -i "s#3306#${DBPORT}#" database.php
sed -i "s#'host' => 'localhost'#'host' => '$DBHOST'#" database.php
sed -i "s#db login#$DBUSER_MISP#" database.php
sed -i "s#db password#$DBPASSWORD_MISP#" database.php
sed -i "s#'database' => 'misp'#'database' => '$DBNAME'#" database.php
sed -i "s#Rooraenietu8Eeyo<Qu2eeNfterd-dd+#$(random_string)#" config.php

print_ok "MISP php config files moved and configured."

# Generate ssl certificate
SSL_CERT_PATH='/etc/ssl/private/misp.local.crt'
SSL_KEY_PATH='/etc/ssl/private/misp.local.key'

if [ -n "${PATH_TO_SSL_CERT}" ] && [ -n "${PATH_TO_SSL_KEY}" ]; then
    SSL_CERT_PATH="${PATH_TO_SSL_CERT}"
    SSL_KEY_PATH="${PATH_TO_SSL_KEY}"
    print_status "Using provided SSL certificate."
    [ -r "${SSL_CERT_PATH}" ] || {
        print_error "SSL certificate not readable: ${SSL_CERT_PATH}"
        exit 1
    }
    [ -r "${SSL_KEY_PATH}" ] || {
        print_error "SSL key not readable: ${SSL_KEY_PATH}"
        exit 1
    }
else
    print_notification "Generating self-signed SSL certificate."
    openssl req -newkey rsa:4096 -days 365 -nodes -x509 \
        -subj "/C=${OPENSSL_C}/ST=${OPENSSL_ST}/L=${OPENSSL_L}/O=${OPENSSL_O}/OU=${OPENSSL_OU}/CN=${OPENSSL_CN}/emailAddress=${OPENSSL_EMAILADDRESS}" \
        -keyout "${SSL_KEY_PATH}" -out "${SSL_CERT_PATH}" &>>$logfile
    error_check "Self-signed SSL certificate generation"
fi

# Generate misp-ssl.conf
print_status "Creating Apache configuration file for MISP..."

echo "<VirtualHost _default_:80>
          ServerAdmin admin@$MISP_DOMAIN
          ServerName $MISP_DOMAIN

          Redirect permanent / https://$MISP_DOMAIN

          LogLevel warn
          ErrorLog /var/log/apache2/misp.local_error.log
          CustomLog /var/log/apache2/misp.local_access.log combined
          ServerSignature Off
  </VirtualHost>

  <VirtualHost _default_:443>
          ServerAdmin admin@$MISP_DOMAIN
          ServerName $MISP_DOMAIN
          DocumentRoot $MISP_PATH/app/webroot

          <Directory $MISP_PATH/app/webroot>
                  Options -Indexes
                  AllowOverride all
  		            Require all granted
                  Order allow,deny
                  allow from all
          </Directory>

          SSLEngine On
          SSLCertificateFile ${SSL_CERT_PATH}
          SSLCertificateKeyFile ${SSL_KEY_PATH}

          LogLevel warn
          ErrorLog /var/log/apache2/misp.local_error.log
          CustomLog /var/log/apache2/misp.local_access.log combined
          ServerSignature Off
          Header set X-Content-Type-Options nosniff
          Header set X-Frame-Options DENY
          SSLCipherSuite HIGH:!aNULL:!SHA1:!MD5:!DHE:!DH:!ADH
  </VirtualHost>" | tee /etc/apache2/sites-available/misp-ssl.conf &>>$logfile

error_check "Apache configuration file creation" &>>$logfile

# ensure redis is running before import
systemctl enable --now redis-server.service &>>$logfile
error_check "Ensure redis is running"

print_status "Running MISP updates"

sudo -u "${APACHE_USER}" "${MISP_PATH}/app/Console/cake Admin" setSetting "MISP.osuser" "${APACHE_USER}" &>>$logfile
sudo -u "${APACHE_USER}" "${MISP_PATH}/app/Console/cake Admin" runUpdates &>>$logfile
MISP_USER_KEY_FILE="$(mktemp)"
sudo -u "${APACHE_USER}" "${MISP_PATH}/app/Console/cake" User init >"${MISP_USER_KEY_FILE}"
MISP_USER_KEY="$(tr -d '\n' <"${MISP_USER_KEY_FILE}")"
rm -f "${MISP_USER_KEY_FILE}"
sudo -u "${APACHE_USER}" "${MISP_PATH}/app/Console/cake" User change_pw 'admin@admin.test' "${PASSWORD}" &>>$logfile

print_ok "MISP updated."

print_status "Generating PGP key"
# The email address should match the one set in the config.php
# set in the configuration menu in the administration menu configuration file

if ! sudo -u "${APACHE_USER}" gpg --homedir "$MISP_PATH/.gnupg" --list-key "${GPG_EMAIL_ADDRESS}" &>/dev/null; then
    sudo -u "${APACHE_USER}" gpg --homedir "$MISP_PATH/.gnupg" --quick-generate-key --batch --passphrase "$GPG_PASSPHRASE" "${GPG_EMAIL_ADDRESS}" ed25519 sign never &>>$logfile
fi
error_check "PGP key generation"
GPG_TTY=$(tty)
export GPG_TTY
echo misp | sudo --preserve-env=GPG_TTY -u "${APACHE_USER}" gpg --homedir "$MISP_PATH/.gnupg" -o /dev/null --batch --passphrase "$GPG_PASSPHRASE" --local-user "${GPG_EMAIL_ADDRESS}" --pinentry-mode loopback -as -
error_check "PGP key passphrase"

# Export the public key to the webroot
sudo -u "${APACHE_USER}" gpg --homedir "$MISP_PATH/.gnupg" --export --armor "${GPG_EMAIL_ADDRESS}" | sudo -u "${APACHE_USER}" tee "$MISP_PATH/app/webroot/gpg.asc" &>>$logfile
error_check "PGP key export"

print_status "Setting up Python environment for MISP"

# Create a python3 virtualenv
sudo -u "${APACHE_USER}" virtualenv -p python3 "${MISP_PATH}/venv" &>>$logfile
error_check "Python virtualenv creation"

cd "${MISP_PATH}" || exit 1
. ./venv/bin/activate &>>$logfile
error_check "Python virtualenv activation"

# install python dependencies
"${MISP_PATH}/venv/bin/pip" install -r "${MISP_PATH}/requirements.txt" &>>$logfile
error_check "Python dependencies installation"

chown -R "${APACHE_USER}:${APACHE_USER}" "${MISP_PATH}/venv"

print_status "Setting up background workers"

if ! grep -q '^\[inet_http_server\]' /etc/supervisor/supervisord.conf; then
    tee -a /etc/supervisor/supervisord.conf >/dev/null <<SUPERVISOR_EOF

[inet_http_server]
port=127.0.0.1:9001
username=$SUPERVISOR_USER
password=$SUPERVISOR_PASSWORD
SUPERVISOR_EOF
fi

echo "[group:misp-workers]
programs=default,email,cache,prio,update,scheduler

[program:default]
directory=$MISP_PATH
command=$MISP_PATH/app/Console/cake start_worker default
process_name=%(program_name)s_%(process_num)02d
numprocs=5
autostart=true
autorestart=true
redirect_stderr=false
stderr_logfile=$MISP_PATH/app/tmp/logs/misp-workers-errors.log
stdout_logfile=$MISP_PATH/app/tmp/logs/misp-workers.log
directory=$MISP_PATH
user=$APACHE_USER

[program:prio]
directory=$MISP_PATH
command=$MISP_PATH/app/Console/cake start_worker prio
process_name=%(program_name)s_%(process_num)02d
numprocs=5
autostart=true
autorestart=true
redirect_stderr=false
stderr_logfile=$MISP_PATH/app/tmp/logs/misp-workers-errors.log
stdout_logfile=$MISP_PATH/app/tmp/logs/misp-workers.log
directory=$MISP_PATH
user=$APACHE_USER

[program:email]
directory=$MISP_PATH
command=$MISP_PATH/app/Console/cake start_worker email
process_name=%(program_name)s_%(process_num)02d
numprocs=5
autostart=true
autorestart=true
redirect_stderr=false
stderr_logfile=$MISP_PATH/app/tmp/logs/misp-workers-errors.log
stdout_logfile=$MISP_PATH/app/tmp/logs/misp-workers.log
directory=$MISP_PATH
user=$APACHE_USER

[program:update]
directory=$MISP_PATH
command=$MISP_PATH/app/Console/cake start_worker update
process_name=%(program_name)s_%(process_num)02d
numprocs=1
autostart=true
autorestart=true
redirect_stderr=false
stderr_logfile=$MISP_PATH/app/tmp/logs/misp-workers-errors.log
stdout_logfile=$MISP_PATH/app/tmp/logs/misp-workers.log
directory=$MISP_PATH
user=$APACHE_USER

[program:cache]
directory=$MISP_PATH
command=$MISP_PATH/app/Console/cake start_worker cache
process_name=%(program_name)s_%(process_num)02d
numprocs=5
autostart=true
autorestart=true
redirect_stderr=false
stderr_logfile=$MISP_PATH/app/tmp/logs/misp-workers-errors.log
stdout_logfile=$MISP_PATH/app/tmp/logs/misp-workers.log
user=$APACHE_USER

[program:scheduler]
directory=$MISP_PATH
command=$MISP_PATH/app/Console/cake scheduler_worker
process_name=%(program_name)s_%(process_num)02d
numprocs=1
autostart=true
autorestart=true
redirect_stderr=false
stderr_logfile=$MISP_PATH/app/tmp/logs/misp-workers-errors.log
stdout_logfile=$MISP_PATH/app/tmp/logs/misp-workers.log
user=$APACHE_USER" | sudo tee /etc/supervisor/conf.d/misp-workers.conf &>>$logfile

# Set settings
# The default install is Python >=3.6 in a virtualenv, setting accordingly
set_misp_setting "MISP.python_bin" "${MISP_PATH}/venv/bin/python"

# Tune global time outs
set_misp_setting "Session.autoRegenerate" 0
set_misp_setting "Session.timeout" 600
set_misp_setting "Session.cookieTimeout" 3600

# Set the default temp dir
set_misp_setting "MISP.tmpdir" "${MISP_PATH}/app/tmp"

# Change base url, either with this CLI command or in the UI
[[ -n ${MISP_DOMAIN} ]] && set_misp_setting "MISP.baseurl" "${MISP_BASEURL}"
[[ -n ${MISP_DOMAIN} ]] && set_misp_setting "MISP.external_baseurl" "${MISP_BASEURL}"

# Enable GnuPG
set_misp_setting "GnuPG.email" "${GPG_EMAIL_ADDRESS}"
set_misp_setting "GnuPG.homedir" "${MISP_PATH}/.gnupg"
set_misp_setting "GnuPG.password" "${GPG_PASSPHRASE}"
set_misp_setting "GnuPG.obscure_subject" true
set_misp_setting "GnuPG.key_fetching_disabled" false
# FIXME: what if we have not gpg binary but a gpg2 one?
set_misp_setting "GnuPG.binary" "$(which gpg)"

# Enable installer org and tune some configurables
set_misp_setting "MISP.host_org_id" 1
set_misp_setting "MISP.email" "${GPG_EMAIL_ADDRESS}"
set_misp_setting "MISP.disable_emailing" false
set_misp_setting "MISP.contact" "${GPG_EMAIL_ADDRESS}"
set_misp_setting "MISP.disablerestalert" true
set_misp_setting "MISP.showCorrelationsOnIndex" true
set_misp_setting "MISP.default_event_tag_collection" 0
set_misp_setting "MISP.log_new_audit" 1

# Configure background workers
set_misp_setting "SimpleBackgroundJobs.enabled" 1
set_misp_setting "SimpleBackgroundJobs.redis_host" '127.0.0.1'
set_misp_setting "SimpleBackgroundJobs.redis_port" 6379
set_misp_setting "SimpleBackgroundJobs.redis_database" 13
set_misp_setting "SimpleBackgroundJobs.redis_password" ""
set_misp_setting "SimpleBackgroundJobs.redis_namespace" "background_jobs"
set_misp_setting "SimpleBackgroundJobs.supervisor_host" "localhost"
set_misp_setting "SimpleBackgroundJobs.supervisor_port" 9001
set_misp_setting "SimpleBackgroundJobs.supervisor_user" "${SUPERVISOR_USER}"
set_misp_setting "SimpleBackgroundJobs.supervisor_password" "${SUPERVISOR_PASSWORD}"
set_misp_setting "SimpleBackgroundJobs.redis_serializer" "JSON"

# Various plugin sightings settings
set_misp_setting "Plugin.Sightings_policy" 0
set_misp_setting "Plugin.Sightings_anonymise" false
set_misp_setting "Plugin.Sightings_anonymise_as" 1
set_misp_setting "Plugin.Sightings_range" 365
set_misp_setting "Plugin.Sightings_sighting_db_enable" false

# ZeroMQ settings
set_misp_setting "Plugin.ZeroMQ_enable" false
set_misp_setting "Plugin.ZeroMQ_host" "127.0.0.1"
set_misp_setting "Plugin.ZeroMQ_port" 50000
set_misp_setting "Plugin.ZeroMQ_redis_host" "localhost"
set_misp_setting "Plugin.ZeroMQ_redis_port" 6379
set_misp_setting "Plugin.ZeroMQ_redis_database" 1
set_misp_setting "Plugin.ZeroMQ_redis_namespace" "mispq"
set_misp_setting "Plugin.ZeroMQ_event_notifications_enable" false
set_misp_setting "Plugin.ZeroMQ_object_notifications_enable" false
set_misp_setting "Plugin.ZeroMQ_object_reference_notifications_enable" false
set_misp_setting "Plugin.ZeroMQ_attribute_notifications_enable" false
set_misp_setting "Plugin.ZeroMQ_sighting_notifications_enable" false
set_misp_setting "Plugin.ZeroMQ_user_notifications_enable" false
set_misp_setting "Plugin.ZeroMQ_organisation_notifications_enable" false
set_misp_setting "Plugin.ZeroMQ_include_attachments" false
set_misp_setting "Plugin.ZeroMQ_tag_notifications_enable" false

# Force defaults to make MISP Server Settings less RED
set_misp_setting "MISP.language" "eng"
set_misp_setting "MISP.proposals_block_attributes" false

# Redis block
set_misp_setting "MISP.redis_host" "127.0.0.1"
set_misp_setting "MISP.redis_port" 6379
set_misp_setting "MISP.redis_database" 13
set_misp_setting "MISP.redis_password" ""
set_misp_setting "MISP.redis_serializer" "JSON"

# Force defaults to make MISP Server Settings less YELLOW
set_misp_setting "MISP.ssdeep_correlation_threshold" 40
set_misp_setting "MISP.extended_alert_subject" false
set_misp_setting "MISP.default_event_threat_level" 4
set_misp_setting "MISP.newUserText" "Dear new MISP user,\\n\\nWe would hereby like to welcome you to the \$org MISP community.\\n\\n Use the credentials below to log into MISP at \$misp, where you will be prompted to manually change your password to something of your own choice.\\n\\nUsername: \$username\\nPassword: \$password\\n\\nIf you have any questions, don't hesitate to contact us at: \$contact.\\n\\nBest regards,\\nYour \$org MISP support team"
set_misp_setting "MISP.passwordResetText" "Dear MISP user,\\n\\nA password reset has been triggered for your account. Use the below provided temporary password to log into MISP at \$misp, where you will be prompted to manually change your password to something of your own choice.\\n\\nUsername: \$username\\nYour temporary password: \$password\\n\\nIf you have any questions, don't hesitate to contact us at: \$contact.\\n\\nBest regards,\\nYour \$org MISP support team"
set_misp_setting "MISP.enableEventBlocklisting" true
set_misp_setting "MISP.enableOrgBlocklisting" true
set_misp_setting "MISP.log_client_ip" true
set_misp_setting "MISP.log_auth" false
set_misp_setting "MISP.log_user_ips" true
set_misp_setting "MISP.log_user_ips_authkeys" true
set_misp_setting "MISP.disableUserSelfManagement" false
set_misp_setting "MISP.disable_user_login_change" false
set_misp_setting "MISP.disable_user_password_change" false
set_misp_setting "MISP.disable_user_add" false
set_misp_setting "MISP.block_event_alert" false
set_misp_setting "MISP.block_event_alert_tag" "no-alerts=\"true\""
set_misp_setting "MISP.block_old_event_alert" false
set_misp_setting "MISP.block_old_event_alert_age" ""
set_misp_setting "MISP.block_old_event_alert_by_date" ""
set_misp_setting "MISP.event_alert_republish_ban" true
set_misp_setting "MISP.event_alert_republish_ban_threshold" 5
set_misp_setting "MISP.event_alert_republish_ban_refresh_on_retry" false
set_misp_setting "MISP.incoming_tags_disabled_by_default" false
set_misp_setting "MISP.attachments_dir" "${MISP_PATH}/app/files"
set_misp_setting "MISP.download_attachments_on_load" true
set_misp_setting "MISP.event_alert_metadata_only" false
set_misp_setting "MISP.terms_download" false

# Force defaults to make MISP Server Settings less GREEN
set_misp_setting "debug" 0
set_misp_setting "Security.auth_enforced" false
set_misp_setting "Security.log_each_individual_auth_fail" false
set_misp_setting "Security.rest_client_baseurl" ""
set_misp_setting "Security.advanced_authkeys" true
set_misp_setting "Security.password_policy_length" 12
set_misp_setting "Security.password_policy_complexity" '/^((?=.*\\d)|(?=.*\\W+))(?![\\n])(?=.*[A-Z])(?=.*[a-z]).*$|.{16,}/'
set_misp_setting "Security.self_registration_message" "If you would like to send us a registration request, please fill out the form below. Make sure you fill out as much information as possible in order to ease the task of the administrators."

# Appease the security audit, #hardening
set_misp_setting "Security.disable_browser_cache" true
set_misp_setting "Security.check_sec_fetch_site_header" true
set_misp_setting "Security.csp_enforce" true
set_misp_setting "Security.advanced_authkeys" true
set_misp_setting "Security.do_not_log_authkeys" true

# Appease the security audit, #loggin
set_misp_setting "Security.username_in_response_header" true

print_ok "Settings configured."

systemctl restart supervisor &>>$logfile
error_check "Background workers setup"

print_status "Ingesting JSON structures"
sudo -u "${APACHE_USER}" "${MISP_PATH}/app/Console/cake" Admin updateJSON &>>$logfile
error_check "JSON structures ingestion"

# Enable modules, settings, and default of SSL in Apache
a2dismod status &>>$logfile
a2enmod ssl &>>$logfile
a2enmod rewrite &>>$logfile
a2enmod headers &>>$logfile
a2dissite 000-default &>>$logfile
a2ensite default-ssl &>>$logfile

# activate new vhost
a2dissite default-ssl &>>$logfile
a2ensite misp-ssl &>>$logfile

# Restart apache
systemctl restart apache2 &>>$logfile
error_check "Apache restart"

print_ok "Settings configured."

print_status "Finalising MISP setup..."
chown -R "${APACHE_USER}:${APACHE_USER}" "${MISP_PATH}" &>>$logfile
chown -R "${APACHE_USER}:${APACHE_USER}" "${MISP_PATH}/.git" &>>$logfile

save_settings

print_notification "You can now access your MISP instance at https://${MISP_DOMAIN}"
print_notification "The default admin credentials are:"
print_notification "Username: admin@admin.test"
print_notification "Password: ${PASSWORD}"
print_notification "MISP setup complete. Thank you, and have a very safe, and productive day."
