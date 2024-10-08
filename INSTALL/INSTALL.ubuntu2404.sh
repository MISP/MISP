#!/bin/bash
# MISP 2.5 installation for Ubuntu 24.04 LTS

# This guide is meant to be a simply installation of MISP on a pristine Ubuntu 20.04 LTS server.
# Keep in mind that whilst this installs the software along with all of its dependencies, it's up to you to properly secure it.

# This guide liberally borrows from three sources:
# - The previous iterations of the official MISP installation guide, which can be found at: https://misp.github.io/MISP
# - The automisp install guide by @da667, which can be found at: https://github.com/da667/AutoMISP/blob/master/auto-MISP-ubuntu.sh
# - MISP-docker by @ostefano, which can be found at: https://github.com/MISP/MISP-docker
# Thanks to both Tony Robinson (@da667), Stefano Ortolani (@ostefano) and Steve Clement (@SteveClement) for their awesome work!

# This installation script assumes that you are installing as root, or a user with sudo access.

random_string() {
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1
}

# Configure the following variables in advance for your environment
## required settings - please change all of these, failing to do so will result in a non-working installation or a highly insecure installation
PASSWORD="$(random_string)"
MISP_DOMAIN='misp.local'
PATH_TO_SSL_CERT=''
INSTALL_SSDEEP='n' # y/n, if you want to install ssdeep, set to 'y', however, this will require the installation of make

## optional settings
MISP_PATH='/var/www/MISP'
APACHE_USER='www-data'

### DB settings, if you want to use a different DB host, name, user, or password, please change these
DBHOST='localhost'
DBUSER_ADMIN='root'
DBPASSWORD_ADMIN='' # Default on Ubuntu is a passwordless root account, if you have changed it, please set it here
DBNAME='misp'
DBPORT='3306'
DBUSER_MISP='misp'
DBPASSWORD_MISP="$(random_string)"

### Supervisor settings
SUPERVISOR_USER='supervisor'
SUPERVISOR_PASSWORD="$(random_string)"

### PHP settings
upload_max_filesize="50M"
post_max_size="50M"
max_execution_time="300"
memory_limit="2048M"

## GPG
GPG_EMAIL_ADDRESS="admin@admin.test"
GPG_PASSPHRASE="$(openssl rand -hex 32)"

### Only needed if no SSL CERT is provided
OPENSSL_C='LU'
OPENSSL_ST='Luxembourg'
OPENSSL_L='Luxembourg'
OPENSSL_O='MISP'
OPENSSL_OU='MISP'
OPENSSL_CN=${MISP_DOMAIN}
OPENSSL_EMAILADDRESS='misp@'${MISP_DOMAIN}

# Some helper functions shamelessly copied from @da667's automisp install script.

logfile=/var/log/misp_install.log
mkfifo ${logfile}.pipe
tee < ${logfile}.pipe $logfile &
exec &> ${logfile}.pipe
rm ${logfile}.pipe

function install_packages ()
{
    install_params=("$@")
    for i in "${install_params[@]}";
    do
        sudo apt-get install -y "$i" &>> $logfile
        error_check "$i installation"
    done
}


function error_check
{
    if [ $? -eq 0 ]; then
        print_ok "$1 successfully completed."
    else
        print_error "$1 failed. Please check $logfile for more details."
    exit 1
    fi
}

function print_status ()
{
    echo -e "\x1B[01;34m[STATUS]\x1B[0m $1"
}

function print_ok ()
{
    echo -e "\x1B[01;32m[OK]\x1B[0m $1"
}

function print_error ()
{
    echo -e "\x1B[01;31m[ERROR]\x1B[0m $1"
}

function print_notification ()
{
	echo -e "\x1B[01;33m[NOTICE]\x1B[0m $1"
}

function os_version_check ()
{
    # Check if we're on Ubuntu 24.04 as expected:
    UBUNTU_VERSION=$(lsb_release -a | grep Release | grep -oP '[\d-]+.[\d-]+$')
    if [[ "$UBUNTU_VERSION" != "24.04" ]]; then
        print_error "This upgrade tool expects you to be running Ubuntu 24.04. If you are on a prior upgrade of Ubuntu, please make sure that you upgrade your distribution first, then execute this script again."
        exit 1
    fi
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
    echo "[$(date)] MISP installation

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
" | tee /var/log/misp_settings.txt  &>> $logfile

    print_notification "Settings saved to /var/log/misp_settings.txt"
}

print_status "Updating base system..."
sudo apt-get update &>> $logfile
sudo apt-get upgrade -y &>> $logfile
error_check "Base system update"

print_status "Installing apt packages (git curl python3 python3-pip python3-virtualenv apache2 zip gcc sudo binutils openssl supervisor)..."
declare -a packages=( git curl python3 python3-pip python3-virtualenv apache2 zip gcc sudo binutils openssl supervisor );
install_packages ${packages[@]}
error_check "Basic dependencies installation"

print_status "Installing MariaDB..."
declare -a packages=( mariadb-server mariadb-client );
install_packages ${packages[@]}
error_check "MariaDB installation"


print_status "Installing PHP and the list of required extensions..."
declare -a packages=( redis-server php8.3 php8.3-cli php8.3-dev php8.3-xml php8.3-mysql php8.3-opcache php8.3-readline php8.3-mbstring php8.3-zip \
  php8.3-intl php8.3-bcmath php8.3-gd php8.3-redis php8.3-gnupg php8.3-apcu libapache2-mod-php8.3 php8.3-curl );
install_packages ${packages[@]}
PHP_ETC_BASE=/etc/php/8.3
PHP_INI=${PHP_ETC_BASE}/apache2/php.ini
error_check "PHP and required extensions installation."

# Install composer and the composer dependencies of MISP

print_status "Installing composer..."

## make pip and composer happy
sudo mkdir /var/www/.cache/
sudo chown -R ${APACHE_USER}:${APACHE_USER} /var/www/.cache/

curl -sS https://getcomposer.org/installer -o /tmp/composer-setup.php &>> $logfile
COMPOSER_HASH=`curl -sS https://composer.github.io/installer.sig`
php -r "if (hash_file('SHA384', '/tmp/composer-setup.php') === '$HASH') { echo 'Installer verified'; } else { echo 'Installer corrupt'; unlink('composer-setup.php'); } echo PHP_EOL;"  &>> $logfile
sudo php /tmp/composer-setup.php --install-dir=/usr/local/bin --filename=composer  &>> $logfile
error_check "Composer installation"

print_status "Configuring php and MySQL configs..."
for key in upload_max_filesize post_max_size max_execution_time max_input_time memory_limit
do
    sudo sed -i "s/^\($key\).*/\1 = $(eval echo \${$key})/" $PHP_INI
done
sudo sed -i "s/^\(session.sid_length\).*/\1 = 32/" $PHP_INI
sudo sed -i "s/^\(session.use_strict_mode\).*/\1 = 1/" $PHP_INI
sudo sed -i "s/^\(session.save_handler\).*/\1 = redis/" $PHP_INI
sudo sed -i "/session.save_handler/a session.save_path = 'tcp:\/\/localhost:6379'/" $PHP_INI

MYCNF="/etc/mysql/mariadb.conf.d/50-server.cnf"
# We go for an innodb buffer pool size of 50% of the available memory

# Check for cgroup memory limits, don't rely on /proc/meminfo in an LXC container with unbound memory limits
# Thanks to Sascha Rommelfangen (@rommelfs) for the hint
CGROUPMEMORYHIGHPATH="/sys/fs/cgroup/memory.high"
if [ -f $CGROUPMEMORYHIGHPATH ] && [[ "cat ${CGROUPMEMORYHIGHPATH}" == "max" ]]; then
    INNODBBUFFERPOOLSIZE='2048M'
else
    INNODBBUFFERPOOLSIZE=$(grep MemTotal /proc/meminfo | awk '{print int($2 / 2048)}')'M'
fi

sudo sed -i "/\[mariadb\]/a innodb_buffer_pool_size = ${INNODBBUFFERPOOLSIZE}" $MYCNF
sudo sed -i '/\[mariadb\]/a innodb_io_capacity = 1000' $MYCNF
sudo sed -i '/\[mariadb\]/a innodb_read_io_threads = 16' $MYCNF

sudo service apache2 restart
error_check "Apache restart"
sudo service mysql restart
error_check "MySQL restart"

print_ok "PHP and MySQL configured..."

print_status "Installing PECL extensions..."

sudo pecl channel-update pecl.php.net &>> $logfile
sudo pecl install brotli &>> $logfile
error_check "PECL brotli extension installation"
sudo pecl install simdjson &>> $logfile
error_check "PECL simdjson extension installation"
sudo pecl install zstd &>> $logfile
error_check "PECL zstd extension installation"

if [ $INSTALL_SSDEEP == "y" ]; then
    sudo apt install make -y &>> $logfile
    error_check "The installation of make"
    git clone --recursive --depth=1 https://github.com/JakubOnderka/pecl-text-ssdeep.git /tmp/pecl-text-ssdeep
    error_check "Jakub Onderka's PHP8 SSDEEP extension cloning"
    cd /tmp/pecl-text-ssdeep && phpize && ./configure && make && make install
    error_check "Jakub Onderka's PHP8 SSDEEP extension compilation and installation"
fi


print_status "Cloning MISP"
sudo git clone https://github.com/MISP/MISP.git ${MISP_PATH}  &>> $logfile
error_check "MISP clonining"
cd ${MISP_PATH}
git fetch origin 2.5 &>> $logfile
error_check "Fetching 2.5 branch"
git checkout 2.5 &>> $logfile
error_check "Checking out 2.5 branch"

print_status "Cloning MISP submodules..."
sudo git config --global --add safe.directory ${MISP_PATH}  &>> $logfile
sudo git -C ${MISP_PATH} submodule update --init --recursive &>> $logfile
error_check "MISP submodules cloning"
sudo git -C ${MISP_PATH} submodule foreach --recursive git config core.filemode false &>> $logfile
sudo chown -R ${APACHE_USER}:${APACHE_USER} ${MISP_PATH} &>> $logfile
sudo chown -R ${APACHE_USER}:${APACHE_USER} ${MISP_PATH}/.git &>> $logfile
print_ok "MISP's submodules cloned."

print_status "Installing MISP composer dependencies..."
cd ${MISP_PATH}/app
sudo -u ${APACHE_USER} composer install --no-dev --no-interaction --prefer-dist &>> $logfile
error_check "MISP composer dependencies installation"

print_status "Create DB and user for MISP as well as importing the basic MISP schema..."
DBUSER_ADMIN_STRING=''
if [ "$DBUSER_ADMIN" != 'root' ]; then
    DBUSER_ADMIN_STRING='-u '"${DBUSER_ADMIN}"
fi

DBPASSWORD_ADMIN_STRING=''
if [ ! -z "${DBPASSWORD_ADMIN}" ]; then
    DBPASSWORD_ADMIN_STRING='-p'"${DBPASSWORD_ADMIN}"
fi

DBUSER_MISP_STRING=''
if [ ! -z "${DBUSER_MISP}" ]; then
    DBUSER_MISP_STRING='-u '"${DBUSER_MISP}"
fi

DBPASSWORD_MISP_STRING=''
if [ ! -z "${DBPASSWORD_MISP}" ]; then
    DBPASSWORD_MISP_STRING='-p'"${DBPASSWORD_MISP}"
fi

DBHOST_STRING=''
if [ ! -z "$DBHOST" ] && [ "$DBHOST" != "localhost" ]; then
    DBHOST_STRING="-h ${DBHOST}"
fi

DBPORT_STRING=''
if [ "$DBPORT" != 3306 ]; then
    DBPORT_STRING='--port '"${DBPORT}"
fi
DBCONN_ADMIN_STRING="${DBPORT_STRING} ${DBHOST_STRING} ${DBUSER_ADMIN_STRING} ${DBPASSWORD_ADMIN_STRING}"
DBCONN_MISP_STRING="${DBPORT_STRING} ${DBHOST_STRING} ${DBUSER_MISP_STRING} ${DBPASSWORD_MISP_STRING}"

sudo mysql $DBCONN_ADMIN_STRING -e "CREATE DATABASE ${DBNAME};"  &>> $logfile
sudo mysql $DBCONN_ADMIN_STRING -e "CREATE USER '${DBUSER_MISP}'@'localhost' IDENTIFIED BY '${DBPASSWORD_MISP}';"  &>> $logfile
sudo mysql $DBCONN_ADMIN_STRING -e "GRANT USAGE ON *.* to '${DBUSER_MISP}'@'localhost';"  &>> $logfile
sudo mysql $DBCONN_ADMIN_STRING -e "GRANT ALL PRIVILEGES on ${DBNAME}.* to '${DBUSER_MISP}'@'localhost';"  &>> $logfile
sudo mysql $DBCONN_ADMIN_STRING -e "FLUSH PRIVILEGES;"  &>> $logfile
mysql $DBCONN_MISP_STRING $DBNAME < "${MISP_PATH}/INSTALL/MYSQL.sql"  &>> $logfile
error_check "MISP database schema import"

print_status "Moving and configuring MISP php config files.."

cd ${MISP_PATH}/app/Config
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
if [ -z "${PATH_TO_SSL_CERT}" ]; then
    print_notification "Generating self-signed SSL certificate."
    sudo openssl req -newkey rsa:4096 -days 365 -nodes -x509 \
    -subj "/C=${OPENSSL_C}/ST=${OPENSSL_ST}/L=${OPENSSL_L}/O=${OPENSSL_O}/OU=${OPENSSL_OU}/CN=${OPENSSL_CN}/emailAddress=${OPENSSL_EMAILADDRESS}" \
    -keyout /etc/ssl/private/misp.local.key -out /etc/ssl/private/misp.local.crt &>> $logfile
    error_check "Self-signed SSL certificate generation"
else
    print_status "Using provided SSL certificate."
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
          SSLCertificateFile /etc/ssl/private/misp.local.crt
          SSLCertificateKeyFile /etc/ssl/private/misp.local.key

          LogLevel warn
          ErrorLog /var/log/apache2/misp.local_error.log
          CustomLog /var/log/apache2/misp.local_access.log combined
          ServerSignature Off
          Header set X-Content-Type-Options nosniff
          Header set X-Frame-Options DENY
  </VirtualHost>" | sudo tee /etc/apache2/sites-available/misp-ssl.conf  &>> $logfile

error_check "Apache configuration file creation"  &>> $logfile


print_status "Running MISP updates"

sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.osuser" ${APACHE_USER} &>> $logfile
sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin runUpdates &>> $logfile
sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake User init | sudo tee /tmp/misp_user_key.txt  &>> $logfile
sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake User change_pw 'admin@admin.test' ${PASSWORD} &>> $logfile
MISP_USER_KEY=`cat /tmp/misp_user_key.txt`
rm -f /tmp/misp_user_key.txt

print_ok "MISP updated."

print_status "Generating PGP key"
# The email address should match the one set in the config.php
# set in the configuration menu in the administration menu configuration file

sudo -u ${APACHE_USER} gpg --homedir $MISP_PATH/.gnupg --quick-generate-key --batch --passphrase $GPG_PASSPHRASE ${GPG_EMAIL_ADDRESS} ed25519 sign never  &>> $logfile
error_check "PGP key generation"
# Export the public key to the webroot
sudo -u ${APACHE_USER} gpg --homedir $MISP_PATH/.gnupg --export --armor ${GPG_EMAIL_ADDRESS} | sudo -u ${APACHE_USER} tee $MISP_PATH/app/webroot/gpg.asc  &>> $logfile
error_check "PGP key export"

print_status "Setting up Python environment for MISP"

# Create a python3 virtualenv
sudo -u ${APACHE_USER} virtualenv -p python3 ${MISP_PATH}/venv &>> $logfile
error_check "Python virtualenv creation"

cd ${MISP_PATH}
. ./venv/bin/activate &>> $logfile
error_check "Python virtualenv activation"

# install python dependencies
${MISP_PATH}/venv/bin/pip install -r ${MISP_PATH}/requirements.txt  &>> $logfile
error_check "Python dependencies installation"

chown -R ${APACHE_USER}:${APACHE_USER} ${MISP_PATH}/venv

print_status "Setting up background workers"

sudo echo "
[inet_http_server]
port=127.0.0.1:9001
username=$SUPERVISOR_USER
password=$SUPERVISOR_PASSWORD" | sudo tee -a /etc/supervisor/supervisord.conf  &>> $logfile

sudo echo "[group:misp-workers]
programs=default,email,cache,prio,update

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
user=$APACHE_USER"  | sudo tee -a /etc/supervisor/conf.d/misp-workers.conf  &>> $logfile

sudo systemctl restart supervisor  &>> $logfile
error_check "Background workers setup"

# Set settings
  # The default install is Python >=3.6 in a virtualenv, setting accordingly
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.python_bin" "${MISP_PATH}/venv/bin/python" &>> $logfile

  # Tune global time outs
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Session.autoRegenerate" 0 &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Session.timeout" 600 &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Session.cookieTimeout" 3600 &>> $logfile
 
  # Set the default temp dir
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.tmpdir" "${MISP_PATH}/app/tmp" &>> $logfile

  # Change base url, either with this CLI command or in the UI
  [[ ! -z ${MISP_DOMAIN} ]] && sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Baseurl $MISP_DOMAIN &>> $logfile
  [[ ! -z ${MISP_DOMAIN} ]] && sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.external_baseurl" ${MISP_BASEURL} &>> $logfile

  # Enable GnuPG
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "GnuPG.email" "${GPG_EMAIL_ADDRESS}" &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "GnuPG.homedir" "${MISP_PATH}/.gnupg" &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "GnuPG.password" "${GPG_PASSPHRASE}" &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "GnuPG.obscure_subject" true &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "GnuPG.key_fetching_disabled" false &>> $logfile
  # FIXME: what if we have not gpg binary but a gpg2 one?
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "GnuPG.binary" "$(which gpg)" &>> $logfile

  # Enable installer org and tune some configurables
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.host_org_id" 1 &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.email" "${GPG_EMAIL_ADDRESS}" &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.disable_emailing" false &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.contact" "${GPG_EMAIL_ADDRESS}" &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.disablerestalert" true &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.showCorrelationsOnIndex" true &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.default_event_tag_collection" 0 &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.log_new_audit" 1 &>> $logfile

  # Configure background workers
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "SimpleBackgroundJobs.enabled" 1 &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "SimpleBackgroundJobs.redis_host" '127.0.0.1' &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "SimpleBackgroundJobs.redis_port" 6379 &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "SimpleBackgroundJobs.redis_database" 13 &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "SimpleBackgroundJobs.redis_password" "" &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "SimpleBackgroundJobs.redis_namespace" "background_jobs" &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "SimpleBackgroundJobs.supervisor_host" "localhost" &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "SimpleBackgroundJobs.supervisor_port" 9001 &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "SimpleBackgroundJobs.supervisor_user" ${SUPERVISOR_USER} &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "SimpleBackgroundJobs.supervisor_password" ${SUPERVISOR_PASSWORD} &>> $logfile

  # Various plugin sightings settings
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Plugin.Sightings_policy" 0 &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Plugin.Sightings_anonymise" false &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Plugin.Sightings_anonymise_as" 1 &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Plugin.Sightings_range" 365 &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Plugin.Sightings_sighting_db_enable" false &>> $logfile

  # ZeroMQ settings
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Plugin.ZeroMQ_enable" false &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Plugin.ZeroMQ_host" "127.0.0.1" &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Plugin.ZeroMQ_port" 50000 &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Plugin.ZeroMQ_redis_host" "localhost" &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Plugin.ZeroMQ_redis_port" 6379 &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Plugin.ZeroMQ_redis_database" 1 &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Plugin.ZeroMQ_redis_namespace" "mispq" &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Plugin.ZeroMQ_event_notifications_enable" false &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Plugin.ZeroMQ_object_notifications_enable" false &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Plugin.ZeroMQ_object_reference_notifications_enable" false &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Plugin.ZeroMQ_attribute_notifications_enable" false &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Plugin.ZeroMQ_sighting_notifications_enable" false &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Plugin.ZeroMQ_user_notifications_enable" false &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Plugin.ZeroMQ_organisation_notifications_enable" false &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Plugin.ZeroMQ_include_attachments" false &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Plugin.ZeroMQ_tag_notifications_enable" false &>> $logfile

  # Force defaults to make MISP Server Settings less RED
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.language" "eng" &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.proposals_block_attributes" false &>> $logfile

  # Redis block
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.redis_host" "127.0.0.1" &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.redis_port" 6379 &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.redis_database" 13 &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.redis_password" "" &>> $logfile

  # Force defaults to make MISP Server Settings less YELLOW
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.ssdeep_correlation_threshold" 40 &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.extended_alert_subject" false &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.default_event_threat_level" 4 &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.newUserText" "Dear new MISP user,\\n\\nWe would hereby like to welcome you to the \$org MISP community.\\n\\n Use the credentials below to log into MISP at \$misp, where you will be prompted to manually change your password to something of your own choice.\\n\\nUsername: \$username\\nPassword: \$password\\n\\nIf you have any questions, don't hesitate to contact us at: \$contact.\\n\\nBest regards,\\nYour \$org MISP support team" &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.passwordResetText" "Dear MISP user,\\n\\nA password reset has been triggered for your account. Use the below provided temporary password to log into MISP at \$misp, where you will be prompted to manually change your password to something of your own choice.\\n\\nUsername: \$username\\nYour temporary password: \$password\\n\\nIf you have any questions, don't hesitate to contact us at: \$contact.\\n\\nBest regards,\\nYour \$org MISP support team" &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.enableEventBlocklisting" true &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.enableOrgBlocklisting" true &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.log_client_ip" true &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.log_auth" false &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.log_user_ips" true &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.log_user_ips_authkeys" true &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.disableUserSelfManagement" false &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.disable_user_login_change" false &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.disable_user_password_change" false &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.disable_user_add" false &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.block_event_alert" false &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.block_event_alert_tag" "no-alerts=\"true\"" &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.block_old_event_alert" false &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.block_old_event_alert_age" "" &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.block_old_event_alert_by_date" "" &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.event_alert_republish_ban" true &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.event_alert_republish_ban_threshold" 5 &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.event_alert_republish_ban_refresh_on_retry" false &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.incoming_tags_disabled_by_default" false &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.attachments_dir" "${MISP_PATH}/app/files" &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.download_attachments_on_load" true &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.event_alert_metadata_only" false &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "MISP.terms_download" false &>> $logfile

  # Force defaults to make MISP Server Settings less GREEN
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "debug" 0 &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Security.auth_enforced" false &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Security.log_each_individual_auth_fail" false &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Security.rest_client_baseurl" "" &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Security.advanced_authkeys" true &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Security.password_policy_length" 12 &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Security.password_policy_complexity" '/^((?=.*\d)|(?=.*\W+))(?![\n])(?=.*[A-Z])(?=.*[a-z]).*$|.{16,}/' &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Security.self_registration_message" "If you would like to send us a registration request, please fill out the form below. Make sure you fill out as much information as possible in order to ease the task of the administrators." &>> $logfile

  # Appease the security audit, #hardening
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Security.disable_browser_cache" true &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Security.check_sec_fetch_site_header" true &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Security.csp_enforce" true &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Security.advanced_authkeys" true &>> $logfile
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Security.do_not_log_authkeys" true &>> $logfile

  # Appease the security audit, #loggin
  sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin setSetting "Security.username_in_response_header" true &>> $logfile

print_ok "Settings configured."

print_status "Ingesting JSON structures"
sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin updateJSON &>> $logfile
error_check "JSON structures ingestion"

  # Enable modules, settings, and default of SSL in Apache
  sudo a2dismod status &>> $logfile
  sudo a2enmod ssl &>> $logfile
  sudo a2enmod rewrite &>> $logfile
  sudo a2enmod headers &>> $logfile
  sudo a2dissite 000-default &>> $logfile
  sudo a2ensite default-ssl &>> $logfile

  # activate new vhost
  sudo a2dissite default-ssl &>> $logfile
  sudo a2ensite misp-ssl &>> $logfile

  # Restart apache
  sudo systemctl restart apache2 &>> $logfile
  error_check "Apache restart"

print_ok "Settings configured."

print_status "Finalising MISP setup..."
sudo chown -R ${APACHE_USER}:${APACHE_USER} ${MISP_PATH} &>> $logfile
sudo chown -R ${APACHE_USER}:${APACHE_USER} ${MISP_PATH}/.git &>> $logfile

save_settings

print_notification "You can now access your MISP instance at https://${MISP_DOMAIN}"
print_notification "The default admin credentials are:"
print_notification "Username: admin@admin.test"
print_notification "Password: ${PASSWORD}"
print_notification "MISP setup complete. Thank you, and have a very safe, and productive day."
