#!/bin/bash
# MISP 2.5 upgrade for MISP 2.4 installations on Ubuntu 24.04 LTS

# For other Ubuntu versions, make sure that you first dist-upgrade to 24.04. 

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
MISP_PATH='/var/www/MISP'
APACHE_USER='www-data'

### Supervisor settings
SWITCH_TO_SUPERVISOR=true
SUPERVISOR_USER='supervisor'
SUPERVISOR_PASSWORD="$(random_string)"
INSTALL_SSDEEP=false

# Some helper functions shamelessly copied from @da667's automisp install script.

logfile=/var/log/misp_upgrade.log
mkfifo ${logfile}.pipe
tee < ${logfile}.pipe $logfile &
exec &> ${logfile}.pipe
rm ${logfile}.pipe

function install_packages()
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


function error_check_soft
{
    if [ $? -eq 0 ]; then
        print_ok "$1 successfully completed."
    else
        print_error "$1 failed. Please check $logfile for more details. This is not a blocking failure though, proceeding..."
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

function os_version_check ()
{
    # Check if we're on Ubuntu 24.04 as expected:
    UBUNTU_VERSION=$(lsb_release -a | grep Release | grep -oP '[\d-]+.[\d-]+$')
    if [[ "$UBUNTU_VERSION" != "24.04" ]]; then
        print_error "This upgrade tool expects you to be running Ubuntu 24.04. If you are on a prior upgrade of Ubuntu, please make sure that you upgrade your distribution first, then execute this script again."
        exit 1
    fi
}

function print_notification ()
{
	echo -e "\x1B[01;33m[NOTICE]\x1B[0m $1"
}

BLUE="\033[1;34m"
NC="\033[0m"
echo -e "${BLUE}███╗   ███╗${NC}██╗███████╗██████╗ "
echo -e "${BLUE}████╗ ████║${NC}██║██╔════╝██╔══██╗"
echo -e "${BLUE}██╔████╔██║${NC}██║███████╗██████╔╝"
echo -e "${BLUE}██║╚██╔╝██║${NC}██║╚════██║██╔═══╝ "
echo -e "${BLUE}██║ ╚═╝ ██║${NC}██║███████║██║     "
echo -e "${BLUE}╚═╝     ╚═╝${NC}╚═╝╚══════╝╚═╝     "
echo -e "v2.5 Upgrade on Ubuntu 24.04 LTS"

os_version_check

save_settings() {
    echo "[$(date)] MISP installation

[MISP internal]
- SUPERVISOR_USER: ${SUPERVISOR_USER}
- SUPERVISOR_PASSWORD: ${SUPERVISOR_PASSWORD}
" | tee /var/log/misp_upgrade_settings.txt  &>> $logfile

    print_notification "Settings saved to /var/log/misp_upgrade_settings.txt"
}

print_status "Updating base system..."
sudo apt-get update &>> $logfile
sudo apt-get upgrade -y &>> $logfile
error_check "Base system update"

print_status "Checking if we're on the correct branch of MISP and updating it to the latest 2.4 release..."
sudo chown -R ${APACHE_USER}:${APACHE_USER} ${MISP_PATH}
sudo chown -R ${APACHE_USER}:${APACHE_USER} ${MISP_PATH}/.git
cd ${MISP_PATH}
git config --global --add safe.directory ${MISP_PATH}
CURRENT_MISP_BRANCH=$(sudo -u ${APACHE_USER} git rev-parse --abbrev-ref HEAD)
if [ $CURRENT_MISP_BRANCH != "2.4" ]; then
    print_error "You are not on the 2.4 branch of MISP. This upgrade script is meant to take your MISP 2.4 installation to 2.5+. Please switch to the 2.4 branch before running this script."
    # exit 1
fi
sudo -u ${APACHE_USER} git pull origin 2.4 &>> $logfile
error_check "Updating MISP to the latest 2.4 release"
sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin runUpdates &>> $logfile
error_check_soft "Updating MISP's database to the latest 2.4 release's schema"

print_status "Installing apt packages (supervisor jq)..."
declare -a packages=( supervisor jq );
install_packages ${packages[@]}
error_check "Basic dependencies installation"

print_status "Installing PHP and the list of required extensions..."
declare -a packages=( php8.3 php8.3-cli php8.3-dev php8.3-xml php8.3-mysql php8.3-opcache php8.3-readline php8.3-mbstring php8.3-zip \
  php8.3-intl php8.3-bcmath php8.3-gd php8.3-redis php8.3-gnupg php8.3-apcu libapache2-mod-php8.3 php8.3-curl );
install_packages ${packages[@]}
PHP_ETC_BASE=/etc/php/8.3
PHP_INI=${PHP_ETC_BASE}/apache2/php.ini
error_check "PHP and required extensions installation."

print_status "Disabling/Enabling php apache module (trial and error like a monkey)..."
sudo a2dismod php7.0 &>> $logfile
sudo a2dismod php7.1 &>> $logfile
sudo a2dismod php7.2 &>> $logfile
sudo a2dismod php7.3 &>> $logfile
sudo a2dismod php7.4 &>> $logfile
sudo a2enmod php8.3 &>> $logfile
error_check "PHP 8.3 module enabling"

# Install composer and the composer dependencies of MISP

print_status "Installing composer..."

## make pip and composer happy
sudo mkdir /var/www/.cache/ &>> $logfile
sudo chown -R ${APACHE_USER}:${APACHE_USER} /var/www/.cache/ &>> $logfile

curl -sS https://getcomposer.org/installer -o /tmp/composer-setup.php &>> $logfile
COMPOSER_HASH=`curl -sS https://composer.github.io/installer.sig`
php -r "if (hash_file('SHA384', '/tmp/composer-setup.php') === '$HASH') { echo 'Installer verified'; } else { echo 'Installer corrupt'; unlink('composer-setup.php'); } echo PHP_EOL;"  &>> $logfile
sudo php /tmp/composer-setup.php --install-dir=/usr/local/bin --filename=composer  &>> $logfile
error_check "Composer installation"

sudo service apache2 restart
error_check "Apache restart"
print_ok "PHP8.3 configured..."

print_status "Installing PECL extensions..."

sudo pecl channel-update pecl.php.net &>> $logfile
sudo pecl install brotli &>> $logfile
error_check "PECL brotli extension installation"
sudo pecl install simdjson &>> $logfile
error_check "PECL simdjson extension installation"
sudo pecl install zstd &>> $logfile
error_check "PECL zstd extension installation"

if [ $INSTALL_SSDEEP ]; then
    sudo apt install make -y &>> $logfile
    error_check "The installation of make"
    git clone --recursive --depth=1 https://github.com/JakubOnderka/pecl-text-ssdeep.git /tmp/pecl-text-ssdeep
    error_check "Jakub Onderka's PHP8 SSDEEP extension cloning"
    cd /tmp/pecl-text-ssdeep && phpize && ./configure && make && make install
    error_check "Jakub Onderka's PHP8 SSDEEP extension compilation and installation"
fi


print_status "Switching to the 2.5 branch"
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
sudo -u ${APACHE_USER} rm -f composer.lock
sudo -u ${APACHE_USER} composer install --no-dev --no-interaction --prefer-dist &>> $logfile
error_check "MISP composer dependencies installation"

print_status "Reworking the MISP database.php file"

cd ${MISP_PATH}/app/Config
sudo -u ${APACHE_USER} cp -a database.php database.php.bk &>> $logfile
sudo -u ${APACHE_USER} cp -a database.default.php database.php &>> $logfile

declare -a dbsettings=("datasource" "persistent" "host" "login" "port" "password" "database" "prefix" "encoding")
for i in "${dbsettings[@]}"
do
   # Hacky AF. I have brought great shame on my family.
   TEMPVALUE=$(cat "${MISP_PATH}/app/Config/database.php.bk" | grep "'$i' => " | grep -v "//'" | grep -v '*')
   sed -i "/'$i' =>/c ${TEMPVALUE}" database.php &>> $logfile
done

print_ok "MISP database.php file rewritten."

print_status "Running MISP updates"

sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin runUpdates &>> $logfile
error_check "MISP schema updates"

print_status "Setting up background workers"

SUPERVISOR_ALREADY_ENABLED=$(${MISP_PATH}/app/Console/cake Admin getSetting SimpleBackgroundJobs.enabled | jq -r '.value')

if [ $SWITCH_TO_SUPERVISOR ] && [ $SUPERVISOR_ALREADY_ENABLED != true ]; then

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


error_check "Background workers setup"

fi

print_status "Ingesting JSON structures"
sudo -u ${APACHE_USER} ${MISP_PATH}/app/Console/cake Admin updateJSON &>> $logfile
error_check "JSON structures ingestion"

# Restart apache
sudo systemctl restart apache2 &>> $logfile
error_check "Apache restart"


print_status "Finalising MISP setup..."
sudo chown -R ${APACHE_USER}:${APACHE_USER} ${MISP_PATH} &>> $logfile
sudo chown -R ${APACHE_USER}:${APACHE_USER} ${MISP_PATH}/.git &>> $logfile

save_settings

print_notification "MISP setup complete. Thank you, and have a very safe, and productive day."