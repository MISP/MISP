# **deprecated** INSTALLATION INSTRUCTIONS
## for CentOS 7.x


Please use the Red Hat Enterprise Linux 7 Instructions for a CentOS 7 install. [click here](https://misp.github.io/MISP/INSTALL.rhel7).

### -1/ Installer and Manual install instructions

Make sure you are reading the parsed version of this Document. When in doubt [click here](https://misp.github.io/MISP/INSTALL.rhel7).

!!! warning
    In the **future**, to install MISP on a fresh CentOS 7 install all you need to do is:

    ```bash
    # Please check the installer options first to make the best choice for your install
    wget --no-cache -O /tmp/INSTALL.sh https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.sh
    bash /tmp/INSTALL.sh

    # This will install MISP Core
    wget --no-cache -O /tmp/INSTALL.sh https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.sh
    bash /tmp/INSTALL.sh -c
    ```
    **The above does NOT work yet**

### 0/ MISP CentOS 7 Minimal NetInstall - Status
--------------------------------------------

{% include_relative generic/community.md %}

{% include_relative generic/rhelVScentos.md %}

!!! notice
    Semi-maintained and tested by @SteveClement, CentOS 7.6-1804 on 20190410<br />
    It is still considered experimental as not everything works seamlessly.

!!! notice
    Maintenance for CentOS 7 will end on: June 30th, 2024 [Source[0]](https://wiki.centos.org/About/Product) [Source[1]](https://linuxlifecycle.com/)
    CentOS 7.6-1810 [NetInstallURL](http://mirror.centos.org/centos/7.6.1810/os/x86_64/)

{% include_relative generic/globalVariables.md %}

```bash
# <snippet-begin 0_RHEL_PHP_INI.sh>
# RHEL/CentOS Specific
WWW_USER="apache"
SUDO_WWW="sudo -H -u ${WWW_USER}"

RUN_PHP='/usr/bin/scl enable rh-php72'
PHP_INI=/etc/opt/rh/rh-php72/php.ini
# <snippet-end 0_RHEL_PHP_INI.sh>
```

### 1/ Minimal CentOS install
-------------------------

Install a minimal CentOS 7.x system with the software:

- OpenSSH server
- LAMP server (actually, this is done below)
- Mail server


```bash
# Make sure you set your hostname CORRECTLY vs. like an brute (manually in /etc/hostname)
sudo hostnamectl set-hostname misp.local # Your choice, in a production environment, it's best to use a FQDN

# Make sure your system is up2date:
sudo yum update -y
```

### 2/ Dependencies *
----------------
Once the system is installed you can perform the following steps as root or with sudo.

```bash
# We need some packages from the Extra Packages for Enterprise Linux repository
sudo yum install epel-release -y

# Since MISP 2.4 PHP 5.5 is a minimal requirement, so we need a newer version than CentOS base provides
# Software Collections is a way do to this, see https://wiki.centos.org/AdditionalResources/Repositories/SCL
sudo yum install centos-release-scl -y

# Because (neo)vim is just so practical
sudo yum install neovim -y

# Install the dependencies:
sudo yum install gcc git zip \
       httpd \
       mod_ssl \
       redis \
       mariadb mariadb-server \
       python-devel python-pip python-zmq \
       libxslt-devel zlib-devel ssdeep-devel -y

# Install PHP 7.2 from SCL, see https://www.softwarecollections.org/en/scls/rhscl/rh-php72/
sudo yum install rh-php72 rh-php72-php-fpm rh-php72-php-devel rh-php72-php-mysqlnd rh-php72-php-mbstring rh-php72-php-xml rh-php72-php-bcmath rh-php72-php-opcache rh-php72-php-gd rh-php72-php-zip -y

# Python 3.6 in now available in CentOS 7.7 base
sudo yum install python3 python3-devel -y

sudo systemctl enable --now rh-php72-php-fpm.service
```

!!! notice
    $RUN_PHP makes php available for you if using rh-php72. e.g: sudo $RUN_PHP "pear list | grep Crypt_GPG"

```bash
# GPG needs lots of entropy, haveged provides entropy
sudo yum install haveged -y
sudo systemctl enable --now haveged.service

# Enable and start redis
sudo systemctl enable --now redis.service
```

### 3/ MISP code
------------
```bash
# Download MISP using git in the /var/www/ directory.
PATH_TO_MISP="/var/www/MISP"
sudo mkdir -p $(dirname ${PATH_TO_MISP})
sudo chown ${WWW_USER}:${WWW_USER} ($dirname ${PATH_TO_MISP})
cd $(dirname ${PATH_TO_MISP})
${SUDO_WWW} git clone https://github.com/MISP/MISP.git
cd ${PATH_TO_MISP}
##${SUDO_WWW} git checkout tags/$(git describe --tags `git rev-list --tags --max-count=1`)
# if the last shortcut doesn't work, specify the latest version manually
# example: git checkout tags/v2.4.XY
# the message regarding a "detached HEAD state" is expected behaviour
# (you only have to create a new branch, if you want to change stuff and do a pull request for example)

# Fetch submodules
${SUDO_WWW} git submodule update --init --recursive
# Make git ignore filesystem permission differences for submodules
${SUDO_WWW} git submodule foreach --recursive git config core.filemode false
# Make git ignore filesystem permission differences
${SUDO_WWW} git config core.filemode false

# Create a python3 virtualenv
sudo pip3 install virtualenv
${SUDO_WWW} python3 "virtualenv -p python3 ${PATH_TO_MISP}/venv"
sudo mkdir /usr/share/httpd/.cache
sudo chown ${WWW_USER}:${WWW_USER} /usr/share/httpd/.cache
${SUDO_WWW} ${PATH_TO_MISP}/venv/bin/pip install -U pip setuptools

# install Mitre's STIX and its dependencies by running the following commands:
##sudo yum install python-importlib python-lxml python-dateutil python-six -y

cd ${PATH_TO_MISP}/app/files/scripts
${SUDO_WWW} git clone https://github.com/CybOXProject/python-cybox.git
${SUDO_WWW} git clone https://github.com/STIXProject/python-stix.git
${SUDO_WWW} git clone --branch master --single-branch https://github.com/lief-project/LIEF.git lief
${SUDO_WWW} git clone https://github.com/CybOXProject/mixbox.git

cd ${PATH_TO_MISP}/app/files/scripts/python-cybox
$SUDO_WWW git config core.filemode false
# If you umask is has been changed from the default, it is a good idea to reset it to 0022 before installing python modules
UMASK=$(umask)
umask 0022
cd ${PATH_TO_MISP}/app/files/scripts/python-stix
$SUDO_WWW git config core.filemode false
${SUDO_WWW} ${PATH_TO_MISP}/venv/bin/pip install .

# install maec
${SUDO_WWW} ${PATH_TO_MISP}/venv/bin/pip install -U maec

# install zmq
${SUDO_WWW} ${PATH_TO_MISP}/venv/bin/pip install -U zmq

# install redis
${SUDO_WWW} ${PATH_TO_MISP}/venv/bin/pip install -U redis

# lief needs manual compilation
sudo yum install devtoolset-7 cmake3 -y


# TODO: Fix static path with PATH_TO_MISP
cd ${PATH_TO_MISP}/app/files/scripts/lief
$SUDO_WWW git config core.filemode false
${SUDO_WWW} mkdir build
cd build
${SUDO_WWW} scl enable devtoolset-7 'bash -c "cmake3 \
-DLIEF_PYTHON_API=on \
-DLIEF_DOC=off \
-DCMAKE_INSTALL_PREFIX=$LIEF_INSTALL \
-DCMAKE_BUILD_TYPE=Release \
-DPYTHON_VERSION=3.6 \
-DPYTHON_EXECUTABLE=${PATH_TO_MISP}/venv/bin/python \
.."'
${SUDO_WWW} make -j3
sudo make install
cd api/python/lief_pybind11-prefix/src/lief_pybind11
${SUDO_WWW} ${PATH_TO_MISP}/venv/bin/python setup.py install
${SUDO_WWW} ${PATH_TO_MISP}/venv/bin/pip install lief

# install magic, pydeep
${SUDO_WWW} ${PATH_TO_MISP}/venv/bin/pip install -U python-magic git+https://github.com/kbandla/pydeep.git

cd ${PATH_TO_MISP}/app/files/scripts/mixbox
$SUDO_WWW git config core.filemode false
${SUDO_WWW} ${PATH_TO_MISP}/venv/bin/pip install .

# Install misp-stix
cd ${PATH_TO_MISP}/app/files/scripts/misp-stix
${SUDO_WWW} ${PATH_TO_MISP}/venv/bin/pip install .

# install PyMISP
cd ${PATH_TO_MISP}/PyMISP
${SUDO_WWW} ${PATH_TO_MISP}/venv/bin/pip install .

# FIXME: Remove libfaup etc once the egg has the library baked-in
# BROKEN: This needs to be tested on RHEL/CentOS
##sudo apt-get install cmake libcaca-dev liblua5.3-dev -y
cd /tmp
[[ ! -d "faup" ]] && $SUDO_CMD git clone https://github.com/stricaud/faup.git faup
[[ ! -d "gtcaca" ]] && $SUDO_CMD git clone https://github.com/stricaud/gtcaca.git gtcaca
sudo chown -R ${MISP_USER}:${MISP_USER} faup gtcaca
cd gtcaca
$SUDO_CMD mkdir -p build
cd build
$SUDO_CMD cmake .. && $SUDO_CMD make
sudo make install
cd ../../faup
$SUDO_CMD mkdir -p build
cd build
$SUDO_CMD cmake .. && $SUDO_CMD make
sudo make install
sudo ldconfig

# Enable dependencies detection in the diagnostics page
# This allows MISP to detect GnuPG, the Python modules' versions and to read the PHP settings.
echo "env[PATH] =/opt/rh/rh-php72/root/usr/bin:/usr/local/bin:/usr/bin:/bin" |sudo tee -a /etc/opt/rh/rh-php72/php-fpm.d/www.conf
sudo sed -i.org -e 's/^;\(clear_env = no\)/\1/' /etc/opt/rh/rh-php72/php-fpm.d/www.conf
sudo systemctl restart rh-php72-php-fpm.service

umask $UMASK
```

### 4/ CakePHP
-----------
#### CakePHP is now included as a submodule of MISP and has been fetch by a previous step.
#### Install CakeResque along with its dependencies if you intend to use the built in background jobs.
```bash
sudo chown -R ${WWW_USER}:${WWW_USER} ${PATH_TO_MISP}
sudo mkdir /usr/share/httpd/.composer
sudo chown ${WWW_USER}:${WWW_USER} /usr/share/httpd/.composer
cd ${PATH_TO_MISP}/app
# Update composer.phar (optional)
#EXPECTED_SIGNATURE="$(wget -q -O - https://composer.github.io/installer.sig)"
#${SUDO_WWW} $RUN_PHP -- php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
#${SUDO_WWW} $RUN_PHP -- php -r "if (hash_file('SHA384', 'composer-setup.php') === '$EXPECTED_SIGNATURE') { echo 'Installer verified'; } else { echo 'Installer corrupt'; unlink('composer-setup.php'); } echo PHP_EOL;"
#${SUDO_WWW} $RUN_PHP "php composer-setup.php"
#${SUDO_WWW} $RUN_PHP -- php -r "unlink('composer-setup.php');"
${SUDO_WWW} $RUN_PHP "php composer.phar install --no-dev"

sudo yum install php-redis -y
sudo systemctl restart rh-php72-php-fpm.service

# If you have not yet set a timezone in php.ini
echo 'date.timezone = "Europe/Luxembourg"' |sudo tee /etc/opt/rh/rh-php72/php.d/99-timezone.ini

# Recommended: Change some PHP settings in /etc/opt/rh/rh-php72/php.ini
# max_execution_time = 300
# memory_limit = 2048M
# upload_max_filesize = 50M
# post_max_size = 50M
for key in upload_max_filesize post_max_size max_execution_time max_input_time memory_limit
do
    sudo sed -i "s/^\($key\).*/\1 = $(eval echo \${$key})/" $PHP_INI
done
sudo sed -i "s/^\(session.sid_length\).*/\1 = $(eval echo \${session0sid_length})/" $PHP_INI
sudo sed -i "s/^\(session.use_strict_mode\).*/\1 = $(eval echo \${session0use_strict_mode})/" $PHP_INI
sudo systemctl restart rh-php72-php-fpm.service

# To use the scheduler worker for scheduled tasks, do the following:
sudo cp -fa ${PATH_TO_MISP}/INSTALL/setup/config.php ${PATH_TO_MISP}/app/Plugin/CakeResque/Config/config.php
```

### 5/ Set the permissions
----------------------
```bash
# Make sure the permissions are set correctly using the following commands as root:
sudo chown -R ${WWW_USER}:${WWW_USER} ${PATH_TO_MISP}
sudo find ${PATH_TO_MISP} -type d -exec chmod g=rx {} \;
sudo chmod -R g+r,o= ${PATH_TO_MISP}
sudo chmod -R 750 ${PATH_TO_MISP}
sudo chmod -R g+xws ${PATH_TO_MISP}/app/tmp
sudo chmod -R g+ws ${PATH_TO_MISP}/app/files
sudo chmod -R g+ws ${PATH_TO_MISP}/app/files/scripts/tmp
sudo chmod -R g+rw ${PATH_TO_MISP}/venv
sudo chmod -R g+rw ${PATH_TO_MISP}/.git
sudo chown ${WWW_USER}:${WWW_USER} ${PATH_TO_MISP}/app/files
sudo chown ${WWW_USER}:${WWW_USER} ${PATH_TO_MISP}/app/files/terms
sudo chown ${WWW_USER}:${WWW_USER} ${PATH_TO_MISP}/app/files/scripts/tmp
sudo chown ${WWW_USER}:${WWW_USER} ${PATH_TO_MISP}/app/Plugin/CakeResque/tmp
sudo chown -R ${WWW_USER}:${WWW_USER} ${PATH_TO_MISP}/app/Config
sudo chown -R ${WWW_USER}:${WWW_USER} ${PATH_TO_MISP}/app/tmp
sudo chown -R ${WWW_USER}:${WWW_USER} ${PATH_TO_MISP}/app/webroot/img/orgs
sudo chown -R ${WWW_USER}:${WWW_USER} ${PATH_TO_MISP}/app/webroot/img/custom
```

### 6/ Create a database and user
-----------------------------
```bash
# Enable, start and secure your mysql database server
sudo systemctl enable --now mariadb.service

sudo yum install expect -y

# Add your credentials if needed, if sudo has NOPASS, comment out the relevant lines
pw="Password1234"

expect -f - <<-EOF
  set timeout 10

  spawn sudo mysql_secure_installation
  expect "*?assword*"
  send -- "$pw\r"
  expect "Enter current password for root (enter for none):"
  send -- "\r"
  expect "Set root password?"
  send -- "y\r"
  expect "New password:"
  send -- "${DBPASSWORD_ADMIN}\r"
  expect "Re-enter new password:"
  send -- "${DBPASSWORD_ADMIN}\r"
  expect "Remove anonymous users?"
  send -- "y\r"
  expect "Disallow root login remotely?"
  send -- "y\r"
  expect "Remove test database and access to it?"
  send -- "y\r"
  expect "Reload privilege tables now?"
  send -- "y\r"
  expect eof
EOF

sudo yum remove tcl expect -y

# Additionally, it is probably a good idea to make the database server listen on localhost only
echo [mysqld] |sudo tee /etc/my.cnf.d/bind-address.cnf
echo bind-address=127.0.0.1 |sudo tee -a /etc/my.cnf.d/bind-address.cnf
sudo systemctl restart mariadb.service
```

#### Manual procedure:
```bash
# Enter the mysql shell
mysql -u root -p
```

```
MariaDB [(none)]> create database misp;
MariaDB [(none)]> grant usage on *.* to misp@localhost identified by 'XXXXXXXXX';
MariaDB [(none)]> grant all privileges on misp.* to misp@localhost ;
MariaDB [(none)]> exit
```

#### Same as Manual but for copy/paste foo:
```bash
sudo mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e "create database $DBNAME;"
sudo mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e "grant usage on *.* to $DBNAME@localhost identified by '$DBPASSWORD_MISP';"
sudo mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e "grant all privileges on $DBNAME.* to '$DBUSER_MISP'@'localhost';"
sudo mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e "flush privileges;"
```

#### Import the empty MySQL database from MYSQL.sql
```bash
${SUDO_WWW} cat ${PATH_TO_MISP}/INSTALL/MYSQL.sql | mysql -u $DBUSER_MISP -p$DBPASSWORD_MISP $DBNAME
```


### 7/ Apache configuration
-----------------------

!!! notice
    SELinux note, to check if it is running:
    ```bash
    $ sestatus
    SELinux status:                 disabled
    ```
    If it is disabled, you can ignore the **chcon/setsebool/semanage/checkmodule/semodule*** commands.

```bash
# Now configure your apache server with the DocumentRoot ${PATH_TO_MISP}/app/webroot/
# A sample vhost can be found in ${PATH_TO_MISP}/INSTALL/apache.misp.centos7

sudo cp ${PATH_TO_MISP}/INSTALL/apache.misp.centos7.ssl /etc/httpd/conf.d/misp.ssl.conf
sudo rm /etc/httpd/conf.d/ssl.conf
sudo chmod 644 /etc/httpd/conf.d/misp.ssl.conf
sudo sed -i '/Listen 80/a Listen 443' /etc/httpd/conf/httpd.conf

# If a valid SSL certificate is not already created for the server, create a self-signed certificate:
echo "The Common Name used below will be: ${OPENSSL_CN}"
# This will take a rather long time, be ready. (13min on a VM, 8GB Ram, 1 core)
sudo openssl dhparam -out /etc/pki/tls/certs/dhparam.pem 4096
sudo openssl genrsa -des3 -passout pass:x -out /tmp/misp.local.key 4096
sudo openssl rsa -passin pass:x -in /tmp/misp.local.key -out /etc/pki/tls/private/misp.local.key
sudo rm /tmp/misp.local.key
sudo openssl req -new -subj "/C=${OPENSSL_C}/ST=${OPENSSL_ST}/L=${OPENSSL_L}/O=${OPENSSL_O}/OU=${OPENSSL_OU}/CN=${OPENSSL_CN}/emailAddress=${OPENSSL_EMAILADDRESS}" -key /etc/pki/tls/private/misp.local.key -out /etc/pki/tls/certs/misp.local.csr
sudo openssl x509 -req -days 365 -in /etc/pki/tls/certs/misp.local.csr -signkey /etc/pki/tls/private/misp.local.key -out /etc/pki/tls/certs/misp.local.crt
sudo ln -s /etc/pki/tls/certs/misp.local.csr /etc/pki/tls/certs/misp-chain.crt
cat /etc/pki/tls/certs/dhparam.pem |sudo tee -a /etc/pki/tls/certs/misp.local.crt 

sudo systemctl restart httpd.service

# Since SELinux is enabled, we need to allow httpd to write to certain directories
sudo chcon -t bin_t ${PATH_TO_MISP}/venv/bin/*
find ${PATH_TO_MISP}/venv -type f -name "*.so*" -or -name "*.so.*" | xargs sudo chcon -t lib_t
sudo chcon -t httpd_sys_rw_content_t ${PATH_TO_MISP}/app/files
sudo chcon -t httpd_sys_rw_content_t ${PATH_TO_MISP}/app/files/terms
sudo chcon -t httpd_sys_rw_content_t ${PATH_TO_MISP}/app/files/scripts/tmp
sudo chcon -t httpd_sys_rw_content_t ${PATH_TO_MISP}/app/Plugin/CakeResque/tmp
sudo chcon -t httpd_sys_script_exec_t ${PATH_TO_MISP}/app/Console/cake
sudo chcon -t httpd_sys_script_exec_t ${PATH_TO_MISP}/app/Console/worker/*.sh
sudo chcon -t httpd_sys_script_exec_t ${PATH_TO_MISP}/app/files/scripts/*.py
sudo chcon -t httpd_sys_script_exec_t ${PATH_TO_MISP}/app/files/scripts/*/*.py
sudo chcon -t httpd_sys_script_exec_t ${PATH_TO_MISP}/app/files/scripts/lief/build/api/python/lief.so
sudo chcon -t httpd_sys_script_exec_t ${PATH_TO_MISP}/app/Vendor/pear/crypt_gpg/scripts/crypt-gpg-pinentry
# Only run these if you want to be able to update MISP from the web interface
sudo chcon -R -t httpd_sys_rw_content_t ${PATH_TO_MISP}/.git
sudo chcon -R -t httpd_sys_rw_content_t ${PATH_TO_MISP}/app/tmp
sudo chcon -R -t httpd_sys_rw_content_t ${PATH_TO_MISP}/app/Lib
sudo chcon -R -t httpd_sys_rw_content_t ${PATH_TO_MISP}/app/Config
sudo chcon -R -t httpd_sys_rw_content_t ${PATH_TO_MISP}/app/tmp
sudo chcon -R -t httpd_sys_rw_content_t ${PATH_TO_MISP}/app/webroot/img/orgs
sudo chcon -R -t httpd_sys_rw_content_t ${PATH_TO_MISP}/app/webroot/img/custom
sudo chcon -R -t httpd_sys_rw_content_t ${PATH_TO_MISP}/app/files/scripts/mispzmq
```

!!! warning
    Todo: Revise all permissions so update in Web UI works.

```bash
# Allow httpd to connect to the redis server and php-fpm over tcp/ip
sudo setsebool -P httpd_can_network_connect on

# Allow httpd to send emails from php
sudo setsebool -P httpd_can_sendmail on

# Enable and start the httpd service
sudo systemctl enable --now httpd.service

# Open a hole in the iptables firewall
sudo firewall-cmd --zone=public --add-port=80/tcp --permanent
sudo firewall-cmd --zone=public --add-port=443/tcp --permanent
sudo firewall-cmd --reload

# We seriously recommend using only HTTPS / SSL !
# Add SSL support by running: sudo yum install mod_ssl
# Check out the apache.misp.ssl file for an example
```

### 8/ Log rotation
---------------
```bash
# MISP saves the stdout and stderr of its workers in ${PATH_TO_MISP}/app/tmp/logs
# To rotate these logs install the supplied logrotate script:

sudo cp ${PATH_TO_MISP}/INSTALL/misp.logrotate /etc/logrotate.d/misp
sudo chmod 0640 /etc/logrotate.d/misp

# Now make logrotate work under SELinux as well
# Allow logrotate to modify the log files
sudo semanage fcontext -a -t httpd_log_t "${PATH_TO_MISP}/app/tmp/logs(/.*)?"
sudo chcon -R -t httpd_log_t ${PATH_TO_MISP}/app/tmp/logs

# Allow logrotate to read /var/www
sudo checkmodule -M -m -o /tmp/misplogrotate.mod ${PATH_TO_MISP}/INSTALL/misplogrotate.te
sudo semodule_package -o /tmp/misplogrotate.pp -m /tmp/misplogrotate.mod
sudo semodule -i /tmp/misplogrotate.pp
```

### 9/ MISP configuration
---------------------
```bash
# There are 4 sample configuration files in ${PATH_TO_MISP}/app/Config that need to be copied
${SUDO_WWW} cp -a ${PATH_TO_MISP}/app/Config/bootstrap.default.php ${PATH_TO_MISP}/app/Config/bootstrap.php
${SUDO_WWW} cp -a ${PATH_TO_MISP}/app/Config/database.default.php ${PATH_TO_MISP}/app/Config/database.php
${SUDO_WWW} cp -a ${PATH_TO_MISP}/app/Config/core.default.php ${PATH_TO_MISP}/app/Config/core.php
${SUDO_WWW} cp -a ${PATH_TO_MISP}/app/Config/config.default.php ${PATH_TO_MISP}/app/Config/config.php

echo "<?php
class DATABASE_CONFIG {
        public \$default = array(
                'datasource' => 'Database/Mysql',
                //'datasource' => 'Database/Postgres',
                'persistent' => false,
                'host' => '$DBHOST',
                'login' => '$DBUSER_MISP',
                'port' => 3306, // MySQL & MariaDB
                //'port' => 5432, // PostgreSQL
                'password' => '$DBPASSWORD_MISP',
                'database' => '$DBNAME',
                'prefix' => '',
                'encoding' => 'utf8',
        );
}" | ${SUDO_WWW} tee ${PATH_TO_MISP}/app/Config/database.php

# Configure the fields in the newly created files:
# config.php   : baseurl (example: 'baseurl' => 'http://misp',) - don't use "localhost" it causes issues when browsing externally
# core.php   : Uncomment and set the timezone: `// date_default_timezone_set('UTC');`
# database.php : login, port, password, database
# DATABASE_CONFIG has to be filled
# With the default values provided in section 6, this would look like:
# class DATABASE_CONFIG {
#   public $default = array(
#       'datasource' => 'Database/Mysql',
#       'persistent' => false,
#       'host' => 'localhost',
#       'login' => 'misp', // grant usage on *.* to misp@localhost
#       'port' => 3306,
#       'password' => 'XXXXdbpasswordhereXXXXX', // identified by 'XXXXdbpasswordhereXXXXX';
#       'database' => 'misp', // create database misp;
#       'prefix' => '',
#       'encoding' => 'utf8',
#   );
#}

# Important! Change the salt key in ${PATH_TO_MISP}/app/Config/config.php
# The admin user account will be generated on the first login, make sure that the salt is changed before you create that user
# If you forget to do this step, and you are still dealing with a fresh installation, just alter the salt,
# delete the user from mysql and log in again using the default admin credentials (admin@admin.test / admin)

# If you want to be able to change configuration parameters from the webinterface:
sudo chown ${WWW_USER}:${WWW_USER} ${PATH_TO_MISP}/app/Config/config.php
sudo chcon -t httpd_sys_rw_content_t ${PATH_TO_MISP}/app/Config/config.php

# Generate a GPG encryption key.
cat >/tmp/gen-key-script <<EOF
    %echo Generating a default key
    Key-Type: default
    Key-Length: $GPG_KEY_LENGTH
    Subkey-Type: default
    Name-Real: $GPG_REAL_NAME
    Name-Comment: $GPG_COMMENT
    Name-Email: $GPG_EMAIL_ADDRESS
    Expire-Date: 0
    Passphrase: $GPG_PASSPHRASE
    # Do a commit here, so that we can later print "done"
    %commit
    %echo done
EOF

sudo gpg --homedir ${PATH_TO_MISP}/.gnupg --batch --gen-key /tmp/gen-key-script
sudo rm -f /tmp/gen-key-script
sudo chown -R ${WWW_USER}:${WWW_USER} ${PATH_TO_MISP}/.gnupg

# And export the public key to the webroot
sudo gpg --homedir ${PATH_TO_MISP}/.gnupg --export --armor $GPG_EMAIL_ADDRESS |sudo tee ${PATH_TO_MISP}/app/webroot/gpg.asc
sudo chown ${WWW_USER}:${WWW_USER} ${PATH_TO_MISP}/app/webroot/gpg.asc

# Start the workers to enable background jobs
sudo chmod +x ${PATH_TO_MISP}/app/Console/worker/start.sh
${SUDO_WWW} $RUN_PHP ${PATH_TO_MISP}/app/Console/worker/start.sh

if [ ! -e /etc/rc.local ]
then
    echo '#!/bin/sh -e' | sudo tee -a /etc/rc.local
    echo 'exit 0' | sudo tee -a /etc/rc.local
    sudo chmod u+x /etc/rc.local
fi

# TODO: Fix static path with PATH_TO_MISP
sudo sed -i -e '$i \su -s /bin/bash apache -c "scl enable rh-php72 ${PATH_TO_MISP}/app/Console/worker/start.sh" > /tmp/worker_start_rc.local.log\n' /etc/rc.local
# Make sure it will execute
sudo chmod +x /etc/rc.local

echo "Admin (root) DB Password: $DBPASSWORD_ADMIN"
echo "User  (misp) DB Password: $DBPASSWORD_MISP"
```

```bash
# some misp-modules dependencies
sudo yum install openjpeg-devel -y

sudo chmod 2777 /usr/local/src
sudo chown root:users /usr/local/src
cd /usr/local/src/
${SUDO_WWW} git clone https://github.com/MISP/misp-modules.git
cd misp-modules
$SUDO_WWW git config core.filemode false
# pip install
${SUDO_WWW} ${PATH_TO_MISP}/venv/bin/pip install -I -r REQUIREMENTS
${SUDO_WWW} ${PATH_TO_MISP}/venv/bin/pip install .
sudo yum install rubygem-rouge rubygem-asciidoctor -y
##sudo gem install asciidoctor-pdf --pre

# install additional dependencies for extended object generation and extraction
${SUDO_WWW} ${PATH_TO_MISP}/venv/bin/pip install maec python-magic pathlib
${SUDO_WWW} ${PATH_TO_MISP}/venv/bin/pip install git+https://github.com/kbandla/pydeep.git

# Start misp-modules
${SUDO_WWW} ${PATH_TO_MISP}/venv/bin/misp-modules -l 0.0.0.0 -s &

# TODO: Fix static path with PATH_TO_MISP
sudo sed -i -e '$i \sudo -u apache ${PATH_TO_MISP}/venv/bin/misp-modules -l 127.0.0.1 -s &\n' /etc/rc.local
```

{% include_relative generic/misp-dashboard-rhel.md %}

{% include_relative generic/misp-dashboard-cake.md %}

{% include_relative generic/MISP_CAKE_init.md %}

{% include_relative generic/INSTALL.done.md %}

{% include_relative generic/recommended.actions.md %}

{% include_relative generic/hardening.md %}
