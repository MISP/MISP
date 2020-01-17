# INSTALLATION INSTRUCTIONS
## for Debian 9.9 "stretch"

### 0/ MISP debian stable install - Status
------------------------------------

!!! notice
    Please use [Debian 10](https://misp.github.io/MISP/xINSTALL.debian10/) as everything works as expected.


!!! notice
    Maintained and tested by @SteveClement on 20190702

!!! warning
    This install document is compiles a custom Python 3.7 meaning some things might be unexpected.
    Debian stretch has Python 3.5 but we need at least python 3.6


### 1/ Minimal Debian install
-------------------------

#### Install a minimal Debian 9.9 "stretch" server system with the software:
- OpenSSH server
- This guide assumes a user name of 'misp' with sudo working

{!generic/known-issues-debian.md!}

{!generic/globalVariables.md!}

```bash
PHP_ETC_BASE=/etc/php/7.0
PHP_INI=${PHP_ETC_BASE}/apache2/php.ini

sudo adduser $MISP_USER staff
sudo adduser $MISP_USER $WWW_USER
```

{!generic/sudo_etckeeper.md!}

{!generic/ethX.md!}

#### Make sure your system is up2date
```bash
sudo apt update
sudo apt dist-upgrade -y
```

#### install postfix, there will be some questions. (optional)
```bash
# Postfix Configuration: Satellite system
sudo apt install -y postfix
```

```bash
# change the relay server later with:
sudo postconf -e 'relayhost = example.com'
sudo postfix reload
```

### 2/ Install LAMP & dependencies
------------------------------

#### Install all the dependencies (some might already be installed)

You need to use at least Python3.6 for [PyMISP](https://github.com/MISP/PyMISP) to work properly.

```bash
# Manual Python3.7.3 install in $HOME
sudo apt-get install -y make build-essential libssl-dev zlib1g-dev libbz2-dev \
libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libncursesw5-dev \
xz-utils tk-dev libffi-dev liblzma-dev -qqy
mkdir -p ~/opt/python3
cd /tmp
wget https://www.python.org/ftp/python/3.7.3/Python-3.7.3.tar.xz
tar xvfJ Python-3.7.3.tar.xz
rm Python-3.7.3.tar.xz
cd Python-3.7.3
# --enable-optimizations will run tests to optimize the resulting python binary, this takes time and is expected
./configure --enable-optimizations --with-ensurepip=install --prefix="$HOME"/opt/python3
make -j3
make altinstall
sudo apt install virtualenv -qqy
```

```bash
sudo apt install \
curl gcc git gnupg-agent make openssl redis-server vim zip libyara-dev \
apache2 apache2-doc apache2-utils \
libpq5 libjpeg-dev libfuzzy-dev ruby asciidoctor \
jq ntp ntpdate imagemagick tesseract-ocr \
libxml2-dev libxslt1-dev zlib1g-dev \
net-tools -qqy

sudo apt install libapache2-mod-php php php-cli php-mbstring php-dev php-json php-xml php-mysql php7.0-opcache php-readline php-redis php-gnupg php-gd -qqy

sudo apt install \
mariadb-client \
mariadb-server -qqy

# Just a quick test if mysql-server restarts without problems
sudo /etc/init.d/mysql restart

# Start haveged to get more entropy (optional)
sudo apt install haveged -qqy
sudo service haveged start

sudo apt install expect -qqy

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
sudo apt purge -qqy expect ; sudo apt autoremove -qqy

# Enable modules, settings, and default of SSL in Apache
sudo a2dismod status
sudo a2enmod ssl rewrite headers
sudo a2dissite 000-default
sudo a2ensite default-ssl
```

#### Apply all changes
```bash
sudo systemctl restart apache2
```

### 3/ MISP code
------------
```bash
# Download MISP using git in the /var/www/ directory.
sudo mkdir $PATH_TO_MISP
sudo chown $WWW_USER:$WWW_USER $PATH_TO_MISP
cd $PATH_TO_MISP
$SUDO_WWW git clone https://github.com/MISP/MISP.git $PATH_TO_MISP
$SUDO_WWW git submodule update --init --recursive
# Make git ignore filesystem permission differences for submodules
$SUDO_WWW git submodule foreach --recursive git config core.filemode false

# Make git ignore filesystem permission differences
$SUDO_WWW git config core.filemode false

# Create a python3 virtualenv
$SUDO_WWW virtualenv -p ~/opt/python3/bin/python3.7 ${PATH_TO_MISP}/venv

# make pip happy
sudo mkdir /var/www/.cache/
sudo chown $WWW_USER:$WWW_USER /var/www/.cache

cd $PATH_TO_MISP/app/files/scripts
$SUDO_WWW git clone https://github.com/CybOXProject/python-cybox.git
$SUDO_WWW git clone https://github.com/STIXProject/python-stix.git
$SUDO_WWW git clone https://github.com/MAECProject/python-maec.git
# install mixbox to accommodate the new STIX dependencies:
$SUDO_WWW git clone https://github.com/CybOXProject/mixbox.git
cd $PATH_TO_MISP/app/files/scripts/mixbox
$SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install .
cd $PATH_TO_MISP/app/files/scripts/python-cybox
$SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install .
cd $PATH_TO_MISP/app/files/scripts/python-stix
$SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install .
cd $PATH_TO_MISP/app/files/scripts/python-maec
$SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install .
# install STIX2.0 library to support STIX 2.0 export:
cd ${PATH_TO_MISP}/cti-python-stix2
$SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install .

# install PyMISP
cd $PATH_TO_MISP/PyMISP
$SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install .

# install pydeep
$SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install git+https://github.com/kbandla/pydeep.git

# install lief
$SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install https://github.com/lief-project/packages/raw/lief-master-latest/pylief-0.9.0.dev.zip

# install zmq needed by mispzmq
$SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install zmq redis

# install python-magic
$SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install python-magic

# install plyara
$SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install plyara
```

### 4/ CakePHP
-----------
#### CakePHP is included as a submodule of MISP.

```bash
# Install CakeResque along with its dependencies if you intend to use the built in background jobs:
cd $PATH_TO_MISP/app
# Make composer cache happy
sudo mkdir /var/www/.composer ; sudo chown $WWW_USER:$WWW_USER /var/www/.composer
# Update composer.phar
#EXPECTED_SIGNATURE="$(wget -q -O - https://composer.github.io/installer.sig)"
# $SUDO_WWW php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
# $SUDO_WWW php -r "if (hash_file('SHA384', 'composer-setup.php') === '$EXPECTED_SIGNATURE') { echo 'Installer verified'; } else { echo 'Installer corrupt'; unlink('composer-setup.php'); } echo PHP_EOL;"
# $SUDO_WWW php composer-setup.php
# $SUDO_WWW php -r "unlink('composer-setup.php');"
$SUDO_WWW php composer.phar install

# Enable CakeResque with php-redis
sudo phpenmod redis
sudo phpenmod gnupg

# To use the scheduler worker for scheduled tasks, do the following:
$SUDO_WWW cp -fa $PATH_TO_MISP/INSTALL/setup/config.php $PATH_TO_MISP/app/Plugin/CakeResque/Config/config.php
```


### 5/ Set the permissions
----------------------

```bash
# Check if the permissions are set correctly using the following commands:
sudo chown -R $WWW_USER:$WWW_USER $PATH_TO_MISP
sudo chmod -R 750 $PATH_TO_MISP
sudo chmod -R g+ws $PATH_TO_MISP/app/tmp
sudo chmod -R g+ws $PATH_TO_MISP/app/files
sudo chmod -R g+ws $PATH_TO_MISP/app/files/scripts/tmp
```


### 6/ Create a database and user
-----------------------------
#### Enter the mysql shell
```bash
sudo mysql -u root -p
```

```
MariaDB [(none)]> create database misp;
MariaDB [(none)]> grant usage on *.* to misp@localhost identified by 'XXXXdbpasswordhereXXXXX';
MariaDB [(none)]> grant all privileges on misp.* to misp@localhost;
MariaDB [(none)]> flush privileges;
MariaDB [(none)]> exit
```

#### copy/paste:
```bash
sudo mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e "create database $DBNAME;"
sudo mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e "grant usage on *.* to $DBNAME@localhost identified by '$DBPASSWORD_MISP';"
sudo mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e "grant all privileges on $DBNAME.* to '$DBUSER_MISP'@'localhost';"
sudo mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e "flush privileges;"
```

#### Import the empty MISP database from MYSQL.sql
```bash
$SUDO_WWW cat $PATH_TO_MISP/INSTALL/MYSQL.sql | mysql -u $DBUSER_MISP -p$DBPASSWORD_MISP $DBNAME
```

### 7/ Apache configuration
-----------------------
```bash
# Now configure your Apache webserver with the DocumentRoot $PATH_TO_MISP/app/webroot/

# If the apache version is 2.4:
sudo cp $PATH_TO_MISP/INSTALL/apache.24.misp.ssl /etc/apache2/sites-available/misp-ssl.conf

# Be aware that the configuration files for apache 2.4 and up have changed.
# The configuration file has to have the .conf extension in the sites-available directory
# For more information, visit http://httpd.apache.org/docs/2.4/upgrading.html

# If a valid SSL certificate is not already created for the server, create a self-signed certificate:
sudo openssl req -newkey rsa:4096 -days 365 -nodes -x509 \
-subj "/C=${OPENSSL_C}/ST=${OPENSSL_ST}/L=${OPENSSL_L}/O=${OPENSSL_O}/OU=${OPENSSL_OU}/CN=${OPENSSL_CN}/emailAddress=${OPENSSL_EMAILADDRESS}" \
-keyout /etc/ssl/private/misp.local.key -out /etc/ssl/private/misp.local.crt

# Otherwise, copy the SSLCertificateFile, SSLCertificateKeyFile, and SSLCertificateChainFile to /etc/ssl/private/. (Modify path and config to fit your environment)
```

```
============================================= Begin sample working SSL config for MISP
<VirtualHost _default_:80>
        ServerAdmin admin@<your.FQDN.here>
        ServerName <your.FQDN.here>

        Redirect permanent / https://<your.FQDN.here>

        LogLevel warn
        ErrorLog /var/log/apache2/misp.local_error.log
        CustomLog /var/log/apache2/misp.local_access.log combined
        ServerSignature Off
</VirtualHost>

<VirtualHost _default_:443>
        ServerAdmin admin@<your.FQDN.here>
        ServerName <your.FQDN.here>
        DocumentRoot $PATH_TO_MISP/app/webroot
        <Directory $PATH_TO_MISP/app/webroot>
                Options -Indexes
                AllowOverride all
                Require all granted
                Order allow,deny
                allow from all
        </Directory>

        SSLEngine On
        SSLCertificateFile /etc/ssl/private/misp.local.crt
        SSLCertificateKeyFile /etc/ssl/private/misp.local.key
#        SSLCertificateChainFile /etc/ssl/private/misp-chain.crt

        LogLevel warn
        ErrorLog /var/log/apache2/misp.local_error.log
        CustomLog /var/log/apache2/misp.local_access.log combined
        ServerSignature Off
</VirtualHost>
============================================= End sample working SSL config for MISP
```

```bash
# activate new vhost
sudo a2dissite default-ssl
sudo a2ensite misp-ssl

# Recommended: Change some PHP settings in /etc/php/7.3/apache2/php.ini
# max_execution_time = 300
# memory_limit = 2048M
# upload_max_filesize = 50M
# post_max_size = 50M
for key in upload_max_filesize post_max_size max_execution_time max_input_time memory_limit
do
    sudo sed -i "s/^\($key\).*/\1 = $(eval echo \${$key})/" $PHP_INI
done

# Restart apache
sudo systemctl restart apache2
```

### 8/ Log rotation
---------------
```bash
# MISP saves the stdout and stderr of its workers in $PATH_TO_MISP/app/tmp/logs
# To rotate these logs install the supplied logrotate script:

sudo cp $PATH_TO_MISP/INSTALL/misp.logrotate /etc/logrotate.d/misp
sudo chmod 0640 /etc/logrotate.d/misp
```

### 9/ MISP configuration
---------------------
```bash
# There are 4 sample configuration files in $PATH_TO_MISP/app/Config that need to be copied
$SUDO_WWW cp -a $PATH_TO_MISP/app/Config/bootstrap.default.php $PATH_TO_MISP/app/Config/bootstrap.php
$SUDO_WWW cp -a $PATH_TO_MISP/app/Config/database.default.php $PATH_TO_MISP/app/Config/database.php
$SUDO_WWW cp -a $PATH_TO_MISP/app/Config/core.default.php $PATH_TO_MISP/app/Config/core.php
$SUDO_WWW cp -a $PATH_TO_MISP/app/Config/config.default.php $PATH_TO_MISP/app/Config/config.php


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
}" | $SUDO_WWW tee $PATH_TO_MISP/app/Config/database.php

# and make sure the file permissions are still OK
sudo chown -R $WWW_USER:$WWW_USER $PATH_TO_MISP/app/Config
sudo chmod -R 750 $PATH_TO_MISP/app/Config

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

$SUDO_WWW gpg --homedir $PATH_TO_MISP/.gnupg --batch --gen-key /tmp/gen-key-script
# The email address should match the one set in the config.php / set in the configuration menu in the administration menu configuration file

# And export the public key to the webroot
$SUDO_WWW sh -c "gpg --homedir $PATH_TO_MISP/.gnupg --export --armor $GPG_EMAIL_ADDRESS" | $SUDO_WWW tee $PATH_TO_MISP/app/webroot/gpg.asc

# To make the background workers start on boot
sudo chmod +x $PATH_TO_MISP/app/Console/worker/start.sh

echo "[Unit]
Description=MISP background workers
After=mariadb.service redis-server.service

[Service]
Type=forking
User=$WWW_USER
Group=$WWW_USER
ExecStart=$PATH_TO_MISP/app/Console/worker/start.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target" |sudo tee /etc/systemd/system/misp-workers.service
sudo systemctl daemon-reload
sudo systemctl enable --now misp-workers.service

if [ ! -e /etc/rc.local ]
then
    echo '#!/bin/sh -e' | sudo tee -a /etc/rc.local
    echo 'exit 0' | sudo tee -a /etc/rc.local
    sudo chmod u+x /etc/rc.local
fi
```
{!generic/MISP_CAKE_init.md!}

```bash
# Add the following lines before the last line (exit 0). Make sure that you replace $WWW_USER with your apache user:
sudo sed -i -e '$i \echo never > /sys/kernel/mm/transparent_hugepage/enabled\n' /etc/rc.local
sudo sed -i -e '$i \echo 1024 > /proc/sys/net/core/somaxconn\n' /etc/rc.local
sudo sed -i -e '$i \sysctl vm.overcommit_memory=1\n' /etc/rc.local
```

{!generic/misp-modules-debian.md!}

```bash
echo "Admin (root) DB Password: $DBPASSWORD_ADMIN"
echo "User  (misp) DB Password: $DBPASSWORD_MISP"
```

{!generic/INSTALL.done.md!}

{!generic/recommended.actions.md!}

### Optional features
-------------------
!!! note
    You can add the following to your shell startup rc scripts to have the *cake* and *viper-cli* commands in your $PATH
    ```bash
    # set PATH so it includes viper if it exists
    if [ -d "/usr/local/src/viper" ] ; then
        PATH="$PATH:/usr/local/src/viper"
    fi

    # set PATH so it includes viper if it exists
    if [ -d "/var/www/MISP/app/Console" ] ; then
        PATH="$PATH:/var/www/MISP/app/Console"
    fi
    ```

#### MISP has a new pub/sub feature, using ZeroMQ. To enable it, simply run the following commands

```bash
$SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install pyzmq
```

#### MISP has a feature for publishing events to Kafka. To enable it, simply run the following commands
```bash
sudo apt install librdkafka-dev php-dev
sudo pecl channel-update pecl.php.net
sudo pecl install rdkafka
echo "extension=rdkafka.so" | sudo tee ${PHP_ETC_BASE}/mods-available/rdkafka.ini
sudo phpenmod rdkafka
sudo service apache2 restart
```

{!generic/misp-dashboard-debian.md!}

{!generic/viper-debian.md!}

{!generic/ssdeep-debian.md!}

{!generic/mail_to_misp-debian.md!}

{!generic/upgrading.md!}

{!generic/hardening.md!}
