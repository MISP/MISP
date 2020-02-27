# INSTALLATION INSTRUCTIONS
## for FreeBSD 12.0-amd64

### 0/ WIP /!\ You are warned, this does not work yet! /!\

!!! warning
    NOT working: pydeep, lief

{!generic/globalVariables.md!}

```bash
PHP_ETC_BASE=/usr/local/etc
PHP_INI=${PHP_ETC_BASE}/php.ini
PATH_TO_MISP=/usr/local/www/MISP
CAKE="$PATH_TO_MISP/app/Console/cake"
```

### 1/ Minimal FreeBSD install
--------------------------

# Install standard FreeBSD-amd64 with:
- sshd
- ntpdate
- ntpd
- ports

# System Hardening

- Clean /tmp
- Disable Syslogd network socket
- Disable Sendmail service

# Install pkg and point to latest
```bash
$ su -
# pkg
```

#### Install sudo
```bash
pkg install -y sudo
```

!!! notice
    Make sure users in group wheel can sudo, uncomment in **/usr/local/etc/sudoers**<br />
    ```
    %wheel ALL=(ALL) ALL
    ```

#### Install bash
```bash
sudo pkg install -y bash
```

#### Optional but useful, add a local misp user
```bash
sudo pw user add misp -s /usr/local/bin/bash -G wheel,www,staff
sudo mkdir /home/misp ; sudo chown misp:misp /home/misp
sudo passwd misp
```

```bash
# In case you already have a MISP User
sudo pw usermod misp -s /usr/local/bin/bash
sudo pw groupmod -n www -m misp
sudo pw groupmod -n staff -m misp
exit
```

#### Update system
```bash
sudo freebsd-update fetch install
```

#### Fetch ports or update ports
```bash
sudo portsnap fetch extract
# OR
sudo portsnap fetch update
```

#### Make python3 default *(optional)
```bash
echo "DEFAULT_VERSIONS= python=3.6 python2=2.7 python3=3.6" >> /etc/make.conf
sudo ln -s /usr/local/bin/python3 /usr/local/bin/python
```

#### Install postfix
```bash
sudo pkg install -y postfix
```

### FAMP
#### Install misc dependencies
```bash
sudo pkg install -y curl git python3 vim m4 help2man gmake automake libtool expect gsed
```

!!! warning
    N.B: MariaDB 10.3 currently segfaults on 11.2: https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=229219

```bash
sudo pkg install -y apache24 \
    logrotate \
    gnupg \
    mariadb102-server mariadb102-client \
    php72 \
    php72-mysqli \
    php72-xml \
    php72-openssl \
    php72-pcntl \
    php72-mbstring \
    php72-pdo_mysql \
    php72-phar \
    php72-json \
    php72-filter \
    php72-fileinfo \
    php72-dom \
    php72-opcache \
    php72-session \
    mod_php72

sudo cp -p /usr/local/etc/php.ini-development /usr/local/etc/php.ini

sudo sysrc apache24_enable="yes"
sudo sysrc mysql_enable="yes"
sudo sysrc mysql_args="--bind-address=127.0.0.1"
sudo service apache24 start
sudo service mysql-server start


### /!\ Needs Fixing /!\
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

sudo pkg remove -R tcl86

echo "<IfModule dir_module>
    DirectoryIndex index.php index.html

    <FilesMatch "\.php$">
        SetHandler application/x-httpd-php
    </FilesMatch>

    <FilesMatch "\.phps$">
        SetHandler application/x-httpd-php-source
    </FilesMatch>
</IfModule>" |sudo tee -a /usr/local/etc/apache24/Includes/php.conf
```

#### Redis needs to be installed via ports

```
cd /usr/ports/databases/redis
sudo make install clean
sudo sysrc redis_enable="yes"
```

##### php-redis
```
cd /usr/ports/databases/pecl-redis
sudo make install clean
```

##### php-gnupg
```
cd /usr/ports/security/pecl-gnupg
sudo make install clean
```

#### PHP CLI Tweak
```bash
echo "PATH=$PATH:/usr/local/bin" |sudo tee -a /usr/local/etc/apache24/envvars.d/php.env

sudo service apache24 restart
```

### 3/ MISP code
------------

```bash
# Download MISP using git in the /usr/local/www/ directory.
sudo mkdir ${PATH_TO_MISP}
sudo chown www:www ${PATH_TO_MISP}
cd ${PATH_TO_MISP}
sudo -u www git clone https://github.com/MISP/MISP.git ${PATH_TO_MISP}

# Make git ignore filesystem permission differences
sudo -u www git config core.filemode false

sudo -u www git submodule update --init --recursive
# Make git ignore filesystem permission differences for submodules
sudo -u www git submodule foreach --recursive git config core.filemode false

# install Mitre's STIX and its dependencies by running the following commands:
sudo pkg install -y py36-pip libxml2 libxslt

# Install virtualenv
sudo pip-3.6 install virtualenv

# Create a python3 virtualenv
sudo -u www virtualenv -p python3 ${PATH_TO_MISP}/venv

cd ${PATH_TO_MISP}/app/files/scripts
sudo -u www git clone https://github.com/CybOXProject/python-cybox.git
sudo -u www git clone https://github.com/STIXProject/python-stix.git
sudo -u www git clone https://github.com/MAECProject/python-maec.git
# install mixbox to accommodate the new STIX dependencies:
sudo -u www git clone https://github.com/CybOXProject/mixbox.git
cd ${PATH_TO_MISP}/app/files/scripts/mixbox
sudo -H -u www ${PATH_TO_MISP}/venv/bin/pip install .
cd ${PATH_TO_MISP}/app/files/scripts/python-cybox
sudo -H -u www ${PATH_TO_MISP}/venv/bin/pip install .
cd ${PATH_TO_MISP}/app/files/scripts/python-stix
sudo -H -u www ${PATH_TO_MISP}/venv/bin/pip install .

# install PyMISP
cd ${PATH_TO_MISP}/PyMISP
sudo -H -u www ${PATH_TO_MISP}/venv/bin/pip install .

```


### 4/ CakePHP
-----------
```bash
# Install CakeResque along with its dependencies if you intend to use the built in background jobs:
cd ${PATH_TO_MISP}/app
sudo -u www php composer.phar install

# To use the scheduler worker for scheduled tasks, do the following:
sudo -u www cp -fa /usr/local/www/MISP/INSTALL/setup/config.php /usr/local/www/MISP/app/Plugin/CakeResque/Config/config.php
```

### 5/ Set the permissions
----------------------

```
# Check if the permissions are set correctly using the following commands:
sudo chown -R www:www /usr/local/www/MISP
sudo chmod -R 750 /usr/local/www/MISP
sudo chmod -R g+ws /usr/local/www/MISP/app/tmp
sudo chmod -R g+ws /usr/local/www/MISP/app/files
sudo chmod -R g+ws /usr/local/www/MISP/app/files/scripts/tmp
```

### 6/ Create a database and user
-----------------------------
```
# Enter the mysql shell
sudo mysql -u root -p

MariaDB [(none)]> create database misp;
MariaDB [(none)]> grant usage on *.* to misp@localhost identified by 'XXXXdbpasswordhereXXXXX';
MariaDB [(none)]> grant all privileges on misp.* to misp@localhost;
MariaDB [(none)]> flush privileges;
MariaDB [(none)]> exit
```

#### copy/paste

```
sudo mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e "create database $DBNAME;"
sudo mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e "grant usage on *.* to $DBNAME@localhost identified by '$DBPASSWORD_MISP';"
sudo mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e "grant all privileges on $DBNAME.* to '$DBUSER_MISP'@'localhost';"
sudo mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e "flush privileges;"
```

```bash
# Import the empty MISP database from MYSQL.sql
sudo -u www cat $PATH_TO_MISP/INSTALL/MYSQL.sql | mysql -u $DBUSER_MISP -p$DBPASSWORD_MISP $DBNAME
```

### 7/ Apache configuration
-----------------------
```bash
# Now configure your Apache webserver with the DocumentRoot /usr/local/www/MISP/app/webroot/

#2.4
sudo mkdir /usr/local/etc/apache24/sites-available/ /usr/local/etc/apache24/sites-enabled/

# If the apache version is 2.4:
sudo cp /usr/local/www/MISP/INSTALL/apache.24.misp.ssl /usr/local/etc/apache24/sites-available/misp-ssl.conf

# Be aware that the configuration files for apache 2.4 and up have changed.
# The configuration file has to have the .conf extension in the sites-available directory
# For more information, visit http://httpd.apache.org/docs/2.4/upgrading.html

sudo mkdir /etc/ssl/private/
# If a valid SSL certificate is not already created for the server, create a self-signed certificate: (Make sure to fill the <…>)
sudo openssl req -newkey rsa:4096 -days 365 -nodes -x509 \
-subj "/C=${OPENSSL_C}/ST=${OPENSSL_ST}/L=${OPENSSL_L}/O=${OPENSSL_O}/OU=${OPENSSL_OU}/CN=${OPENSSL_CN}/emailAddress=${OPENSSL_EMAILADDRESS}" \
-keyout /etc/ssl/private/misp.local.key -out /etc/ssl/private/misp.local.crt

sudo chmod 750 /etc/ssl/private/
sudo chmod 640 /etc/ssl/private/*

# Otherwise, copy the SSLCertificateFile, SSLCertificateKeyFile, and SSLCertificateChainFile to /etc/ssl/private/. (Modify path and config to fit your environment)

sudo mkdir /var/log/apache24/

sudo gsed -i "s/apache2/apache24/" /usr/local/etc/apache24/sites-available/misp-ssl.conf
sudo gsed -i "s/var\/www/usr\/local\/www/" /usr/local/etc/apache24/sites-available/misp-ssl.conf
sudo gsed -i "s/SSLCertificateChainFile/#SSLCertificateChainFile/" /usr/local/etc/apache24/sites-available/misp-ssl.conf

# activate new vhost
cd /usr/local/etc/apache24/sites-enabled/
sudo ln -s ../sites-available/misp-ssl.conf
echo "Include etc/apache24/sites-enabled/*.conf" |sudo tee -a /usr/local/etc/apache24/httpd.conf
echo "IncludeOptional etc/apache24/sites-enabled/*.conf" |sudo tee -a /usr/local/etc/apache24/httpd.conf

for key in upload_max_filesize post_max_size max_execution_time max_input_time memory_limit
do
    sudo gsed -i "s/^\($key\).*/\1 = $(eval echo \${$key})/" $PHP_INI
done

sudo gsed -i "s/#LoadModule rewrite_module libexec\/apache24\/mod_rewrite.so/LoadModule rewrite_module libexec\/apache24\/mod_rewrite.so/" /usr/local/etc/apache24/httpd.conf
sudo gsed -i "s/#LoadModule ssl_module libexec\/apache24\/mod_ssl.so/LoadModule ssl_module libexec\/apache24\/mod_ssl.so/" /usr/local/etc/apache24/httpd.conf
sudo gsed -i "s/Listen 80/Listen 80\nListen 443/" /usr/local/etc/apache24/httpd.conf

# Restart apache
sudo service apache24 restart
```

### 8/ Log rotation
---------------
```bash
# MISP saves the stdout and stderr of its workers in /usr/local/www/MISP/app/tmp/logs
# To rotate these logs install the supplied logrotate script:
sudo cp /usr/local/www/MISP/INSTALL/misp.logrotate /usr/local/etc/logrotate.d/misp
sudo chmod 0640 /usr/local/etc/logrotate.d/misp
```

### 9/ MISP configuration
---------------------
```bash
# There are 4 sample configuration files in /usr/local/www/MISP/app/Config that need to be copied
sudo -u www cp -a /usr/local/www/MISP/app/Config/bootstrap.default.php /usr/local/www/MISP/app/Config/bootstrap.php
sudo -u www cp -a /usr/local/www/MISP/app/Config/database.default.php /usr/local/www/MISP/app/Config/database.php
sudo -u www cp -a /usr/local/www/MISP/app/Config/core.default.php /usr/local/www/MISP/app/Config/core.php
sudo -u www cp -a /usr/local/www/MISP/app/Config/config.default.php /usr/local/www/MISP/app/Config/config.php

# Configure the fields in the newly created files:


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
}" | sudo -u www tee $PATH_TO_MISP/app/Config/database.php

# Important! Change the salt key in /usr/local/www/MISP/app/Config/config.php
# The salt key must be a string at least 32 bytes long.
# The admin user account will be generated on the first login, make sure that the salt is changed before you create that user
# If you forget to do this step, and you are still dealing with a fresh installation, just alter the salt,
# delete the user from mysql and log in again using the default admin credentials (admin@admin.test / admin)

# Change base url in config.php
# example: 'baseurl' => 'https://<your.FQDN.here>',
# alternatively, you can leave this field empty if you would like to use relative pathing in MISP
# 'baseurl' => '',

# and make sure the file permissions are still OK
sudo chown -R www:www /usr/local/www/MISP/app/Config
sudo chmod -R 750 /usr/local/www/MISP/app/Config

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

sudo -u www gpg --homedir $PATH_TO_MISP/.gnupg --batch --gen-key /tmp/gen-key-script
# The email address should match the one set in the config.php / set in the configuration menu in the administration menu configuration file

# And export the public key to the webroot
sudo -u www sh -c "gpg --homedir $PATH_TO_MISP/.gnupg --export --armor $GPG_EMAIL_ADDRESS" | sudo -u www tee $PATH_TO_MISP/app/webroot/gpg.asc

# To make the background workers start on boot
sudo chmod +x /usr/local/www/MISP/app/Console/worker/start.sh

if [ ! -e /etc/rc.local ]
then
    echo '#!/bin/sh -e' | sudo tee -a /etc/rc.local
    echo 'exit 0' | sudo tee -a /etc/rc.local
    sudo chmod u+x /etc/rc.local
fi
```

{!generic/MISP_CAKE_init.md!}

```bash
sudo gsed -i -e '$i \sudo -u www bash /usr/local/www/MISP/app/Console/worker/start.sh > /tmp/worker_start_rc.local.log\n' /etc/rc.local
sudo gsed -i -e '$i \sudo -u www /usr/local/www/MISP/venv/bin/misp-modules -l 127.0.0.1 -s > /tmp/misp-modules_rc.local.log 2> /dev/null &\n' /etc/rc.local
```

### 10/ MISP modules

```bash
sudo pkg install -y yara
sudo mkdir /usr/local/src
sudo chmod 2775 /usr/local/src
sudo chown root:staff /usr/local/src
cd /usr/local/src/
git clone https://github.com/MISP/misp-modules.git
cd misp-modules
# lief broken...
sudo -H -u www ${PATH_TO_MISP}/venv/bin/pip install maec python-magic
sudo -H -u www ${PATH_TO_MISP}/venv/bin/pip install -I -r REQUIREMENTS
sudo -H -u www ${PATH_TO_MISP}/venv/bin/pip install .
##sudo pip-3.6 install git+https://github.com/kbandla/pydeep.git

# install STIX2.0 library to support STIX 2.0 export:
sudo -H -u www ${PATH_TO_MISP}/venv/bin/pip install stix2
```

{!generic/INSTALL.done.md!}

{!generic/recommended.actions.md!}

### Optional features
-----------------
#### MISP has a new pub/sub feature, using ZeroMQ. To enable it, simply run the following command
```bash
sudo pkg install -y libzmq4
sudo -H -u www ${PATH_TO_MISP}/venv/bin/pip install pyzmq
```

#### misp-dashboard  (NOT WORKING)

!!! notice
    Enable ZeroMQ for misp-dashboard

!!! warning
    This is not working, still needs a working WSGI config.


!!! warning
    The install_dependencies.sh script is for Linux ONLY. The following blurp will be a diff of a working OpenBSD version.

```diff
(DASHENV) fbsd# diff -u install_dependencies.sh install_dependencies_fbsd.sh
diff --git a/install_dependencies.sh b/install_dependencies.sh
index ca10fc0..bd5d415 100755
--- a/install_dependencies.sh
+++ b/install_dependencies.sh
@@ -1,9 +1,9 @@
-#!/bin/bash
+#!/usr/local/bin/bash
 
 set -e
 #set -x
 
-sudo apt-get install python3-virtualenv virtualenv screen redis-server unzip -y
+pkg install -y unzip wget screen
 
 if [ -z "$VIRTUAL_ENV" ]; then
     virtualenv -p python3 DASHENV
@@ -25,8 +25,8 @@ if [ -e "config/config.cfg" ]; then
 else
     cp -i config/config.cfg.default config/config.cfg
     echo "Sanitizing MaxMindDB Path"
-    sed -i "s|pathMaxMindDB=./data/GeoLite2-City/GeoLite2-City.mmdb|pathMaxMindDB=$PWD/data/GeoLite2-City/GeoLite2-City.mmdb|" config/config.cfg
-    sed -i "s|path_countrycode_to_coord_JSON=./data/country_code_lat_long.json|path_countrycode_to_coord_JSON=$PWD/data/country_code_lat_long.json|" config/config.cfg
+    gsed -i "s|pathMaxMindDB=./data/GeoLite2-City/GeoLite2-City.mmdb|pathMaxMindDB=$PWD/data/GeoLite2-City/GeoLite2-City.mmdb|" config/config.cfg
+    gsed -i "s|path_countrycode_to_coord_JSON=./data/country_code_lat_long.json|path_countrycode_to_coord_JSON=$PWD/data/country_code_lat_long.json|" config/config.cfg
 fi
 
 ## Web stuff
```

```
cd /usr/local/www
sudo mkdir misp-dashboard
sudo chown www:www misp-dashboard
sudo -u www git clone https://github.com/MISP/misp-dashboard.git
cd misp-dashboard
#/!\ Made on Linux, the next script will fail
#sudo /usr/local/www/misp-dashboard/install_dependencies.sh
sudo virtualenv -ppython3 /usr/local/www/misp-dashboard/DASHENV
sudo chown -R www DASHENV/
sudo -u www /usr/local/www/misp-dashboard/DASHENV/bin/pip install -U pip argparse redis zmq geoip2 flask phonenumbers pycountry

sudo gsed -i "s/^host\ =\ localhost/host\ =\ 0.0.0.0/g" /usr/local/www/misp-dashboard/config/config.cfg
sudo gsed -i -e '$i \sudo -u www bash /usr/local/www/misp-dashboard/start_all.sh\n' /etc/rc.local
#/!\ Add port 8001 as a listener
#sudo sed -i '/Listen 80/a Listen 0.0.0.0:8001' /etc/apache2/ports.conf
sudo pkg install -y ap24-py36-mod_wsgi

echo "<VirtualHost *:8001>
    ServerAdmin admin@misp.local
    ServerName misp.local
    DocumentRoot /usr/local/www/misp-dashboard
    
    WSGIDaemonProcess misp-dashboard \
       user=misp group=misp \
       python-home=/usr/local/www/misp-dashboard/DASHENV \
       processes=1 \
       threads=15 \
       maximum-requests=5000 \
       listen-backlog=100 \
       queue-timeout=45 \
       socket-timeout=60 \
       connect-timeout=15 \
       request-timeout=60 \
       inactivity-timeout=0 \
       deadlock-timeout=60 \
       graceful-timeout=15 \
       eviction-timeout=0 \
       shutdown-timeout=5 \
       send-buffer-size=0 \
       receive-buffer-size=0 \
       header-buffer-size=0 \
       response-buffer-size=0 \
       server-metrics=Off
    WSGIScriptAlias / /usr/local/www/misp-dashboard/misp-dashboard.wsgi
    <Directory /usr/local/www/misp-dashboard>
        WSGIProcessGroup misp-dashboard
        WSGIApplicationGroup %{GLOBAL}
        Require all granted
    </Directory>
    LogLevel info
    ErrorLog /usr/local/log/apache2/misp-dashboard.local_error.log
    CustomLog /usr/local/log/apache2/misp-dashboard.local_access.log combined
    ServerSignature Off
</VirtualHost>" | sudo tee /usr/local/etc/apache24/sites-available/misp-dashboard.conf

sudo ln -s /usr/local/etc/apache24/sites-available/misp-dashboard.conf /usr/local/etc/apache24/sites-enabled/misp-dashboard.conf
```

Add this to /etc/httpd2.conf
```
LoadModule wsgi_module /usr/local/lib/apache2/mod_wsgi.so
Listen 8001
```


```
sudo $CAKE Admin setSetting "Plugin.ZeroMQ_enable" true
sudo $CAKE Admin setSetting "Plugin.ZeroMQ_event_notifications_enable" true
sudo $CAKE Admin setSetting "Plugin.ZeroMQ_object_notifications_enable" true
sudo $CAKE Admin setSetting "Plugin.ZeroMQ_object_reference_notifications_enable" true
sudo $CAKE Admin setSetting "Plugin.ZeroMQ_attribute_notifications_enable" true
sudo $CAKE Admin setSetting "Plugin.ZeroMQ_sighting_notifications_enable" true
sudo $CAKE Admin setSetting "Plugin.ZeroMQ_user_notifications_enable" true
sudo $CAKE Admin setSetting "Plugin.ZeroMQ_organisation_notifications_enable" true
sudo $CAKE Admin setSetting "Plugin.ZeroMQ_port" 50000
sudo $CAKE Admin setSetting "Plugin.ZeroMQ_redis_host" "localhost"
sudo $CAKE Admin setSetting "Plugin.ZeroMQ_redis_port" 6379
sudo $CAKE Admin setSetting "Plugin.ZeroMQ_redis_database" 1
sudo $CAKE Admin setSetting "Plugin.ZeroMQ_redis_namespace" "mispq"
sudo $CAKE Admin setSetting "Plugin.ZeroMQ_include_attachments" false
sudo $CAKE Admin setSetting "Plugin.ZeroMQ_tag_notifications_enable" false
sudo $CAKE Admin setSetting "Plugin.ZeroMQ_audit_notifications_enable" false
```
#### misp-modules (section deprecated)
-------------------------------
!!! notice
    If you want to add the misp modules functionality, follow the setup procedure described in misp-modules:<br />
    https://github.com/MISP/misp-modules#how-to-install-and-start-misp-modules<br />
    Then the enrichment, export and import modules can be enabled in MISP via the settings.
