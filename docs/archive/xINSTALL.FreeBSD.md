# INSTALLATION INSTRUCTIONS
## for FreeBSD 11.2-amd64

### 0/ WIP /!\ You are warned, this does not work yet! /!\

!!! warning
    NOT working: pydeep, lief, py-yara, MAEC

{!generic/globalVariables.md!}

```
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

Install pkg by typing:
```bash
$ su -
# pkg
```

#### Install sudo

```bash
pkg install -y sudo
```

#### Install bash

```bash
sudo pkg install -y bash
```

Make sure users in group wheel can sudo, uncomment in /usr/local/etc/sudoers :
```
%wheel ALL=(ALL) ALL
```

#### Update system
```bash
sudo freebsd-update fetch install
```

#### Make python3 default *(optional)

```bash
echo "DEFAULT_VERSIONS= python=3.6 python2=2.7 python3=3.6" >> /etc/make.conf
sudo ln -s /usr/local/bin/python3 /usr/local/bin/python
```

#### Install postfix
```bash
sudo pkg install -y postfix

# Optional but useful, add a local misp user
sudo pw user add misp -s /usr/local/bin/bash -G wheel,www
sudo mkdir /home/misp ; sudo chown misp:misp /home/misp
sudo passwd misp
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
```

```
sudo vi /usr/local/etc/apache24/Includes/php.conf
```

Add:
```
<IfModule dir_module>
    DirectoryIndex index.php index.html

    <FilesMatch "\.php$">
        SetHandler application/x-httpd-php
    </FilesMatch>

    <FilesMatch "\.phps$">
        SetHandler application/x-httpd-php-source
    </FilesMatch>
</IfModule>
```

#### Redis need to be installed via ports

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

#### PHP CLI Tweak
```bash
echo "PATH=$PATH:/usr/local/bin" |sudo tee -a /usr/local/etc/apache24/envvars.d/php.env

sudo service apache24 restart
```

### 3/ MISP code
------------

```bash
# Download MISP using git in the /usr/local/www/ directory.
sudo mkdir /usr/local/www/MISP
sudo chown www:www /usr/local/www/MISP
cd /usr/local/www/MISP
sudo -u www git clone https://github.com/MISP/MISP.git /usr/local/www/MISP

# Make git ignore filesystem permission differences
sudo -u www git config core.filemode false

sudo -u www git submodule update --init --recursive
# Make git ignore filesystem permission differences for submodules
sudo -u www git submodule foreach --recursive git config core.filemode false

# install Mitre's STIX and its dependencies by running the following commands:
##sudo apt-get install python-dev zlib1g-dev python-setuptools
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
cd /usr/local/www/MISP/app
sudo -u www php composer.phar require kamisama/cake-resque:4.1.2
sudo -u www php composer.phar config vendor-dir Vendor
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
```

Now edit: /usr/local/etc/apache24/sites-available/misp-ssl.conf to reflect the below.
Make sure the ssl fqdn will reflect what you entered as a CN in the SSL-Cert.
You might see this: "AH00558: httpd: Could not reliably determine the server's fully qualified domain name, using 127.0.0.1. Set the 'ServerName' directive globally to suppress this message"
Edit: 

```
============================================= Begin sample working SSL config for MISP
<VirtualHost <IP, FQDN, or *>:80>
        ServerName <your.FQDN.here>

        Redirect permanent / https://<your.FQDN.here>

        LogLevel warn
        ErrorLog /var/log/apache24/misp.local_error.log
        CustomLog /var/log/apache24/misp.local_access.log combined
        ServerSignature Off
</VirtualHost>

<VirtualHost <IP, FQDN, or *>:443>
        ServerAdmin admin@<your.FQDN.here>
        ServerName <your.FQDN.here>
        DocumentRoot /usr/local/www/MISP/app/webroot
        <Directory /usr/local/www/MISP/app/webroot>
                Options -Indexes
                AllowOverride all
                Order allow,deny
                allow from all
        </Directory>

        SSLEngine On
        SSLCertificateFile /etc/ssl/private/misp.local.crt
        SSLCertificateKeyFile /etc/ssl/private/misp.local.key
#        SSLCertificateChainFile /etc/ssl/private/misp-chain.crt

        LogLevel warn
        ErrorLog /var/log/apache24/misp.local_error.log
        CustomLog /var/log/apache24/misp.local_access.log combined
        ServerSignature Off
</VirtualHost>
============================================= End sample working SSL config for MISP
```

```
# activate new vhost
cd /usr/local/etc/apache24/sites-enabled/
sudo ln -s ../sites-available/misp-ssl.conf
echo "Include etc/apache24/sites-enabled/*.conf" |sudo tee -a /usr/local/etc/apache24/httpd.conf
echo "IncludeOptional etc/apache24/sites-enabled/*.conf" |sudo tee -a /usr/local/etc/apache24/httpd.conf

for key in upload_max_filesize post_max_size max_execution_time max_input_time memory_limit
do
    sudo gsed -i "s/^\($key\).*/\1 = $(eval echo \${$key})/" $PHP_INI
done

sudo vi /usr/local/etc/apache24/httpd.conf
/!\ Enable mod_rewrite in httpd.conf /!\
LoadModule rewrite_module libexec/apache24/mod_rewrite.so
LoadModule ssl_module libexec/apache24/mod_ssl.so
Listen 443

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
sudo gsed -i -e '$i \sudo -u www bash ${PATH_TO_MISP}/app/Console/worker/start.sh > /tmp/worker_start_rc.local.log\n' /etc/rc.local
sudo gsed -i -e '$i \sudo -u www ${PATH_TO_MISP}/venv/bin/misp-modules -l 127.0.0.1 -s > /tmp/misp-modules_rc.local.log &\n' /etc/rc.local
```

### 10/ MISP modules

```bash
sudo pkg install yara
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
sudo pkg install libzmq4
sudo -H -u www ${PATH_TO_MISP}/venv/bin/pip install pyzmq
```

#### misp-modules (section deprecated)
-------------------------------
!!! notice
    If you want to add the misp modules functionality, follow the setup procedure described in misp-modules:<br />
    https://github.com/MISP/misp-modules#how-to-install-and-start-misp-modules<br />
    Then the enrichment, export and import modules can be enabled in MISP via the settings.
