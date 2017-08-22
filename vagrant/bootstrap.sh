#! /usr/bin/env bash

# Database configuration
DBHOST='localhost'
DBNAME='misp'
DBUSER_ADMIN='root'
DBPASSWORD_ADMIN="$(openssl rand -hex 32)"
DBUSER_MISP='misp'
DBPASSWORD_MISP="$(openssl rand -hex 32)"

# Webserver configuration
PATH_TO_MISP='/var/www/MISP'
MISP_BASEURL='http://127.0.0.1:5000'
MISP_LIVE='1'
FQDN='localhost'

# OpenSSL configuration
OPENSSL_C='LU'
OPENSSL_ST='State'
OPENSSL_L='Location'
OPENSSL_O='Organization'
OPENSSL_OU='Organizational Unit'
OPENSSL_CN='Common Name'
OPENSSL_EMAILADDRESS='info@localhost'

# GPG configuration
GPG_REAL_NAME='Real name'
GPG_EMAIL_ADDRESS='info@localhost'
GPG_KEY_LENGTH='2048'
GPG_PASSPHRASE=''




echo -e "\n--- Installing MISP... ---\n"


echo -e "\n--- Updating packages list ---\n"
apt-get -qq update


echo -e "\n--- Install base packages ---\n"
apt-get -y install curl gcc git gnupg-agent make python openssl redis-server sudo vim zip > /dev/null 2>&1

# To prevent a random error when cloning with Git: 'RPC failed; curl 56 GnuTLS recv error (-54): Error in the pull function.'
git config --global http.postBuffer 1048576000
git config --global https.postBuffer 1048576000

echo -e "\n--- Installing and configuring Postfix ---\n"
# # Postfix Configuration: Satellite system
# # change the relay server later with:
# sudo postconf -e 'relayhost = example.com'
# sudo postfix reload
echo "postfix postfix/mailname string `hostname`.ourdomain.org" | debconf-set-selections
echo "postfix postfix/main_mailer_type string 'Satellite system'" | debconf-set-selections
apt-get install -y postfix > /dev/null 2>&1


echo -e "\n--- Installing MariaDB specific packages and settings ---\n"
apt-get install -y mariadb-client mariadb-server > /dev/null 2>&1
# Secure the MariaDB installation (especially by setting a strong root password)
sleep 7 # give some time to the DB to launch...
apt-get install -y expect > /dev/null 2>&1
expect -f - <<-EOF
  set timeout 10
  spawn mysql_secure_installation
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
apt-get purge -y expect > /dev/null 2>&1


echo -e "\n--- Installing Apache2 ---\n"
apt-get install -y apache2 apache2-doc apache2-utils > /dev/null 2>&1
a2dismod status > /dev/null 2>&1
a2enmod ssl > /dev/null 2>&1
a2enmod rewrite > /dev/null 2>&1
a2dissite 000-default > /dev/null 2>&1
a2ensite default-ssl > /dev/null 2>&1


echo -e "\n--- Installing PHP-specific packages ---\n"
apt-get install -y libapache2-mod-php php php-cli php-crypt-gpg php-dev php-json php-mysql php-opcache php-readline php-redis php-xml > /dev/null 2>&1


echo -e "\n--- Restarting Apache ---\n"
systemctl restart apache2 > /dev/null 2>&1


echo -e "\n--- Retrieving MISP ---\n"
mkdir $PATH_TO_MISP
chown www-data:www-data $PATH_TO_MISP
cd $PATH_TO_MISP
#git clone https://github.com/MISP/MISP.git $PATH_TO_MISP
#git checkout tags/$(git describe --tags `git rev-list --tags --max-count=1`)
git config core.filemode false
# chown -R www-data $PATH_TO_MISP
# chgrp -R www-data $PATH_TO_MISP
# chmod -R 700 $PATH_TO_MISP


echo -e "\n--- Installing Mitre's STIX ---\n"
apt-get install -y python-dev python-pip libxml2-dev libxslt1-dev zlib1g-dev python-setuptools > /dev/null 2>&1
cd $PATH_TO_MISP/app/files/scripts
git clone https://github.com/CybOXProject/python-cybox.git
git clone https://github.com/STIXProject/python-stix.git
cd $PATH_TO_MISP/app/files/scripts/python-cybox
git checkout v2.1.0.12
python setup.py install > /dev/null 2>&1
cd $PATH_TO_MISP/app/files/scripts/python-stix
git checkout v1.1.1.4
python setup.py install > /dev/null 2>&1
# install mixbox to accomodate the new STIX dependencies:
cd $PATH_TO_MISP/app/files/scripts/
git clone https://github.com/CybOXProject/mixbox.git
cd $PATH_TO_MISP/app/files/scripts/mixbox
git checkout v1.0.2
python setup.py install > /dev/null 2>&1


echo -e "\n--- Retrieving CakePHP... ---\n"
# CakePHP is included as a submodule of MISP, execute the following commands to let git fetch it:
cd $PATH_TO_MISP
git submodule init
git submodule update
# Once done, install CakeResque along with its dependencies if you intend to use the built in background jobs:
cd $PATH_TO_MISP/app
php composer.phar require kamisama/cake-resque:4.1.2
php composer.phar config vendor-dir Vendor
php composer.phar install
# Enable CakeResque with php-redis
phpenmod redis
# To use the scheduler worker for scheduled tasks, do the following:
cp -fa $PATH_TO_MISP/INSTALL/setup/config.php $PATH_TO_MISP/app/Plugin/CakeResque/Config/config.php


echo -e "\n--- Setting the permissions... ---\n"
chown -R www-data:www-data $PATH_TO_MISP
chmod -R 750 $PATH_TO_MISP
chmod -R g+ws $PATH_TO_MISP/app/tmp
chmod -R g+ws $PATH_TO_MISP/app/files
chmod -R g+ws $PATH_TO_MISP/app/files/scripts/tmp


echo -e "\n--- Creating a database user... ---\n"
mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e "create database $DBNAME;"
mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e "grant usage on *.* to $DBNAME@localhost identified by '$DBPASSWORD_MISP';"
mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e "grant all privileges on $DBNAME.* to '$DBUSER_MISP'@'localhost';"
mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e "flush privileges;"
# Import the empty MISP database from MYSQL.sql
mysql -u $DBUSER_MISP -p$DBPASSWORD_MISP $DBNAME < /var/www/MISP/INSTALL/MYSQL.sql


echo -e "\n--- Configuring Apache... ---\n"
# !!! apache.24.misp.ssl seems to be missing
#cp $PATH_TO_MISP/INSTALL/apache.24.misp.ssl /etc/apache2/sites-available/misp-ssl.conf
# If a valid SSL certificate is not already created for the server, create a self-signed certificate:
sudo openssl req -newkey rsa:4096 -days 365 -nodes -x509 -subj "/C=$OPENSSL_C/ST=$OPENSSL_ST/L=$OPENSSL_L/O=<$OPENSSL_O/OU=$OPENSSL_OU/CN=$OPENSSL_CN/emailAddress=$OPENSSL_EMAILADDRESS" -keyout /etc/ssl/private/misp.local.key -out /etc/ssl/private/misp.local.crt


echo -e "\n--- Add a VirtualHost for MISP ---\n"
cat > /etc/apache2/sites-available/misp-ssl.conf <<EOF
<VirtualHost *:80>
        ServerAdmin me@me.local
        ServerName misp.local
        DocumentRoot $PATH_TO_MISP/app/webroot

        <Directory $PATH_TO_MISP/app/webroot>
            Options -Indexes
            AllowOverride all
            Require all granted
        </Directory>

        LogLevel warn
        ErrorLog /var/log/apache2/misp.local_error.log
        CustomLog /var/log/apache2/misp.local_access.log combined
        ServerSignature Off
</VirtualHost>
EOF
# cat > /etc/apache2/sites-available/misp-ssl.conf <<EOF
# <VirtualHost *:80>
#         ServerName misp.local
#
#         Redirect permanent / https://$FQDN
#
#         LogLevel warn
#         ErrorLog /var/log/apache2/misp.local_error.log
#         CustomLog /var/log/apache2/misp.local_access.log combined
#         ServerSignature Off
# </VirtualHost>
#
# <VirtualHost *:443>
#         ServerAdmin me@me.local
#         ServerName misp.local
#         DocumentRoot $PATH_TO_MISP/app/webroot
#
#         <Directory $PATH_TO_MISP/app/webroot>
#             Options -Indexes
#             AllowOverride all
#             Require all granted
#         </Directory>
#
#         SSLEngine On
#         SSLCertificateFile /etc/ssl/private/misp.local.crt
#         SSLCertificateKeyFile /etc/ssl/private/misp.local.key
#         #SSLCertificateChainFile /etc/ssl/private/misp-chain.crt
#
#         LogLevel warn
#         ErrorLog /var/log/apache2/misp.local_error.log
#         CustomLog /var/log/apache2/misp.local_access.log combined
#         ServerSignature Off
# </VirtualHost>
# EOF
# activate new vhost
a2dissite default-ssl
a2ensite misp-ssl


echo -e "\n--- Restarting Apache ---\n"
systemctl restart apache2 > /dev/null 2>&1


echo -e "\n--- Configuring log rotation ---\n"
cp $PATH_TO_MISP/INSTALL/misp.logrotate /etc/logrotate.d/misp


echo -e "\n--- MISP configuration ---\n"
# There are 4 sample configuration files in /var/www/MISP/app/Config that need to be copied
cp -a $PATH_TO_MISP/app/Config/bootstrap.default.php /var/www/MISP/app/Config/bootstrap.php
cp -a $PATH_TO_MISP/app/Config/database.default.php /var/www/MISP/app/Config/database.php
cp -a $PATH_TO_MISP/app/Config/core.default.php /var/www/MISP/app/Config/core.php
cp -a $PATH_TO_MISP/app/Config/config.default.php /var/www/MISP/app/Config/config.php
cat > $PATH_TO_MISP/app/Config/database.php <<EOF
<?php
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
}
EOF
# and make sure the file permissions are still OK
chown -R www-data:www-data $PATH_TO_MISP/app/Config
chmod -R 750 $PATH_TO_MISP/app/Config
# Set some MISP directives with the command line tool
$PATH_TO_MISP/app/Console/cake Baseurl $MISP_BASEURL
$PATH_TO_MISP/app/Console/cake Live $MISP_LIVE


echo -e "\n--- Generating a GPG encryption key... ---\n"
apt-get install -y rng-tools haveged
mkdir $PATH_TO_MISP/.gnupg
chmod 700 $PATH_TO_MISP/.gnupg
cat >gen-key-script <<EOF
    %echo Generating a default key
    Key-Type: default
    Key-Length: $GPG_KEY_LENGTH
    Subkey-Type: default
    Name-Real: $GPG_REAL_NAME
    Name-Comment: no comment
    Name-Email: $GPG_EMAIL_ADDRESS
    Expire-Date: 0
    Passphrase: '$GPG_PASSPHRASE'
    # Do a commit here, so that we can later print "done"
    %commit
    %echo done
EOF
gpg --homedir $PATH_TO_MISP/.gnupg --batch --gen-key gen-key-script
rm gen-key-script
# And export the public key to the webroot
gpg --homedir $PATH_TO_MISP/.gnupg --export --armor $EMAIL_ADDRESS > $PATH_TO_MISP/app/webroot/gpg.asc


echo -e "\n--- Making the background workers start on boot... ---\n"
chmod 755 $PATH_TO_MISP/app/Console/worker/start.sh
cat > /etc/systemd/system/workers.service  <<EOF
[Unit]
Description=Start the background workers at boot

[Service]
Type=forking
User=www-data
ExecStart=$PATH_TO_MISP/app/Console/worker/start.sh

[Install]
WantedBy=multi-user.target
EOF
systemctl enable workers.service > /dev/null
systemctl restart workers.service > /dev/null


echo -e "\n--- Installing MISP modules... ---\n"
apt-get install -y python3-dev python3-pip libpq5 libjpeg-dev > /dev/null 2>&1
cd /usr/local/src/
git clone https://github.com/MISP/misp-modules.git
cd misp-modules
pip3 install -I -r REQUIREMENTS > /dev/null 2>&1
pip3 install -I . > /dev/null 2>&1
cat > /etc/systemd/system/misp-modules.service  <<EOF
[Unit]
Description=Start the misp modules server at boot

[Service]
Type=forking
User=www-data
ExecStart=/bin/sh -c 'misp-modules -l 0.0.0.0 -s &'

[Install]
WantedBy=multi-user.target
EOF
systemctl enable misp-modules.service > /dev/null
systemctl restart misp-modules.service > /dev/null


echo -e "\n--- Restarting Apache... ---\n"
systemctl restart apache2 > /dev/null 2>&1
sleep 5

echo -e "\n--- Updating the galaxies... ---\n"
sudo -E $PATH_TO_MISP/app/Console/cake userInit -q > /dev/null
AUTH_KEY=$(mysql -u $DBUSER_MISP -p$DBPASSWORD_MISP misp -e "SELECT authkey FROM users;" | tail -1)
curl -k -X POST -H "Authorization: $AUTH_KEY" -H "Accept: application/json" -v http://127.0.0.1/galaxies/update > /dev/null 2>&1


echo -e "\n--- Updating the taxonomies... ---\n"
curl -k -X POST -H "Authorization: $AUTH_KEY" -H "Accept: application/json" -v http://127.0.0.1/taxonomies/update > /dev/null 2>&1


# echo -e "\n--- Enabling MISP new pub/sub feature (ZeroMQ)... ---\n"
# # ZeroMQ depends on the Python client for Redis
# pip install redis > /dev/null 2>&1
# ## Install ZeroMQ and prerequisites
# apt-get install -y pkg-config > /dev/null 2>&1
# cd /usr/local/src/
# git clone git://github.com/jedisct1/libsodium.git > /dev/null 2>&1
# cd libsodium
# /autogen.sh > /dev/null 2>&1
# ./configure > /dev/null 2>&1
# make check > /dev/null 2>&1
# make > /dev/null 2>&1
# make install > /dev/null 2>&1
# ldconfig > /dev/null 2>&1
# cd /usr/local/src/
# wget https://archive.org/download/zeromq_4.1.5/zeromq-4.1.5.tar.gz > /dev/null 2>&1
# tar -xvf zeromq-4.1.5.tar.gz > /dev/null 2>&1
# cd zeromq-4.1.5/
# ./autogen.sh > /dev/null 2>&1
# ./configure > /dev/null 2>&1
# make check > /dev/null 2>&1
# make > /dev/null 2>&1
# make install > /dev/null 2>&1
# ldconfig > /dev/null 2>&1
# ## install pyzmq
# pip install pyzmq > /dev/null 2>&1


echo -e "\e[32mMISP is ready\e[0m"
echo -e "\e[0mPoint your Web browser to \e[33m$MISP_BASEURL\e[0m"
echo -e "\e[0mDefault user/pass = \e[33madmin@admin.test/admin\e[0m"
