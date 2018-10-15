INSTALLATION INSTRUCTIONS
------------------------- for OpenBSD 6.3-amd64

0/ WIP /!\ You are warned, this does not work yet! /!\

Current issues: php-redis only available in binary for php-56, workaround: use ports.
This guide attempts to offer native httpd or apache2/nginx set-up.

1/ Minimal OpenBSD install
--------------------------

# Install standard OpenBSD-amd64 with ports

## In case you forgot to fetch ports

```
$ cd /tmp
$ ftp https://ftp.openbsd.org/pub/OpenBSD/$(uname -r)/{ports.tar.gz,SHA256.sig}
$ signify -Cp /etc/signify/openbsd-$(uname -r | cut -c 1,3)-base.pub -x SHA256.sig ports.tar.gz
# cd /usr
# tar xzf /tmp/ports.tar.gz
````

# System Hardening

- TBD

# doas & pkg (as root)
```
echo http://ftp.belnet.be/pub/OpenBSD/ > /etc/installurl
echo "permit keepenv setenv { PKG_PATH ENV PS1 SSH_AUTH_SOCK } :wheel" > /etc/doas.conf
```

# Update system
```
doas syspatch
```

# Install bash & ntp
```
doas pkg_add -v bash ntp
```

# rc.local - Add ntpdate on boot

```
echo -n ' ntpdate'
/usr/local/sbin/ntpdate -b pool.ntp.org >/dev/null
```

# Launch ntpd on boot
```
doas rcctl enable xntpd
doas rcctl set xntpd flags "-p /var/run/ntpd.pid"
doas /usr/local/sbin/ntpd -p /var/run/ntpd.pid
```

# misp user
```
useradd -m -s /usr/local/bin/bash -G wheel,www misp
```

# nvim (optional)
```
doas pkg_add -v neovim
doas mv /usr/bin/vi /usr/bin/vi-`date +%d%m%y`
doas ln -s /usr/local/bin/nvim /usr/bin/vi
```

# /etc/httpd.conf
```
cp /etc/examples/httpd.conf /etc # adjust by hand, or copy/paste the config example below
```

```
# $OpenBSD: httpd.conf,v 1.18 2018/03/23 11:36:41 florian Exp $

#
# Macros
#
ext4_addr="*"
ext6_addr="::"

server "default" {
        #listen on $ext4_addr port 80 block return 301 "https://$SERVER_NAME$REQUEST_URI"
        listen on $ext4_addr port 80
        listen on $ext4_addr tls port 443
        #listen on $ext6_addr port 80 block return 301 "https://$SERVER_NAME$REQUEST_URI"
        listen on $ext6_addr port 80
        listen on $ext6_addr tls port 443

        root "/htdocs/MISP/app/webroot"

        tls {
                key "/etc/ssl/private/server.key"
                certificate "/etc/ssl/server.crt"
        }
        directory {
                index "index.php"
        }
        location "*.php" {
                fastcgi socket "/run/php-fpm.sock"
        }
        #location "/.well-known/acme-challenge/*" {
        #       root "/acme"
        #       root strip 2
        #}
        #location * {
        #       block return 302 "https://$HTTP_HOST$REQUEST_URI"
        #}
}

# Include MIME types instead of the built-in ones
types {
        include "/usr/share/misc/mime.types"
}

#server "example.com" {
#       listen on * tls port 443
#       listen on :: tls port 443
#       tls {
#               certificate "/etc/ssl/example.com.fullchain.pem"
#               key "/etc/ssl/private/example.com.key"
#       }
#       location "/pub/*" {
#               directory auto index
#       }
#       location "/.well-known/acme-challenge/*" {
#               root "/acme"
#               root strip 2
#       }
#}
```

# If a valid SSL certificate is not already created for the server, create a self-signed certificate:
```
doas openssl genrsa -out /etc/ssl/private/server.key
doas openssl req -new -x509 -subj "/C=<Country>/ST=<State>/L=<Locality>/O=<Organization>/OU=<Organizational Unit Name>/CN=<QDN.here>/emailAddress=admin@<your.FQDN.here>" -key /etc/ssl/private/server.key -out /etc/ssl/server.crt -days 3650
```

# mariadb server
```
pkd_add -v mariadb-server 
```

# start httpd
```
/etc/rc.d/httpd -f start
```

# Install postfix
```
doas pkg_add -v postfix
```

# Enable httpd
```
doas rcctl enable httpd
```

# Install misc dependencies

```
doas pkg_add -v curl git python redis
```

# OpendBSD + Apache/httpd/nginx + MySQL/Mariadb + PHP
```
#pkg_add -v apache-httpd
pkg_add -v \
    gnupg \
```

# php7 ports
```
    php-mysqli 
    php-pcntl 
    php-pdo_mysql 
    pecl-redis 
    pear
```

# Optional for Apache2
```
doas pkg_add -v fcgi-cgi fcgi
``

# /etc/php-5.6.ini 
```
allow_url_fopen = On
```

```
cd /etc/php-5.6
doas cp ../php-5.6.sample/* .
```

# php ln
```
doas ln -s /usr/local/bin/php-5.6 /usr/local/bin/php
```

# Enable php fpm 
``
doas rcctl enable php56_fpm
```

# Configure fpm
```
doas vi /etc/php-fpm.conf
```

error_log = log/php-fpm.log
chroot -> remove for the time being


For native httpd: listen = /var/www/run/php-fpm.sock
For apache2: listen = 127.0.0.1:9000

# Enable redis
```
doas rcctl enable redis
doas /etc/rc.d/redis start
```

# Enable mysqld
```
doas rcctl set mysqld status on
doas rcctl set mysqld flags --bind-address=127.0.0.1
doas /etc/rc.d/mysqld start
doas mysql_secure_installation
```

3/ MISP code
------------
```
# Download MISP using git in the /usr/local/www/ directory.
doas mkdir /var/www/htdocs/MISP
doas chown www:www /var/www/htdocs/MISP
cd /var/www/htdocs/MISP
doas -u www git clone https://github.com/MISP/MISP.git /var/www/htdocs/MISP

# Make git ignore filesystem permission differences
doas -u www git config core.filemode false

doas pkg_add py-pip py3-pip libxml libxslt py3-jsonschema

cd /var/www/htdocs/MISP/app/files/scripts
doas -u www git clone https://github.com/CybOXProject/python-cybox.git
doas -u www git clone https://github.com/STIXProject/python-stix.git
cd /var/www/htdocs/MISP/app/files/scripts/python-cybox
doas python3 setup.py install
cd /var/www/htdocs/MISP/app/files/scripts/python-stix
doas python3 setup.py install

# install mixbox to accomodate the new STIX dependencies:
cd /var/www/htdocs/MISP/app/files/scripts/
doas -u www git clone https://github.com/CybOXProject/mixbox.git
cd /var/www/htdocs/MISP/app/files/scripts/mixbox
doas python3 setup.py install

# install PyMISP
cd /var/www/htdocs/MISP/PyMISP
doas python3 setup.py install

# install support for STIX 2.0
doas pip3.6 install stix2
```

4/ CakePHP
-----------
```
# CakePHP is included as a submodule of MISP, execute the following commands to let git fetch it:
cd /var/www/htdocs/MISP
doas -u www git submodule update --init --recursive
# Make git ignore filesystem permission differences for submodules
doas -u www git submodule foreach --recursive git config core.filemode false

# Once done, install CakeResque along with its dependencies if you intend to use the built in background jobs:
cd /var/www/htdocs/MISP/app
doas -u www php composer.phar require kamisama/cake-resque:4.1.2
doas -u www php composer.phar config vendor-dir Vendor
doas -u www php composer.phar install

# To use the scheduler worker for scheduled tasks, do the following:
doas -u www cp -f /var/www/htdocs/MISP/INSTALL/setup/config.php /var/www/htdocs/MISP/app/Plugin/CakeResque/Config/config.php
```

5/ Set the permissions
----------------------
```
# Check if the permissions are set correctly using the following commands:
doas chown -R www:www /var/www/htdocs/MISP
doas chmod -R 750 /var/www/htdocs/MISP
doas chmod -R g+ws /var/www/htdocs/MISP/app/tmp
doas chmod -R g+ws /var/www/htdocs/MISP/app/files
doas chmod -R g+ws /var/www/htdocs/MISP/app/files/scripts/tmp
```

6/ Create a database and user
-----------------------------
```
# Enter the mysql shell
doas mysql -u root -p
```

```
MariaDB [(none)]> create database misp;
MariaDB [(none)]> grant usage on *.* to misp@localhost identified by 'XXXXdbpasswordhereXXXXX';
MariaDB [(none)]> grant all privileges on misp.* to misp@localhost;
MariaDB [(none)]> flush privileges;
MariaDB [(none)]> exit
```

```
# Import the empty MISP database from MYSQL.sql
doas -u www sh -c "mysql -u misp -p misp < /var/www/htdocs/MISP/INSTALL/MYSQL.sql"
# enter the password you set previously
```

7/ Apache configuration (optional)
-----------------------
# Now configure your Apache webserver with the DocumentRoot /var/www/htdocs/MISP/app/webroot/

#2.4
doas mkdir /etc/apache2/sites-available/ /etc/apache2/sites-enabled/

# If the apache version is 2.4:
doas cp /var/www/htdocs/MISP/INSTALL/apache.24.misp.ssl /etc/apache2/sites-available/misp-ssl.conf

# Be aware that the configuration files for apache 2.4 and up have changed.
# The configuration file has to have the .conf extension in the sites-available directory
# For more information, visit http://httpd.apache.org/docs/2.4/upgrading.html

doas mkdir /etc/ssl/private/
# If a valid SSL certificate is not already created for the server, create a self-signed certificate: (Make sure to fill the <…>)
doas openssl req -newkey rsa:4096 -days 3650 -nodes -x509 \
-subj "/C=<Country>/ST=<State>/L=<Locality>/O=<Organization>/OU=<Organizational Unit Name>/CN=<QDN.here>/emailAddress=admin@<your.FQDN.here>" \
-keyout /etc/ssl/private/misp.local.key -out /etc/ssl/private/misp.local.crt

# Otherwise, copy the SSLCertificateFile, SSLCertificateKeyFile, and SSLCertificateChainFile to /etc/ssl/private/. (Modify path and config to fit your environment)

doas mkdir /var/log/apache2/

============================================= Begin sample working SSL config for MISP
<VirtualHost <IP, FQDN, or *>:80>
        ServerName <your.FQDN.here>

        Redirect permanent / https://<your.FQDN.here>

        LogLevel warn
        ErrorLog /var/log/apache2/misp.local_error.log
        CustomLog /var/log/apache2/misp.local_access.log combined
        ServerSignature Off
</VirtualHost>

<VirtualHost <IP, FQDN, or *>:443>
        ServerAdmin admin@<your.FQDN.here>
        ServerName <your.FQDN.here>
        DocumentRoot /var/www/htdocs/MISP/app/webroot
        <Directory /var/www/htdocs/MISP/app/webroot>
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
        ErrorLog /var/log/apache2/misp.local_error.log
        CustomLog /var/log/apache2/misp.local_access.log combined
        ServerSignature Off
</VirtualHost>
============================================= End sample working SSL config for MISP

# activate new vhost
cd /etc/apache2/sites-enabled/
doas ln -s ../sites-available/misp-ssl.conf
echo "Include /etc/apache2/sites-enabled/*.conf" >> /etc/apache2/httpd2.conf

doas vi /etc/apache2/httpd2.conf

/!\ Enable mod_rewrite in httpd2.conf /!\
LoadModule rewrite_module /usr/local/lib/apache2/mod_rewrite.so
LoadModule ssl_module /usr/local/lib/apache2/mod_ssl.so
LoadModule proxy_module /usr/local/lib/apache2/mod_proxy.so
LoadModule proxy_fcgi_module /usr/local/lib/apache2/mod_proxy_fcgi.so
Listen 443

# Restart apache
doas /etc/rc.d/apache2 restart

8/ Log rotation (needs to be adapted to OpenBSD, newsyslog does this for you
---------------
# MISP saves the stdout and stderr of its workers in /var/www/htdocs/MISP/app/tmp/logs


9/ MISP configuration
---------------------
# There are 4 sample configuration files in /var/www/htdocs/MISP/app/Config that need to be copied
doas -u www cp /var/www/htdocs/MISP/app/Config/bootstrap.default.php /var/www/htdocs/MISP/app/Config/bootstrap.php
doas -u www cp /var/www/htdocs/MISP/app/Config/database.default.php /var/www/htdocs/MISP/app/Config/database.php
doas -u www cp /var/www/htdocs/MISP/app/Config/core.default.php /var/www/htdocs/MISP/app/Config/core.php
doas -u www cp /var/www/htdocs/MISP/app/Config/config.default.php /var/www/htdocs/MISP/app/Config/config.php

# Configure the fields in the newly created files:
doas -u www vim /var/www/htdocs/MISP/app/Config/database.php
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

# Important! Change the salt key in /usr/local/www/MISP/app/Config/config.php
# The salt key must be a string at least 32 bytes long.
# The admin user account will be generated on the first login, make sure that the salt is changed before you create that user
# If you forget to do this step, and you are still dealing with a fresh installation, just alter the salt,
# delete the user from mysql and log in again using the default admin credentials (admin@admin.test / admin)

# Change base url in config.php
doas -u www vim /var/www/htdocs/MISP/app/Config/config.php
# example: 'baseurl' => 'https://<your.FQDN.here>',
# alternatively, you can leave this field empty if you would like to use relative pathing in MISP
# 'baseurl' => '',

# and make sure the file permissions are still OK
doas chown -R www:www /var/www/htdocs/MISP/app/Config
doas chmod -R 750 /var/www/htdocs/MISP/app/Config

# Generate a GPG encryption key.
doas -u www mkdir /var/www/htdocs/MISP/.gnupg
doas chmod 700 /var/www/htdocs/MISP/.gnupg
##### doas -u www gpg --homedir /var/www/htdocs/MISP/.gnupg --gen-key <- Broken
# The email address should match the one set in the config.php / set in the configuration menu in the administration menu configuration file

# And export the public key to the webroot
doas -u www sh -c "gpg --homedir /var/www/htdocs/MISP/.gnupg --export --armor YOUR-KEYS-EMAIL-HERE > /var/www/htdocs/MISP/app/webroot/gpg.asc"

# To make the background workers start on boot
doas chmod +x /var/www/htdocs/MISP/app/Console/worker/start.sh
doas vim /etc/rc.local
# Add the following line before the last line (exit 0). Make sure that you replace www with your apache user:
doas -u www bash /var/www/htdocs/MISP/app/Console/worker/start.sh

# Now log in using the webinterface:
# The default user/pass = admin@admin.test/admin

# Using the server settings tool in the admin interface (Administration -> Server Settings), set MISP up to your preference
# It is especially vital that no critical issues remain!
# start the workers by navigating to the workers tab and clicking restart all workers

# Don't forget to change the email, password and authentication key after installation.

# Once done, have a look at the diagnostics

# If any of the directories that MISP uses to store files is not writeable to the apache user, change the permissions
# you can do this by running the following commands:

doas chmod -R 750 /var/www/htdocs/MISP/<directory path with an indicated issue>
doas chown -R www:www /var/www/htdocs/MISP/<directory path with an indicated issue>

# Make sure that the STIX libraries and GnuPG work as intended, if not, refer to INSTALL.txt's paragraphs dealing with these two items

# If anything goes wrong, make sure that you check MISP's logs for errors:
# /var/www/htdocs/MISP/app/tmp/logs/error.log
# /var/www/htdocs/MISP/app/tmp/logs/resque-worker-error.log
# /var/www/htdocs/MISP/app/tmp/logs/resque-scheduler-error.log
# /var/www/htdocs/MISP/app/tmp/logs/resque-2015-01-01.log // where the actual date is the current date


Recommended actions
-------------------
- By default CakePHP exposes its name and version in email headers. Apply a patch to remove this behavior.

- You should really harden your OS
- You should really harden the configuration of Apache/httpd
- You should really harden the configuration of MySQL/MariaDB
- Keep your software up2date (OS, MISP, CakePHP and everything else)
- Log and audit


Optional features
-------------------
# MISP has a new pub/sub feature, using ZeroMQ.

# ZeroMQ depends on the Python client for Redis
```
doas pkg_add -v py3-zmq
```
