# INSTALLATION INSTRUCTIONS!}
## for OpenBSD 7.0-amd64

!!! warning
    This is not fully working yet. Mostly it is a template for our ongoing documentation efforts :spider:
    LIEF, will probably not be available for a long long time on OpenBSD, until someone is brave enough to make it work.
    GnuPG also needs some more TLC.
    misp-modules are broken because of the python-opencv dependency.

### 0/ WIP! You are warned, this does only partially work!
------------

!!! notice
    This guide attempts to offer native httpd or apache2/nginx.

!!! notice
    As of OpenBSD 6.4 the native httpd has rewrite rules and php 5.6 is gone too.

{% include_relative generic/globalVariables.md %}

```bash
export AUTOMAKE_VERSION=1.16
export AUTOCONF_VERSION=2.71
```

### 1/ Minimal OpenBSD install
------------

#### Install standard OpenBSD-amd64 with ports

#### System Hardening

- TBD

#### doas & pkg (as root)
```bash
if [[ ! -e /etc/installurl ]]; then
  echo https://cdn.openbsd.org/pub/OpenBSD/ > /etc/installurl
fi
echo "permit keepenv setenv { PKG_PATH ENV PS1 SSH_AUTH_SOCK } :wheel" > /etc/doas.conf
## FIXME: this does NOT set the HOME env correctly, please fix to make pip happier
echo "permit nopass setenv { ENV PS1 HOME=/var/www } www" >> /etc/doas.conf
```

##### In case you forgot to fetch ports (optional)

```bash
cd /tmp
ftp https://cdn.openbsd.org/pub/OpenBSD/$(uname -r)/{ports.tar.gz,SHA256.sig}
signify -Cp /etc/signify/openbsd-$(uname -r | cut -c 1,3)-base.pub -x SHA256.sig ports.tar.gz
doas tar -x -z -f /tmp/ports.tar.gz -C /usr
```

##### If you want to use php-gd (resizing of images) you need X (optional)

```bash
cd /tmp
ftp https://cdn.openbsd.org/pub/OpenBSD/$(uname -r)/$(uname -m)/{xbase$(uname -r| tr -d \.).tgz,SHA256.sig}
signify -Cp /etc/signify/openbsd-$(uname -r | cut -c 1,3)-base.pub -x SHA256.sig xbase$(uname -r |tr -d \.).tgz
doas tar -xzphf /tmp/xbase$(uname -r| tr -d \.).tgz -C /
ftp https://cdn.openbsd.org/pub/OpenBSD/$(uname -r)/$(uname -m)/{xshare$(uname -r| tr -d \.).tgz,SHA256.sig}
signify -Cp /etc/signify/openbsd-$(uname -r | cut -c 1,3)-base.pub -x SHA256.sig xshare$(uname -r |tr -d \.).tgz
doas tar -xzphf /tmp/xshare$(uname -r| tr -d \.).tgz -C /
```

#### Update system
```bash
doas syspatch
```

#### Install bash & ntp
```bash
doas pkg_add -v bash ntp
```

#### mariadb server
```bash
doas pkg_add -v mariadb-server 
```

#### Install misc dependencies

```bash
doas pkg_add -v curl git sqlite3 python--%3.9 redis libmagic autoconf--%2.71 automake--%1.16 libtool unzip--iconv rust
```

```bash
doas pkg_add -v gnupg--%gnupg2
doas ln -s /usr/local/bin/gpg2 /usr/local/bin/gpg
```

#### Install postfix (optional)

```bash
doas pkg_add -v postfix--%stable
doas /usr/local/sbin/postfix-enable 
```

#### nvim (optional)
```bash
doas pkg_add -v neovim
doas mv /usr/bin/vi /usr/bin/vi-`date +%d%m%y`
doas ln -s /usr/local/bin/nvim /usr/bin/vi
```

#### rc.local - Add ntpdate on boot
```bash
echo "echo -n ' ntpdate'" |doas tee -a /etc/rc.local
echo "/usr/local/sbin/ntpdate -b pool.ntp.org >/dev/null" |doas tee -a /etc/rc.local
```

#### Launch ntpd on boot
```bash
doas rcctl enable xntpd
doas rcctl set xntpd flags "-p /var/run/ntpd.pid"
doas /usr/local/sbin/ntpd -p /var/run/ntpd.pid
```

#### misp user
```bash
if [[ -z $(id misp 2>/dev/null) ]]; then
  doas useradd -m -s /usr/local/bin/bash -G wheel,www misp
else
  doas usermod -G www misp
fi
```

#### /etc/httpd.conf (native httpd)
```bash
doas cp /etc/examples/httpd.conf /etc # adjust by hand, or copy/paste the config example below
```

```
# $OpenBSD: httpd.conf,v 1.20 2018/06/13 15:08:24 reyk Exp $

#
# Macros
#
ext_addr="*"

server "default" {
        #listen on $ext4_addr port 80 block return 301 "https://$SERVER_NAME$REQUEST_URI"
        listen on $ext_addr port 80
        listen on $ext_addr tls port 443

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
        location match "/(.*)" {
                request rewrite "/$HTTP_HOST/%1"
        }
# Temporary Apache 2.x rewrite rules for future foo!
        #RewriteRule    ^$    webroot/    [L]
        #RewriteRule    (.*) webroot/$1    [L]
# Temporary Apache 2.x rewrite rules for future foo!

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

#### If a valid SSL certificate is not already created for the server, create a self-signed certificate:

```
# OpenSSL configuration
OPENSSL_C='LU'
OPENSSL_ST='State'
OPENSSL_L='Location'
OPENSSL_O='Organization'
OPENSSL_OU='Organizational Unit'
OPENSSL_CN='Common Name'
OPENSSL_EMAILADDRESS='info@localhost'
```

```bash
doas openssl req -newkey rsa:4096 -days 3650 -nodes -x509 -subj "/C=$OPENSSL_C/ST=$OPENSSL_ST/L=$OPENSSL_L/O=<$OPENSSL_O/OU=$OPENSSL_OU/CN=$OPENSSL_CN/emailAddress=$OPENSSL_EMAILADDRESS" -keyout /etc/ssl/private/server.key -out /etc/ssl/server.crt
```

#### start httpd
```bash
doas /etc/rc.d/httpd -f start
```

#### Enable httpd
```bash
doas rcctl enable httpd
```

#### Install Python virtualenv
```bash
doas pkg_add -v py3-virtualenv py3-pip
doas ln -sf /usr/local/bin/pip3.9 /usr/local/bin/pip
doas ln -s /usr/local/bin/python3.9 /usr/local/bin/python
doas mkdir /usr/local/virtualenvs
doas /usr/local/bin/virtualenv /usr/local/virtualenvs/MISP
```

#### Install ssdeep
```bash
doas pkg_add -v ssdeep
```

#### Apache2 only
```bash
doas pkg_add -v apache-httpd
doas pkg_add -v fcgi-cgi fcgi
```

#### php7 ports
```
doas pkg_add -v php-mysqli--%7.4 php-pcntl--%7.4 php-pdo_mysql--%7.4 php-apache--%7.4 pecl74-redis php-gd--%7.4 php-zip--%7.4 php-bcmath--%7.4 php-intl--%7.4
```

#### /etc/php-7.4.ini 
```
doas sed -i "s/^allow_url_fopen = Off/allow_url_fopen = On/g" /etc/php-7.4.ini
```

```bash
cd /etc/php-7.4
doas cp ../php-7.4.sample/* .
```

#### php symlinks
```bash
doas ln -s /usr/local/bin/php-7.4 /usr/local/bin/php
doas ln -s /usr/local/bin/phpize-7.4 /usr/local/bin/phpize
doas ln -s /usr/local/bin/php-config-7.4 /usr/local/bin/php-config
```

#### Enable php fpm 
```bash
doas rcctl enable php74_fpm
```

#### Configure fpm
```
doas vi /etc/php-fpm.conf

doas sed -i "s/^;pid = run\/php-fpm.pid/pid = \/var\/www\/run\/php-fpm.pid/g" /etc/php-fpm.conf
doas sed -i "s/^;error_log = log\/php-fpm.log/error_log = \/var\/www\/logs\/php-fpm.log/g" /etc/php-fpm.conf

doas mkdir -p /etc/php-fpm.d
echo ";;;;;;;;;;;;;;;;;;;;
; Pool Definitions ;
;;;;;;;;;;;;;;;;;;;;

[www]
user = www
group = www
listen = /var/www/run/php-fpm.sock
listen.owner = www
listen.group = www
listen.mode = 0660
pm = dynamic
pm.max_children = 5
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3
chroot = /var/www" | doas tee /etc/php-fpm.d/default.conf

doas /etc/rc.d/php74_fpm start 
```

!!! notice
    For native httpd: listen = /var/www/run/php-fpm.sock
    For apache2: listen = 127.0.0.1:9000

#### Enable redis
```bash
doas rcctl enable redis
doas /etc/rc.d/redis start
```

#### Enable mysqld
```bash
doas /usr/local/bin/mysql_install_db
doas rcctl set mysqld status on
doas rcctl set mysqld flags --bind-address=127.0.0.1
doas /etc/rc.d/mysqld start
echo "Admin (${DBUSER_ADMIN}) DB Password: ${DBPASSWORD_ADMIN}"
doas mysql_secure_installation
```

### 2/ MISP code
------------
```bash
# Download MISP using git in the /usr/local/www/ directory.
doas mkdir /var/www/htdocs/MISP
doas chown www:www /var/www/htdocs/MISP
cd /var/www/htdocs/MISP
false; while [[ $? -ne 0 ]]; do ${SUDO_WWW} git clone https://github.com/MISP/MISP.git /var/www/htdocs/MISP; done
false; while [[ $? -ne 0 ]]; do ${SUDO_WWW} git submodule update --progress --init --recursive; done
# Make git ignore filesystem permission differences for submodules
${SUDO_WWW} git submodule foreach --recursive git config core.filemode false

# Make git ignore filesystem permission differences
${SUDO_WWW} git config core.filemode false

doas pkg_add -v py3-pip libxml libxslt py3-jsonschema
doas /usr/local/virtualenvs/MISP/bin/pip install -U pip setuptools setuptools-rust

cd /var/www/htdocs/MISP/app/files/scripts
false; while [[ $? -ne 0 ]]; do ${SUDO_WWW} git clone https://github.com/CybOXProject/python-cybox.git; done
false; while [[ $? -ne 0 ]]; do ${SUDO_WWW} git clone https://github.com/STIXProject/python-stix.git; done
false; while [[ $? -ne 0 ]]; do ${SUDO_WWW} git clone https://github.com/MAECProject/python-maec.git; done
false; while [[ $? -ne 0 ]]; do ${SUDO_WWW} git clone https://github.com/CybOXProject/mixbox.git; done

cd /var/www/htdocs/MISP/app/files/scripts/python-cybox
$SUDO_WWW git config core.filemode false
doas /usr/local/virtualenvs/MISP/bin/python setup.py install

cd /var/www/htdocs/MISP/app/files/scripts/python-stix
$SUDO_WWW git config core.filemode false
doas /usr/local/virtualenvs/MISP/bin/python setup.py install

cd /var/www/htdocs/MISP/app/files/scripts/python-maec
$SUDO_WWW git config core.filemode false
doas /usr/local/virtualenvs/MISP/bin/python setup.py install

# Install mixbox to accommodate the new STIX dependencies:
cd /var/www/htdocs/MISP/app/files/scripts/mixbox
$SUDO_WWW git config core.filemode false
doas /usr/local/virtualenvs/MISP/bin/python setup.py install

# Install PyMISP
cd /var/www/htdocs/MISP/PyMISP
doas /usr/local/virtualenvs/MISP/bin/python setup.py install

# Install misp-stix
cd /var/www/htdocs/MISP/app/files/scripts/misp-stix
doas /usr/local/virtualenvs/MISP/bin/python setup.py install

# Install python-magic and pydeep
doas /usr/local/virtualenvs/MISP/bin/pip install python-magic
doas /usr/local/virtualenvs/MISP/bin/pip install git+https://github.com/kbandla/pydeep.git
```

### 3/ CakePHP
-----------
```bash
# CakePHP is included as a submodule of MISP and has been fetched earlier.
# Install CakeResque along with its dependencies if you intend to use the built in background jobs:
cd /var/www/htdocs/MISP/app
doas mkdir /var/www/.composer ; doas chown www:www /var/www/.composer
${SUDO_WWW} env HOME=/var/www php composer.phar install --no-dev

# To use the scheduler worker for scheduled tasks, do the following:
${SUDO_WWW} cp -f /var/www/htdocs/MISP/INSTALL/setup/config.php /var/www/htdocs/MISP/app/Plugin/CakeResque/Config/config.php
```

### 4/ Set the permissions
----------------------
```bash
# Check if the permissions are set correctly using the following commands:
doas chown -R www:www /var/www/htdocs/MISP
doas chmod -R 750 /var/www/htdocs/MISP
doas chmod -R g+ws /var/www/htdocs/MISP/app/tmp
doas chmod -R g+ws /var/www/htdocs/MISP/app/files
doas chmod -R g+ws /var/www/htdocs/MISP/app/files/scripts/tmp
```

### 5/ Create a database and user
-----------------------------
```bash
# Enter the mysql shell
doas mysql -u root -p
```

```
echo "Admin (${DBUSER_ADMIN}) DB Password: ${DBPASSWORD_ADMIN}"
echo "User  (${DBUSER_MISP}) DB Password: ${DBPASSWORD_MISP}"

MariaDB [(none)]> create database misp;
MariaDB [(none)]> grant usage on *.* to misp@localhost identified by '${DBPASSWORD_MISP}';
MariaDB [(none)]> grant all privileges on misp.* to misp@localhost;
MariaDB [(none)]> flush privileges;
MariaDB [(none)]> exit
```

```bash
# Import the empty MISP database from MYSQL.sql
${SUDO_WWW} sh -c "mysql -u misp -p${DBPASSWORD_MISP} misp < /var/www/htdocs/MISP/INSTALL/MYSQL.sql"
# enter the password you set previously
```

### 6/ Apache configuration (optional)
-----------------------
```bash
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
-subj "/C=$OPENSSL_C/ST=$OPENSSL_ST/L=$OPENSSL_L/O=<$OPENSSL_O/OU=$OPENSSL_OU/CN=$OPENSSL_CN/emailAddress=$OPENSSL_EMAILADDRESS" \
-keyout /etc/ssl/private/server.key -out /etc/ssl/server.crt
# Otherwise, copy the SSLCertificateFile, SSLCertificateKeyFile, and SSLCertificateChainFile to /etc/ssl/private/. (Modify path and config to fit your environment)

doas mkdir /var/log/apache2/
```

```
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
        SSLCertificateFile /etc/ssl/server.crt
        SSLCertificateKeyFile /etc/ssl/private/server.key
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
cd /etc/apache2/sites-enabled/
doas ln -s ../sites-available/misp-ssl.conf
echo "Include /etc/apache2/sites-enabled/*.conf" |doas tee -a /etc/apache2/httpd2.conf

doas vi /etc/apache2/httpd2.conf
```

```
/!\ Enable mod_rewrite in httpd2.conf /!\
LoadModule rewrite_module /usr/local/lib/apache2/mod_rewrite.so
LoadModule ssl_module /usr/local/lib/apache2/mod_ssl.so
LoadModule proxy_module /usr/local/lib/apache2/mod_proxy.so
LoadModule proxy_fcgi_module /usr/local/lib/apache2/mod_proxy_fcgi.so
LoadModule socache_shmcb_module /usr/local/lib/apache2/socache_shmcb_module.so
Listen 443
DirectoryIndex index.php
```

```bash
doas ln -sf /var/www/conf/modules.sample/php-7.4.conf /var/www/conf/modules/php.conf
# Restart apache
doas /etc/rc.d/apache2 restart
``` 

### 7/ Log rotation (needs to be adapted to OpenBSD, newsyslog does this for you
---------------
!!! notice
    MISP saves the stdout and stderr of its workers in /var/www/htdocs/MISP/app/tmp/logs

### 8/ MISP configuration
---------------------
``` 
# There are 4 sample configuration files in /var/www/htdocs/MISP/app/Config that need to be copied
${SUDO_WWW} cp /var/www/htdocs/MISP/app/Config/bootstrap.default.php /var/www/htdocs/MISP/app/Config/bootstrap.php
${SUDO_WWW} cp /var/www/htdocs/MISP/app/Config/database.default.php /var/www/htdocs/MISP/app/Config/database.php
${SUDO_WWW} cp /var/www/htdocs/MISP/app/Config/core.default.php /var/www/htdocs/MISP/app/Config/core.php
${SUDO_WWW} cp /var/www/htdocs/MISP/app/Config/config.default.php /var/www/htdocs/MISP/app/Config/config.php

# Configure the fields in the newly created files:
${SUDO_WWW} vi /var/www/htdocs/MISP/app/Config/database.php
``` 
``` 
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
``` 

!!! danger
    Important! Change the salt key in /usr/local/www/MISP/app/Config/config.php
    The salt key must be a string at least 32 bytes long.
    The admin user account will be generated on the first login, make sure that the salt is changed before you create that user
    If you forget to do this step, and you are still dealing with a fresh installation, just alter the salt,
    delete the user from mysql and log in again using the default admin credentials (admin@admin.test / admin)

``` 
# Change base url in config.php
${SUDO_WWW} vi /var/www/htdocs/MISP/app/Config/config.php
# example: 'baseurl' => 'https://<your.FQDN.here>',
# alternatively, you can leave this field empty if you would like to use relative pathing in MISP
# 'baseurl' => '',

# and make sure the file permissions are still OK
doas chown -R www:www /var/www/htdocs/MISP/app/Config
doas chmod -R 750 /var/www/htdocs/MISP/app/Config

# Generate a GPG encryption key.
export GPG_REAL_NAME='Autogenerated Key'
export GPG_COMMENT='WARNING: MISP AutoGenerated Key consider this Key VOID!'
export GPG_EMAIL_ADDRESS='admin@admin.test'
export GPG_KEY_LENGTH='2048'
export GPG_PASSPHRASE='Password1234'
echo "%echo Generating a default key
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
%echo done" > /tmp/gen-key-script
${SUDO_WWW} mkdir /var/www/htdocs/MISP/.gnupg
doas chmod 700 /var/www/htdocs/MISP/.gnupg
doas gpg2 --homedir /var/www/htdocs/MISP/.gnupg --batch --gen-key /tmp/gen-key-script
# The email address should match the one set in the config.php / set in the configuration menu in the administration menu configuration file

# And export the public key to the webroot
doas sh -c "gpg2 --homedir /var/www/htdocs/MISP/.gnupg --export --armor $GPG_EMAIL_ADDRESS > /var/www/htdocs/MISP/app/webroot/gpg.asc"

# To make the background workers start on boot
doas chmod +x /var/www/htdocs/MISP/app/Console/worker/start.sh
doas vi /etc/rc.local
# Add the following line before the last line (exit 0). Make sure that you replace www with your apache user:
${SUDO_WWW} bash /var/www/htdocs/MISP/app/Console/worker/start.sh
``` 

{% include_relative generic/INSTALL.done.md %}

{% include_relative generic/recommended.actions.md %}

#### MISP Modules
```
doas pkg_add -v jpeg yara
mkdir -p /usr/local/src/
cd /usr/local/src/
doas chown ${MISP_USER} /usr/local/src
doas -u misp git clone https://github.com/MISP/misp-modules.git
cd misp-modules
$SUDO_WWW git config core.filemode false
# pip3 install
doas /usr/local/virtualenvs/MISP/bin/pip install -I -r REQUIREMENTS
doas /usr/local/virtualenvs/MISP/bin/pip install -I .
doas /usr/local/virtualenvs/MISP/bin/pip install git+https://github.com/VirusTotal/yara-python.git
doas /usr/local/virtualenvs/MISP/bin/pip install wand
##doas gem install pygments.rb
##doas gem install asciidoctor-pdf --pre
${SUDO_WWW} /usr/local/virtualenvs/MISP/bin/misp-modules -l 0.0.0.0 -s &
echo "${SUDO_WWW} /usr/local/virtualenvs/MISP/bin/misp-modules -l 0.0.0.0 -s &" |doas tee -a /etc/rc.local
```

!!! notice
    Make sure that the STIX libraries and GnuPG work as intended, if not, refer to INSTALL.txt's paragraphs dealing with these two items

!!! notice
    If anything goes wrong, make sure that you check MISP's logs for errors:
    /var/www/htdocs/MISP/app/tmp/logs/error.log
    /var/www/htdocs/MISP/app/tmp/logs/resque-worker-error.log
    /var/www/htdocs/MISP/app/tmp/logs/resque-scheduler-error.log
    /var/www/htdocs/MISP/app/tmp/logs/resque-2015-01-01.log // where the actual date is the current date


#### MISP Config Automation

```bash
doas $CAKE Live $MISP_LIVE
AUTH_KEY=$(mysql -u misp -p${DBPASSWORD_MISP} misp -e "SELECT authkey FROM users;" | tail -1)
$CAKE userInit -q
$CAKE Admin runUpdates
$CAKE Admin setSetting "MISP.python_bin" "/usr/local/virtualenvs/MISP/bin/python"

# Update the galaxies…
doas $CAKE Admin updateGalaxies

# Updating the taxonomies…
doas $CAKE Admin updateTaxonomies

# Updating the warning lists…
doas $CAKE Admin updateWarningLists

# Updating the notice lists…
doas $CAKE Admin updateNoticeLists

# Updating the object templates…
doas $CAKE Admin updateObjectTemplates "1337"

# Tune global time outs
doas $CAKE Admin setSetting "Session.autoRegenerate" 0
doas $CAKE Admin setSetting "Session.timeout" 600
doas $CAKE Admin setSetting "Session.cookie_timeout" 3600

# Enable GnuPG
doas $CAKE Admin setSetting "GnuPG.email" "admin@admin.test"
doas $CAKE Admin setSetting "GnuPG.homedir" "${PATH_TO_MISP}/.gnupg"
doas $CAKE Admin setSetting "GnuPG.password" "Password1234"

# Enable Enrichment set better timeouts
doas $CAKE Admin setSetting "Plugin.Enrichment_services_enable" true
doas $CAKE Admin setSetting "Plugin.Enrichment_hover_enable" true
doas $CAKE Admin setSetting "Plugin.Enrichment_timeout" 300
doas $CAKE Admin setSetting "Plugin.Enrichment_hover_timeout" 150
doas $CAKE Admin setSetting "Plugin.Enrichment_cve_enabled" true
doas $CAKE Admin setSetting "Plugin.Enrichment_dns_enabled" true
doas $CAKE Admin setSetting "Plugin.Enrichment_services_url" "http://127.0.0.1"
doas $CAKE Admin setSetting "Plugin.Enrichment_services_port" 6666

# Enable Import modules set better timeout
doas $CAKE Admin setSetting "Plugin.Import_services_enable" true
doas $CAKE Admin setSetting "Plugin.Import_services_url" "http://127.0.0.1"
doas $CAKE Admin setSetting "Plugin.Import_services_port" 6666
doas $CAKE Admin setSetting "Plugin.Import_timeout" 300
doas $CAKE Admin setSetting "Plugin.Import_ocr_enabled" true
doas $CAKE Admin setSetting "Plugin.Import_csvimport_enabled" true

# Enable Export modules set better timeout
doas $CAKE Admin setSetting "Plugin.Export_services_enable" true
doas $CAKE Admin setSetting "Plugin.Export_services_url" "http://127.0.0.1"
doas $CAKE Admin setSetting "Plugin.Export_services_port" 6666
doas $CAKE Admin setSetting "Plugin.Export_timeout" 300
doas $CAKE Admin setSetting "Plugin.Export_pdfexport_enabled" true

# Enable installer org and tune some configurables
doas $CAKE Admin setSetting "MISP.host_org_id" 1
doas $CAKE Admin setSetting "MISP.email" "info@admin.test"
doas $CAKE Admin setSetting "MISP.disable_emailing" true
doas $CAKE Admin setSetting "MISP.contact" "info@admin.test"
doas $CAKE Admin setSetting "MISP.disablerestalert" true
doas $CAKE Admin setSetting "MISP.showCorrelationsOnIndex" true

# Provisional Cortex tunes
doas $CAKE Admin setSetting "Plugin.Cortex_services_enable" false
doas $CAKE Admin setSetting "Plugin.Cortex_services_url" "http://127.0.0.1"
doas $CAKE Admin setSetting "Plugin.Cortex_services_port" 9000
doas $CAKE Admin setSetting "Plugin.Cortex_timeout" 120
doas $CAKE Admin setSetting "Plugin.Cortex_services_url" "http://127.0.0.1"
doas $CAKE Admin setSetting "Plugin.Cortex_services_port" 9000
doas $CAKE Admin setSetting "Plugin.Cortex_services_timeout" 120
doas $CAKE Admin setSetting "Plugin.Cortex_services_authkey" ""
doas $CAKE Admin setSetting "Plugin.Cortex_ssl_verify_peer" false
doas $CAKE Admin setSetting "Plugin.Cortex_ssl_verify_host" false
doas $CAKE Admin setSetting "Plugin.Cortex_ssl_allow_self_signed" true

# Various plugin sightings settings
doas $CAKE Admin setSetting "Plugin.Sightings_policy" 0
doas $CAKE Admin setSetting "Plugin.Sightings_anonymise" false
doas $CAKE Admin setSetting "Plugin.Sightings_range" 365

# Plugin CustomAuth tuneable
doas $CAKE Admin setSetting "Plugin.CustomAuth_disable_logout" false

# RPZ Plugin settings

doas $CAKE Admin setSetting "Plugin.RPZ_policy" "DROP"
doas $CAKE Admin setSetting "Plugin.RPZ_walled_garden" "127.0.0.1"
doas $CAKE Admin setSetting "Plugin.RPZ_serial" "\$date00"
doas $CAKE Admin setSetting "Plugin.RPZ_refresh" "2h"
doas $CAKE Admin setSetting "Plugin.RPZ_retry" "30m"
doas $CAKE Admin setSetting "Plugin.RPZ_expiry" "30d"
doas $CAKE Admin setSetting "Plugin.RPZ_minimum_ttl" "1h"
doas $CAKE Admin setSetting "Plugin.RPZ_ttl" "1w"
doas $CAKE Admin setSetting "Plugin.RPZ_ns" "localhost."
doas $CAKE Admin setSetting "Plugin.RPZ_ns_alt" ""
doas $CAKE Admin setSetting "Plugin.RPZ_email" "root.localhost"

# Force defaults to make MISP Server Settings less RED
doas $CAKE Admin setSetting "MISP.language" "eng"
doas $CAKE Admin setSetting "MISP.proposals_block_attributes" false

## Redis block
doas $CAKE Admin setSetting "MISP.redis_host" "127.0.0.1"
doas $CAKE Admin setSetting "MISP.redis_port" 6379
doas $CAKE Admin setSetting "MISP.redis_database" 13
doas $CAKE Admin setSetting "MISP.redis_password" ""

# Force defaults to make MISP Server Settings less YELLOW
doas $CAKE Admin setSetting "MISP.ssdeep_correlation_threshold" 40
doas $CAKE Admin setSetting "MISP.extended_alert_subject" false
doas $CAKE Admin setSetting "MISP.default_event_threat_level" 4
doas $CAKE Admin setSetting "MISP.newUserText" "Dear new MISP user,\\n\\nWe would hereby like to welcome you to the \$org MISP community.\\n\\n Use the credentials below to log into MISP at \$misp, where you will be prompted to manually change your password to something of your own choice.\\n\\nUsername: \$username\\nPassword: \$password\\n\\nIf you have any questions, don't hesitate to contact us at: \$contact.\\n\\nBest regards,\\nYour \$org MISP support team"
doas $CAKE Admin setSetting "MISP.passwordResetText" "Dear MISP user,\\n\\nA password reset has been triggered for your account. Use the below provided temporary password to log into MISP at \$misp, where you will be prompted to manually change your password to something of your own choice.\\n\\nUsername: \$username\\nYour temporary password: \$password\\n\\nIf you have any questions, don't hesitate to contact us at: \$contact.\\n\\nBest regards,\\nYour \$org MISP support team"
doas $CAKE Admin setSetting "MISP.enableEventBlacklisting" true
doas $CAKE Admin setSetting "MISP.enableOrgBlacklisting" true
doas $CAKE Admin setSetting "MISP.log_client_ip" false
doas $CAKE Admin setSetting "MISP.log_auth" false
doas $CAKE Admin setSetting "MISP.disableUserSelfManagement" false
doas $CAKE Admin setSetting "MISP.block_event_alert" false
doas $CAKE Admin setSetting "MISP.block_event_alert_tag" "no-alerts=\"true\""
doas $CAKE Admin setSetting "MISP.block_old_event_alert" false
doas $CAKE Admin setSetting "MISP.block_old_event_alert_age" ""
doas $CAKE Admin setSetting "MISP.incoming_tags_disabled_by_default" false
doas $CAKE Admin setSetting "MISP.footermidleft" "This is an initial install"
doas $CAKE Admin setSetting "MISP.footermidright" "Please configure and harden accordingly"
doas $CAKE Admin setSetting "MISP.welcome_text_top" "Initial Install, please configure"
doas $CAKE Admin setSetting "MISP.welcome_text_bottom" "Welcome to MISP, change this message in MISP Settings"

# Force defaults to make MISP Server Settings less GREEN
doas $CAKE Admin setSetting "Security.password_policy_length" 12
doas $CAKE Admin setSetting "Security.password_policy_complexity" '/^((?=.*\d)|(?=.*\W+))(?![\n])(?=.*[A-Z])(?=.*[a-z]).*$|.{16,}/'
# Tune global time outs
doas $CAKE Admin setSetting "Session.autoRegenerate" 0
doas $CAKE Admin setSetting "Session.timeout" 600
doas $CAKE Admin setSetting "Session.cookie_timeout" 3600
```

### Recommended actions
-------------------
- By default CakePHP exposes its name and version in email headers. Apply a patch to remove this behavior.

- You should really harden your OS
- You should really harden the configuration of Apache/httpd
- You should really harden the configuration of MySQL/MariaDB
- Keep your software up2date (OS, MISP, CakePHP and everything else)
- Log and audit


### Optional features
-------------------

!!! notice
    MISP has a pub/sub feature, using ZeroMQ.

#### ZeroMQ depends on the Python client for Redis
```bash
doas pkg_add -v py3-zmq zeromq
doas /usr/local/virtualenvs/MISP/bin/pip install pyzmq
```

#### misp-dashboard 

!!! notice
    Enable ZeroMQ for misp-dashboard

!!! warning
    This still needs more testing, it runs but no data is showing.


!!! warning
    The install_dependencies.sh script is for Linux ONLY. The following blurp will be a diff of a working OpenBSD version.

```diff
(DASHENV) obsd# diff -u install_dependencies.sh install_dependencies_obsd.sh  
--- install_dependencies.sh     Fri Oct 19 12:14:38 2018
+++ install_dependencies_obsd.sh        Fri Oct 19 12:43:22 2018
@@ -1,14 +1,14 @@
-#!/bin/bash
+#!/usr/local/bin/bash
 
 set -e
 #set -x
 
-sudo apt-get install python3-virtualenv virtualenv screen redis-server unzip -y
+doas pkg_add -v unzip wget
 
 if [ -z "$VIRTUAL_ENV" ]; then
-    virtualenv -p python3 DASHENV
+    virtualenv -p python3 /usr/local/virtualenvs/DASHENV
 
-    . ./DASHENV/bin/activate
+    . /usr/local/virtualenvs/DASHENV/bin/activate
 fi
 
 pip3 install -U pip argparse redis zmq geoip2 flask phonenumbers pycountry
```

```
cd /var/www
doas mkdir misp-dashboard
doas chown www:www misp-dashboard
${SUDO_WWW} git clone https://github.com/MISP/misp-dashboard.git
cd misp-dashboard
$SUDO_WWW git config core.filemode false
#/!\ Made on Linux, the next script will fail
#doas /var/www/misp-dashboard/install_dependencies.sh
doas virtualenv -ppython3 /usr/local/virtualenvs/DASHENV
doas /usr/local/virtualenvs/DASHENV/bin/pip install -U pip argparse redis zmq geoip2 flask phonenumbers pycountry

doas sed -i "s/^host\ =\ localhost/host\ =\ 0.0.0.0/g" /var/www/misp-dashboard/config/config.cfg
doas sed -i -e '$i \${SUDO_WWW} bash /var/www/misp-dashboard/start_all.sh\n' /etc/rc.local
#/!\ Add port 8001 as a listener
#doas sed -i '/Listen 80/a Listen 0.0.0.0:8001' /etc/apache2/ports.conf
doas pkg_add -v ap2-mod_wsgi

echo "<VirtualHost *:8001>
    ServerAdmin admin@misp.local
    ServerName misp.local
    DocumentRoot /var/www/misp-dashboard
    
    WSGIDaemonProcess misp-dashboard \
       user=misp group=misp \
       python-home=/var/www/misp-dashboard/DASHENV \
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
    WSGIScriptAlias / /var/www/misp-dashboard/misp-dashboard.wsgi
    <Directory /var/www/misp-dashboard>
        WSGIProcessGroup misp-dashboard
        WSGIApplicationGroup %{GLOBAL}
        Require all granted
    </Directory>
    LogLevel info
    ErrorLog /var/log/apache2/misp-dashboard.local_error.log
    CustomLog /var/log/apache2/misp-dashboard.local_access.log combined
    ServerSignature Off
</VirtualHost>" | doas tee /etc/apache2/sites-available/misp-dashboard.conf

doas ln -s /etc/apache2/sites-available/misp-dashboard.conf /etc/apache2/sites-enabled/misp-dashboard.conf
```

Add this to /etc/httpd.conf
```
LoadModule wsgi_module /usr/local/lib/apache2/mod_wsgi.so
Listen 8001
```


```
doas $CAKE Admin setSetting "Plugin.ZeroMQ_enable" true
doas $CAKE Admin setSetting "Plugin.ZeroMQ_event_notifications_enable" true
doas $CAKE Admin setSetting "Plugin.ZeroMQ_object_notifications_enable" true
doas $CAKE Admin setSetting "Plugin.ZeroMQ_object_reference_notifications_enable" true
doas $CAKE Admin setSetting "Plugin.ZeroMQ_attribute_notifications_enable" true
doas $CAKE Admin setSetting "Plugin.ZeroMQ_sighting_notifications_enable" true
doas $CAKE Admin setSetting "Plugin.ZeroMQ_user_notifications_enable" true
doas $CAKE Admin setSetting "Plugin.ZeroMQ_organisation_notifications_enable" true
doas $CAKE Admin setSetting "Plugin.ZeroMQ_port" 50000
doas $CAKE Admin setSetting "Plugin.ZeroMQ_redis_host" "localhost"
doas $CAKE Admin setSetting "Plugin.ZeroMQ_redis_port" 6379
doas $CAKE Admin setSetting "Plugin.ZeroMQ_redis_database" 1
doas $CAKE Admin setSetting "Plugin.ZeroMQ_redis_namespace" "mispq"
doas $CAKE Admin setSetting "Plugin.ZeroMQ_include_attachments" false
doas $CAKE Admin setSetting "Plugin.ZeroMQ_tag_notifications_enable" false
doas $CAKE Admin setSetting "Plugin.ZeroMQ_audit_notifications_enable" false
```

{% include_relative generic/hardening.md %}
