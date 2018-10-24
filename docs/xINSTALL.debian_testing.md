# INSTALLATION INSTRUCTIONS
## for Debian testing "buster" server

### 0/ MISP testing dev install - Status
------------------------------------

!!! notice
    This is mostly the install [@SteveClement](https://twitter.com/SteveClement)
    uses for testing, qc and random development.
    Maintained and tested by @SteveClement on 20181023

!!! warning
    PHP 7.3.0RC2 is not working at the moment. Please us 7.2<br />
    **php-gnupg** and **php-redis** pull in PHP 7.3 thus they are installed with **pecl**

{!generic/globalVariables.md!}

```bash
PHP_INI=/etc/php/7.2/apache2/php.ini
```

### 1/ Minimal Debian install
-------------------------

#### Install a minimal Debian testing "buster" server system with the software:
- OpenSSH server
- Web server, apache FTW!
- This guide assumes a user name of 'misp'

#### install etckeeper and sudo (optional)
```bash
su -
apt install -y etckeeper
apt install -y sudo
adduser misp sudo
# Add the user to the staff group to be able to write to /usr/local/src
adduser misp staff
```

#### Make sure your system is up2date
```bash
sudo apt update
sudo apt -y dist-upgrade
```

#### Network Interface Name salvage (optional)

This will bring back 'ethX' e.g: eth0

```bash
GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0"
DEFAULT_GRUB=/etc/default/grub
for key in GRUB_CMDLINE_LINUX
do
    sudo sed -i "s/^\($key\)=.*/\1=\"$(eval echo \${$key})\"/" $DEFAULT_GRUB
done
sudo grub-mkconfig -o /boot/grub/grub.cfg
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

```bash
sudo apt install -y \
curl gcc git gnupg-agent make openssl redis-server neovim zip libyara-dev \
python3-setuptools python3-dev python3-pip python3-yara python3-redis python3-zmq virtualenv \
mariadb-client \
mariadb-server \
apache2 apache2-doc apache2-utils \
libapache2-mod-php7.2 php7.2 php7.2-cli php7.2-mbstring php7.2-dev php7.2-json php7.2-xml php7.2-mysql php7.2-opcache php7.2-readline \
libpq5 libjpeg-dev libfuzzy-dev ruby asciidoctor \
jq ntp ntpdate jupyter-notebook imagemagick tesseract-ocr \
libxml2-dev libxslt1-dev zlib1g-dev

# Start rng-tools to get more entropy (optional)
# If you get TPM errors, enable "Security chip" in BIOS (keep secure boot disabled)
# On virtual machines this might fail by default. haveged should work
sudo apt install rng-tools haveged -y
sudo service rng-tools start

sudo apt install expect -y

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
sudo apt-get purge -y expect ; sudo apt autoremove -y

# Enable modules, settings, and default of SSL in Apache
sudo a2dismod status
sudo a2enmod ssl rewrite
sudo a2dissite 000-default
sudo a2ensite default-ssl

# Switch to python3 by default (optional)

sudo update-alternatives --install /usr/bin/python python /usr/bin/python2.7 1
sudo update-alternatives --install /usr/bin/python python /usr/bin/python3.6 2
```

To flip between the 2 pythons use *update-alternatives*
```bash
sudo update-alternatives --config python
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
sudo chown www-data:www-data $PATH_TO_MISP
cd $PATH_TO_MISP
sudo -u www-data git clone https://github.com/MISP/MISP.git $PATH_TO_MISP

#### Make git ignore filesystem permission differences
sudo -u www-data git config core.filemode false

#### Create a python3 virtualenv

sudo -u www-data virtualenv -p python3 /var/www/MISP/venv
sudo mkdir /var/www/.cache/
sudo chown www-data:www-data /var/www/.cache

cd $PATH_TO_MISP/app/files/scripts
sudo -u www-data git clone https://github.com/CybOXProject/python-cybox.git
sudo -u www-data git clone https://github.com/STIXProject/python-stix.git
sudo -u www-data git clone https://github.com/MAECProject/python-maec.git
cd $PATH_TO_MISP/app/files/scripts/python-cybox
sudo -u www-data /var/www/MISP/venv/bin/pip install .
cd $PATH_TO_MISP/app/files/scripts/python-stix
sudo -u www-data /var/www/MISP/venv/bin/pip install .
cd $PATH_TO_MISP/app/files/scripts/python-maec
sudo -u www-data /var/www/MISP/venv/bin/pip install .

# install mixbox to accomodate the new STIX dependencies:
cd $PATH_TO_MISP/app/files/scripts/
sudo -u www-data git clone https://github.com/CybOXProject/mixbox.git
cd $PATH_TO_MISP/app/files/scripts/mixbox
sudo -u www-data /var/www/MISP/venv/bin/pip install .

cd $PATH_TO_MISP
sudo -u www-data git submodule update --init --recursive
# Make git ignore filesystem permission differences for submodules
sudo -u www-data git submodule foreach --recursive git config core.filemode false

# install PyMISP
cd $PATH_TO_MISP/PyMISP
sudo -u www-data /var/www/MISP/venv/bin/pip install .
```

### 4/ CakePHP
-----------
#### CakePHP is included as a submodule of MISP.

!!! warning
    PHP Warning:  PHP Startup: Unable to load dynamic library 'redis.so' (tried: /usr/lib/php/20170718/redis.so (/usr/lib/php/20170718/redis.so: cannot open shared object file: No such file or directory), /usr/lib/php/20170718/redis.so.so (/usr/lib/php/20170718/redis.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0<br />
    This probably means you installed the package **php-redis** which pulls in PHP-7.3 which is not working yet. Please install with **pecl**

```bash
# Install CakeResque along with its dependencies if you intend to use the built in background jobs:
cd $PATH_TO_MISP/app
# Make composer cache happy
sudo mkdir /var/www/.composer ; sudo chown www-data:www-data /var/www/.composer
sudo -u www-data php composer.phar require kamisama/cake-resque:4.1.2
sudo -u www-data php composer.phar config vendor-dir Vendor
sudo -u www-data php composer.phar install

## /!\ This will only be possible once PHP 7.3 works with composer
### Enable CakeResque with php-redis
##sudo phpenmod redis

# To use the scheduler worker for scheduled tasks, do the following:
sudo -u www-data cp -fa $PATH_TO_MISP/INSTALL/setup/config.php $PATH_TO_MISP/app/Plugin/CakeResque/Config/config.php
```


### 5/ Set the permissions
----------------------

```bash
# Check if the permissions are set correctly using the following commands:
sudo chown -R www-data:www-data $PATH_TO_MISP
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
sudo -u www-data cat $PATH_TO_MISP/INSTALL/MYSQL.sql | mysql -u $DBUSER_MISP -p$DBPASSWORD_MISP $DBNAME
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

# Install PHP external dependencies
sudo pecl channel-update pecl.php.net
yes no |sudo pecl install redis
# gnupg dependency
sudo apt-get install libgpgme11-dev -y
sudo pecl install gnupg

echo "extension=redis.so" | sudo tee /etc/php/7.2/mods-available/redis.ini
echo "extension=gnupg.so" | sudo tee /etc/php/7.2/mods-available/gnupg.ini

sudo phpenmod redis
sudo phpenmod gnupg

# Recommended: Change some PHP settings in /etc/php/7.2/apache2/php.ini
# max_execution_time = 300
# memory_limit = 512M
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
sudo -u www-data cp -a $PATH_TO_MISP/app/Config/bootstrap.default.php $PATH_TO_MISP/app/Config/bootstrap.php
sudo -u www-data cp -a $PATH_TO_MISP/app/Config/database.default.php $PATH_TO_MISP/app/Config/database.php
sudo -u www-data cp -a $PATH_TO_MISP/app/Config/core.default.php $PATH_TO_MISP/app/Config/core.php
sudo -u www-data cp -a $PATH_TO_MISP/app/Config/config.default.php $PATH_TO_MISP/app/Config/config.php


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
}" | sudo -u www-data tee $PATH_TO_MISP/app/Config/database.php

# and make sure the file permissions are still OK
sudo chown -R www-data:www-data $PATH_TO_MISP/app/Config
sudo chmod -R 750 $PATH_TO_MISP/app/Config

# Set some MISP directives with the command line tool

# Change base url
sudo $CAKE Baseurl $MISP_BASEURL

# example: 'baseurl' => 'https://<your.FQDN.here>',
# alternatively, you can leave this field empty if you would like to use relative pathing in MISP
# 'baseurl' => '',

# and make sure the file permissions are still OK
sudo chown -R www-data:www-data $PATH_TO_MISP/app/Config
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

sudo -u www-data gpg --homedir $PATH_TO_MISP/.gnupg --batch --gen-key /tmp/gen-key-script
# The email address should match the one set in the config.php / set in the configuration menu in the administration menu configuration file

# And export the public key to the webroot
sudo -u www-data sh -c "gpg --homedir $PATH_TO_MISP/.gnupg --export --armor $GPG_EMAIL_ADDRESS" | sudo -u www-data tee $PATH_TO_MISP/app/webroot/gpg.asc

# To make the background workers start on boot
sudo chmod +x $PATH_TO_MISP/app/Console/worker/start.sh
if [ ! -e /etc/rc.local ]
then
    echo '#!/bin/sh -e' | sudo tee -a /etc/rc.local
    echo 'exit 0' | sudo tee -a /etc/rc.local
    sudo chmod u+x /etc/rc.local
fi
```
{!generic/MISP_CAKE_init.md!}

```bash
# Add the following lines before the last line (exit 0). Make sure that you replace www-data with your apache user:
sudo sed -i -e '$i \echo never > /sys/kernel/mm/transparent_hugepage/enabled\n' /etc/rc.local
sudo sed -i -e '$i \echo 1024 > /proc/sys/net/core/somaxconn\n' /etc/rc.local
sudo sed -i -e '$i \sysctl vm.overcommit_memory=1\n' /etc/rc.local
sudo sed -i -e '$i \sudo -u www-data bash /var/www/MISP/app/Console/worker/start.sh > /tmp/worker_start_rc.local.log\n' /etc/rc.local
sudo sed -i -e '$i \sudo -u www-data /var/www/MISP/venv/bin/misp-modules -l 127.0.0.1 -s > /tmp/misp-modules_rc.local.log &\n' /etc/rc.local

# Start the workers
sudo -u www-data bash $PATH_TO_MISP/app/Console/worker/start.sh

# some misp-modules dependencies
sudo apt-get install -y libpq5 libjpeg-dev libfuzzy-dev

sudo chmod 2775 /usr/local/src
sudo chown root:staff /usr/local/src
cd /usr/local/src/
git clone https://github.com/MISP/misp-modules.git
cd misp-modules
# pip install
sudo -u www-data /var/www/MISP/venv/bin/pip install -I -r REQUIREMENTS
sudo -u www-data /var/www/MISP/venv/bin/pip install .
sudo apt install ruby-pygments.rb -y
sudo gem install asciidoctor-pdf --pre

# install STIX2.0 library to support STIX 2.0 export:
sudo -u www-data /var/www/MISP/venv/bin/pip install stix2

# install additional dependencies for extended object generation and extraction
sudo -u www-data /var/www/MISP/venv/bin/pip install maec lief python-magic pathlib
sudo -u www-data /var/www/MISP/venv/bin/pip install git+https://github.com/kbandla/pydeep.git

# Start misp-modules
## /!\ Check wtf is going on with yara.
sudo -u www-data /var/www/MISP/venv/bin/misp-modules -l 0.0.0.0 -s &

echo "Admin (root) DB Password: $DBPASSWORD_ADMIN"
echo "User  (misp) DB Password: $DBPASSWORD_MISP"
```

!!! notice
    Now log in using the webinterface:<br />
    The default user/pass = admin@admin.test/admin<br />
    Using the server settings tool in the admin interface (Administration -> Server Settings), set MISP up to your preference<br />
    It is especially vital that no critical issues remain!<br />
    Don't forget to change the email, password and authentication key after installation.

!!! notice
    Start the workers by navigating to the workers tab and clicking restart all workers

!!! notice
    Once done, have a look at the diagnostics
    If any of the directories that MISP uses to store files is not writeable to the apache user, change the permissions
    you can do this by running the following commands:
    ```
    sudo chmod -R 750 $PATH_TO_MISP/<directory path with an indicated issue>
    sudo chown -R www-data:www-data $PATH_TO_MISP/<directory path with an indicated issue>
    ```

!!! warning
    Make sure that the STIX libraries and GnuPG work as intended, if not, refer to INSTALL.txt's paragraphs dealing with these two items

!!! notice
    If anything goes wrong, make sure that you check MISP's logs for errors:
    ```
    # $PATH_TO_MISP/app/tmp/logs/error.log
    # $PATH_TO_MISP/app/tmp/logs/resque-worker-error.log
    # $PATH_TO_MISP/app/tmp/logs/resque-scheduler-error.log
    # $PATH_TO_MISP/app/tmp/logs/resque-2015-01-01.log // where the actual date is the current date
    ```

!!! warning
    If you have install a python virtualenv to the recommended place of */var/www/MISP/venv* set the following MISP configurable
    ```bash
    sudo $CAKE Admin setSetting "MISP.python_bin" "/var/www/MISP/venv/bin/python"
    ```

### Recommended actions
-------------------
- By default CakePHP exposes its name and version in email headers. Apply a patch to remove this behavior.

- You should really harden your OS
- You should really harden the configuration of Apache
- You should really harden the configuration of MySQL/MariaDB
- Keep your software up2date (OS, MISP, CakePHP and everything else)
- Log and audit

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

#### Experimental ssdeep correlations¶

##### installing ssdeep
```
cd /usr/local/src
wget https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/ssdeep-2.14.1.tar.gz
tar zxvf ssdeep-2.14.1.tar.gz
cd ssdeep-2.14.1
./configure
make
sudo make install

#installing ssdeep_php
sudo pecl install ssdeep

# You should add "extension=ssdeep.so" to mods-available - Check /etc/php for your current version
echo "extension=ssdeep.so" | sudo tee /etc/php/7.2/mods-available/ssdeep.ini
sudo phpenmod ssdeep
sudo service apache2 restart
```

#### MISP has a new pub/sub feature, using ZeroMQ. To enable it, simply run the following commands
```bash
# ZeroMQ depends on the Python client for Redis
sudo apt install python3-redis -y

# install pyzmq
sudo apt install python3-zmq -y
```

In case you are using a virtualenv make sure pyzmq is installed therein.
```bash
sudo -u www-data /var/www/MISP/venv/bin/pip install pyzmq
```

#### MISP Dashboard
--------------
```bash
cd /var/www
sudo mkdir misp-dashboard
sudo chown www-data:www-data misp-dashboard
sudo -u www-data git clone https://github.com/MISP/misp-dashboard.git
cd misp-dashboard
sudo /var/www/misp-dashboard/install_dependencies.sh
sudo sed -i "s/^host\ =\ localhost/host\ =\ 0.0.0.0/g" /var/www/misp-dashboard/config/config.cfg
sudo sed -i -e '$i \sudo -u www-data bash /var/www/misp-dashboard/start_all.sh\n' /etc/rc.local
sudo sed -i '/Listen 80/a Listen 0.0.0.0:8001' /etc/apache2/ports.conf
sudo apt install libapache2-mod-wsgi-py3 -y

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
</VirtualHost>" | sudo tee /etc/apache2/sites-available/misp-dashboard.conf

sudo a2ensite misp-dashboard
sudo systemctl reload apache2

# Add misp-dashboard to rc.local to start on boot.
sudo sed -i -e '$i \sudo -u www-data bash /var/www/misp-dashboard/start_all.sh > /tmp/misp-dashboard_rc.local.log\n' /etc/rc.local

# Enable ZeroMQ for misp-dashboard
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


#### Install viper framework (with a virtualenv)
-----------------------
```bash
cd /usr/local/src/
sudo apt-get install -y libssl-dev swig python3-ssdeep p7zip-full unrar-free sqlite python3-pyclamd exiftool radare2 python3-magic python3-sqlalchemy python3-prettytable
git clone https://github.com/viper-framework/viper.git
cd viper
virtualenv -p python3 venv
git submodule update --init --recursive
./venv/bin/pip install scrapy
./venv/bin/pip install -r requirements.txt
sed -i '1 s/^.*$/\#!\/usr\/local\/src\/viper\/venv\/bin\/python/' viper-cli
sed -i '1 s/^.*$/\#!\/usr\/local\/src\/viper\/venv\/bin\/python/' viper-web
## /!\ Check wtf is going on with yara.
###sudo pip3 uninstall yara -y
###./venv/bin/pip uninstall yara -y
/usr/local/src/viper/viper-cli -h
/usr/local/src/viper/viper-web -p 8888 -H 0.0.0.0 &
echo 'PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/usr/local/src/viper"' |sudo tee /etc/environment
sed -i "s/^misp_url\ =/misp_url\ =\ http:\/\/localhost/g" ~/.viper/viper.conf
sed -i "s/^misp_key\ =/misp_key\ =\ $AUTH_KEY/g" ~/.viper/viper.conf
# Reset admin password to: admin/Password1234
sqlite3 ~/.viper/admin.db 'UPDATE auth_user SET password="pbkdf2_sha256$100000$iXgEJh8hz7Cf$vfdDAwLX8tko1t0M1TLTtGlxERkNnltUnMhbv56wK/U="'
# Add viper-web to rc.local to be started on boot
sudo sed -i -e '$i \sudo -u misp /usr/local/src/viper/viper-web -p 8888 -H 0.0.0.0 > /tmp/viper-web_rc.local.log &\n' /etc/rc.local
```

#### Install mail to misp
--------------------
```bash
cd /usr/local/src/
sudo apt-get install -y cmake
git clone https://github.com/MISP/mail_to_misp.git
git clone https://github.com/stricaud/faup.git
cd faup
sudo mkdir -p build
cd build
cmake .. && make
sudo make install
sudo ldconfig
cd ../../
cd mail_to_misp
virtualenv -p python3 venv
./venv/bin/pip install -r requirements.txt
cp mail_to_misp_config.py-example mail_to_misp_config.py

sed -i "s/^misp_url\ =\ 'YOUR_MISP_URL'/misp_url\ =\ 'http:\/\/localhost'/g" /usr/local/src/mail_to_misp/mail_to_misp_config.py
sed -i "s/^misp_key\ =\ 'YOUR_KEY_HERE'/misp_key\ =\ '$AUTH_KEY'/g" /usr/local/src/mail_to_misp/mail_to_misp_config.py
```
