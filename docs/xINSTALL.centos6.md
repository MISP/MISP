 # INSTALLATION INSTRUCTIONS
## for CentOS 6.x

### 0/ MISP CentOS 6 Minimal NetInstall - Status
--------------------------------------------

CentOS 6.10 [NetInstallURL](http://mirrors.sonic.net/centos/6.10/os/x86_64/)

{!generic/globalVariables.md!}

```bash
# CentOS Specific
RUN_PHP='/usr/bin/scl enable rh-php56 '
RUN_PYTHON='/usr/bin/scl enable rh-python36 '

PHP_INI=/etc/opt/rh/rh-php56/php.ini
```

### 1/ Minimal CentOS install
-------------------------

Install a minimal CentOS 6.x system with the software:

- OpenSSH server
- LAMP server (actually, this is done below)
- Mail server


```bash
# Make sure you set your hostname CORRECTLY vs. like an brute (manually in /etc/hostname)
hostnamectl set-hostname misp.local # or whatever you want it to be

# Make sure your system is up2date:
sudo yum update -y
```

### 2/ Dependencies *
----------------
Once the system is installed you can perform the following steps as root or with sudo.

```bash
# We need some packages from the Extra Packages for Enterprise Linux repository
curl -o /tmp/epel.rpm http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm
sudo rpm -Uvh /tmp/epel.rpm

# Since MISP 2.4 PHP 5.5 is a minimal requirement, so we need a newer version than CentOS base provides
# Software Collections is a way do to this, see https://wiki.centos.org/AdditionalResources/Repositories/SCL
sudo yum install centos-release-scl

# Because vim is just so practical
sudo yum install vim

# Install the dependencies:
sudo yum install gcc git httpd zip redis mysql-server python-devel python-pip libxslt-devel zlib-devel

# Install PHP 5.6 from SCL, see https://www.softwarecollections.org/en/scls/rhscl/rh-php56/
sudo yum install rh-php56 rh-php56-php-fpm rh-php56-php-devel rh-php56-php-mysqlnd rh-php56-php-mbstring rh-php56-php-xml rh-php56-php-bcmath

# Install Python 3.6 from SCL, see https://www.softwarecollections.org/en/scls/rhscl/rh-python36/
sudo yum install rh-python36

# rh-php56-php only provided mod_php for httpd24-httpd from SCL
# if we want to use httpd from CentOS base we can use rh-php56-php-fpm instead
sudo chkconfig rh-php56-php-fpm on
sudo service rh-php56-php-fpm start

# php-fpm is accessed using the fcgi interface
sudo yum install mod_fcgid mod_proxy_fcgi

# Start a new shell with rh-php56 enabled
sudo scl enable rh-php56 bash

sudo pear channel-update pear.php.net

sudo pear install Crypt_GPG    # we need version >1.3.0

# GPG needs lots of entropy, haveged provides entropy
sudo yum install haveged
sudo chkconfig haveged on
sudo service haveged start

# Enable and start redis
sudo chkconfig redis on
sudo service redis start
```

### 3/ MISP code
------------
```bash
# Download MISP using git in the /var/www/ directory.
cd /var/www/
sudo git clone https://github.com/MISP/MISP.git
cd /var/www/MISP
sudo git checkout tags/$(git describe --tags `git rev-list --tags --max-count=1`)
# if the last shortcut doesn't work, specify the latest version manually
# example: git checkout tags/v2.4.XY
# the message regarding a "detached HEAD state" is expected behaviour
# (you only have to create a new branch, if you want to change stuff and do a pull request for example)

# Make git ignore filesystem permission differences
sudo git config core.filemode false

# Fetch submodules
cd /var/www/MISP
sudo git submodule update --init --recursive
# Make git ignore filesystem permission differences for submodules
sudo git submodule foreach --recursive git config core.filemode false

# install Mitre's STIX and its dependencies by running the following commands:
sudo yum install python-importlib python-lxml python-dateutil python-six -y
cd /var/www/MISP/app/files/scripts
sudo git clone https://github.com/CybOXProject/python-cybox.git
sudo git clone https://github.com/STIXProject/python-stix.git
cd /var/www/MISP/app/files/scripts/python-cybox
sudo git config core.filemode false
# If you umask is has been changed from the default, it is a good idea to reset it to 0022 before installing python modules
UMASK=$(umask)
umask 0022
sudo $RUN_PYTHON "python3 setup.py install"
cd /var/www/MISP/app/files/scripts/python-stix
sudo git config core.filemode false
sudo $RUN_PYTHON "python3 setup.py install"

# install maec
sudo $RUN_PYTHON "pip install maec"

# install zmq
sudo $RUN_PYTHON "pip install zmq"

# install redis
sudo $RUN_PYTHON "pip install redis"

# install mixbox to accomodate the new STIX dependencies:
cd /var/www/MISP/app/files/scripts/
sudo git clone https://github.com/CybOXProject/mixbox.git
cd /var/www/MISP/app/files/scripts/mixbox
sudo git config core.filemode false
sudo $RUN_PYTHON "python3 setup.py install"

# install PyMISP
cd /var/www/MISP/PyMISP
sudo $RUN_PYTHON "python3 setup.py install"

# Enable python3 for php-fpm
echo 'source scl_source enable rh-python36' | sudo tee -a /etc/opt/rh/rh-php56/sysconfig/php-fpm
sudo sed -i.org -e 's/^;\(clear_env = no\)/\1/' /etc/opt/rh/rh-php56/php-fpm.d/www.conf
sudo service rh-php56-php-fpm restart

umask $UMASK
```


### 4/ CakePHP
-----------
#### CakePHP is now included as a submodule of MISP and has been fetch by a previous step.
#### Install CakeResque along with its dependencies if you intend to use the built in background jobs.
```bash
sudo chown -R apache:apache /var/www/MISP
sudo mkdir /usr/share/httpd/.composer
sudo chown apache:apache /usr/share/httpd/.composer
cd /var/www/MISP/app
sudo -u apache $RUN_PHP "php composer.phar require kamisama/cake-resque:4.1.2"
sudo -u apache $RUN_PHP "php composer.phar config vendor-dir Vendor"
sudo -u apache $RUN_PHP "php composer.phar install"

# CakeResque normally uses phpredis to connect to redis, but it has a (buggy) fallback connector through Redisent. It is highly advised to install phpredis
sudo $RUN_PHP "pecl install redis-2.2.8"
echo "extension=redis.so" |sudo tee /etc/opt/rh/rh-php56/php-fpm.d/redis.ini
sudo ln -s ../php-fpm.d/redis.ini /etc/opt/rh/rh-php56/php.d/99-redis.ini
sudo service rh-php56-php-fpm restart

# If you have not yet set a timezone in php.ini
echo 'date.timezone = "Europe/Luxembourg"' |sudo tee /etc/opt/rh/rh-php56/php-fpm.d/timezone.ini
sudo ln -s ../php-fpm.d/timezone.ini /etc/opt/rh/rh-php56/php.d/99-timezone.ini

# Recommended: Change some PHP settings in /etc/opt/rh/rh-php56/php.ini
# max_execution_time = 300
# memory_limit = 512M
# upload_max_filesize = 50M
# post_max_size = 50M
for key in upload_max_filesize post_max_size max_execution_time max_input_time memory_limit
do
    sudo sed -i "s/^\($key\).*/\1 = $(eval echo \${$key})/" $PHP_INI
done
sudo systemctl restart rh-php56-php-fpm.service
# To use the scheduler worker for scheduled tasks, do the following:
sudo cp -fa /var/www/MISP/INSTALL/setup/config.php /var/www/MISP/app/Plugin/CakeResque/Config/config.php
```

### 5/ Set the permissions
----------------------
```bash
# Make sure the permissions are set correctly using the following commands as root:
sudo chown -R root:apache /var/www/MISP
sudo find /var/www/MISP -type d -exec chmod g=rx {} \;
sudo chmod -R g+r,o= /var/www/MISP
sudo chown apache:apache /var/www/MISP/app/files
sudo chown apache:apache /var/www/MISP/app/files/terms
sudo chown apache:apache /var/www/MISP/app/files/scripts/tmp
sudo chown apache:apache /var/www/MISP/app/Plugin/CakeResque/tmp
sudo chown -R apache:apache /var/www/MISP/app/tmp
sudo chown -R apache:apache /var/www/MISP/app/webroot/img/orgs
sudo chown -R apache:apache /var/www/MISP/app/webroot/img/custom

### 6/ Create a database and user
-----------------------------
```bash
# Enable, start and secure your mysql database server
chkconfig mysqld on
service mysqld start
mysql_secure_installation
# Additionally, it is probably a good idea to make the database server listen on localhost only
# Add the following to the [mysqld] of /etc/my.cnf
# bind-address=127.0.0.1

# Enter the mysql shell
mysql -u root -p
```

```
mysql> create database misp;
mysql> grant usage on *.* to misp@localhost identified by 'XXXXXXXXX';
mysql> grant all privileges on misp.* to misp@localhost ;
mysql> exit
```

#### copy/paste:

```bash
sudo mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e "create database $DBNAME;"
sudo mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e "grant usage on *.* to $DBNAME@localhost identified by '$DBPASSWORD_MISP';"
sudo mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e "grant all privileges on $DBNAME.* to '$DBUSER_MISP'@'localhost';"
sudo mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e "flush privileges;"
```

#### Import the empty MySQL database from MYSQL.sql
```bash
sudo -u apache cat $PATH_TO_MISP/INSTALL/MYSQL.sql | mysql -u $DBUSER_MISP -p$DBPASSWORD_MISP $DBNAME
```


### 7/ Apache configuration
-----------------------
```bash
# Now configure your apache server with the DocumentRoot /var/www/MISP/app/webroot/
# A sample vhost can be found in /var/www/MISP/INSTALL/apache.misp.centos6

sudo cp /var/www/MISP/INSTALL/apache.misp.centos6 /etc/httpd/conf.d/misp.conf

# Allow httpd to connect to the redis server and php-fpm over tcp/ip
sudo setsebool -P httpd_can_network_connect on

# Enable and start the httpd service
sudo chkconfig httpd on
sudo service httpd start

# Open a hole in the iptables firewall
sudo iptables -I INPUT 5 -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
sudo service iptables save

# We seriously recommend using only HTTPS / SSL !
# Add SSL support by running: yum install mod_ssl
# Check out the apache.misp.ssl file for an example
```


```bash
# If a valid SSL certificate is not already created for the server, create a self-signed certificate:
sudo openssl req -newkey rsa:4096 -days 365 -nodes -x509 \
-subj "/C=${OPENSSL_C}/ST=${OPENSSL_ST}/L=${OPENSSL_L}/O=${OPENSSL_O}/OU=${OPENSSL_OU}/CN=${OPENSSL_CN}/emailAddress=${OPENSSL_EMAILADDRESS}" \
-keyout /etc/ssl/private/misp.local.key -out /etc/ssl/private/misp.local.crt
```


### 8/ Log rotation
---------------
```bash
# MISP saves the stdout and stderr of its workers in /var/www/MISP/app/tmp/logs
# To rotate these logs install the supplied logrotate script:

sudo cp INSTALL/misp.logrotate /etc/logrotate.d/misp
sudo chmod 0640 /etc/logrotate.d/misp
```

### 9/ MISP configuration
---------------------
```
# There are 4 sample configuration files in /var/www/MISP/app/Config that need to be copied
cd /var/www/MISP/app/Config
cp -a bootstrap.default.php bootstrap.php
cp -a database.default.php database.php
cp -a core.default.php core.php
cp -a config.default.php config.php

# Configure the fields in the newly created files:
# config.php   : baseurl
# database.php : login, port, password, database

# Important! Change the salt key in /var/www/MISP/app/Config/config.php
# The admin user account will be generated on the first login, make sure that the salt is changed before you create that user
# If you forget to do this step, and you are still dealing with a fresh installation, just alter the salt,
# delete the user from mysql and log in again using the default admin credentials (admin@admin.test / admin)
	
# If you want to be able to change configuration parameters from the webinterface:
sudo chown apache:apache /var/www/MISP/app/Config/config.php

# Generate a GPG encryption key.
# If the following command gives an error message, try it as root from the console
gpg --gen-key
mv ~/.gnupg /var/www/MISP/
chown -R apache:apache /var/www/MISP/.gnupg

# The email address should match the one set in the config.php configuration file
# Make sure that you use the same settings in the MISP Server Settings tool (Described on line 232)

# And export the public key to the webroot
sudo -u apache gpg --homedir /var/www/MISP/.gnupg --export --armor YOUR-EMAIL > /var/www/MISP/app/webroot/gpg.asc

# Start the workers to enable background jobs
sudo chmod +x /var/www/MISP/app/Console/worker/start.sh
su -s /bin/bash apache -c 'scl enable rh-php56 /var/www/MISP/app/Console/worker/start.sh'

# To make the background workers start on boot
vi /etc/rc.local
# Add the following line at the end
su -s /bin/bash apache -c 'scl enable rh-php56 /var/www/MISP/app/Console/worker/start.sh'

{!generic/MISP_CAKE_init_centos.md!}

{!generic/INSTALL.done.md!}

{!generic/recommended.actions.md!}

