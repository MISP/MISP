INSTALLATION INSTRUCTIONS
------------------------- for CentOS 6.x

1/ Minimal CentOS install
-------------------------

Install a minimal CentOS 6.x system with the software:

- OpenSSH server
- LAMP server (actually, this is done below)
- Mail server

# Make sure your system is up2date:
yum update


2/ Dependencies *
----------------
Once the system is installed you can perform the following steps as root:

# We need some packages from the Extra Packages for Enterprise Linux repository
curl -o epel.rpm http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm
rpm -Uvh epel.rpm

# Since MISP 2.4 PHP 5.5 is a minimal requirement, so we need a newer version than CentOS base provides
# Software Collections is a way do to this, see https://wiki.centos.org/AdditionalResources/Repositories/SCL
yum install centos-release-scl

# Because vim is just so practical
yum install vim

# Install the dependencies:
yum install gcc git httpd zip redis mysql-server python-devel python-pip libxslt-devel zlib-devel

# Install PHP 5.6 from SCL, see https://www.softwarecollections.org/en/scls/rhscl/rh-php56/
yum install rh-php56 rh-php56-php-fpm rh-php56-php-devel rh-php56-php-mysqlnd rh-php56-php-mbstring rh-php56-php-xml rh-php56-php-bcmath

# Install Python 3.6 from SCL, see https://www.softwarecollections.org/en/scls/rhscl/rh-python36/
yum install rh-python36

# rh-php56-php only provided mod_php for httpd24-httpd from SCL
# if we want to use httpd from CentOS base we can use rh-php56-php-fpm instead
chkconfig rh-php56-php-fpm on
service rh-php56-php-fpm start

# php-fpm is accessed using the fcgi interface
yum install mod_fcgid mod_proxy_fcgi

# Start a new shell with rh-php56 enabled
scl enable rh-php56 bash

pear channel-update pear.php.net

pear install Crypt_GPG    # we need version >1.3.0

# GPG needs lots of entropy, haveged provides entropy
yum install haveged
chkconfig haveged on
service haveged start

# Enable and start redis
chkconfig redis on
service redis start

3/ MISP code
------------
# Download MISP using git in the /var/www/ directory.
cd /var/www/
git clone https://github.com/MISP/MISP.git

# Make git ignore filesystem permission differences
cd /var/www/MISP
git config core.filemode false

# Start new shell with python 3 enabled
scl enable rh-python36 bash

# install Mitre's STIX and its dependencies by running the following commands:
yum install python-importlib python-lxml python-dateutil python-six
cd /var/www/MISP/app/files/scripts
git clone https://github.com/CybOXProject/python-cybox.git
git clone https://github.com/STIXProject/python-stix.git
cd /var/www/MISP/app/files/scripts/python-cybox
git config core.filemode false
# If you umask is has been changed from the default, it is a good idea to reset it to 0022 before installing python modules
UMASK=$(umask)
umask 0022
python3 setup.py install
cd /var/www/MISP/app/files/scripts/python-stix
git config core.filemode false
python3 setup.py install

# install mixbox to accomodate the new STIX dependencies:
cd /var/www/MISP/app/files/scripts/
git clone https://github.com/CybOXProject/mixbox.git
cd /var/www/MISP/app/files/scripts/mixbox
git config core.filemode false
python3 setup.py install

# install PyMISP
cd /var/www/MISP/PyMISP
python3 setup.py install

# Enable python3 for php-fpm
echo 'source scl_source enable rh-python36' >> /etc/opt/rh/rh-php56/sysconfig/php-fpm
sed -i.org -e 's/^;\(clear_env = no\)/\1/' /etc/opt/rh/rh-php56/php-fpm.d/www.conf
service rh-php56-php-fpm restart

umask $UMASK

4/ CakePHP
-----------
# CakePHP is now included as a submodule of MISP, execute the following commands to let git fetch it
# ignore this message:
# No submodule mapping found in .gitmodules for path 'app/Plugin/CakeResque'

cd /var/www/MISP
git submodule update --init --recursive
# Make git ignore filesystem permission differences for submodules
git submodule foreach --recursive git config core.filemode false

# Once done, install CakeResque along with its dependencies if you intend to use the built in background jobs:
cd /var/www/MISP/app
php composer.phar require kamisama/cake-resque:4.1.2
php composer.phar config vendor-dir Vendor
php composer.phar install

# CakeResque normally uses phpredis to connect to redis, but it has a (buggy) fallback connector through Redisent. It is highly advised to install phpredis
pecl install redis
echo "extension=redis.so" > /etc/opt/rh/rh-php56/php-fpm.d/redis.ini
ln -s ../php-fpm.d/redis.ini /etc/opt/rh/rh-php56/php.d/99-redis.ini
service rh-php56-php-fpm restart

# If you have not yet set a timezone in php.ini
echo 'date.timezone = "Europe/Amsterdam"' > /etc/opt/rh/rh-php56/php-fpm.d/timezone.ini
ln -s ../php-fpm.d/timezone.ini /etc/opt/rh/rh-php56/php.d/99-timezone.ini

# To use the scheduler worker for scheduled tasks, do the following:
cp -fa /var/www/MISP/INSTALL/setup/config.php /var/www/MISP/app/Plugin/CakeResque/Config/config.php

5/ Set the permissions
----------------------

# Make sure the permissions are set correctly using the following commands as root:
chown -R root:apache /var/www/MISP
find /var/www/MISP -type d -exec chmod g=rx {} \;
chmod -R g+r,o= /var/www/MISP
chown apache:apache /var/www/MISP/app/files
chown apache:apache /var/www/MISP/app/files/terms
chown apache:apache /var/www/MISP/app/files/scripts/tmp
chown apache:apache /var/www/MISP/app/Plugin/CakeResque/tmp
chown -R apache:apache /var/www/MISP/app/tmp
chown -R apache:apache /var/www/MISP/app/webroot/img/orgs
chown -R apache:apache /var/www/MISP/app/webroot/img/custom

6/ Create a database and user
-----------------------------
# Enable, start and secure your mysql database server
chkconfig mysqld on
service mysqld start
mysql_secure_installation
# Additionally, it is probably a good idea to make the database server listen on localhost only
# Add the following to the [mysqld] of /etc/my.cnf
# bind-address=127.0.0.1

# Enter the mysql shell
mysql -u root -p

mysql> create database misp;
mysql> grant usage on *.* to misp@localhost identified by 'XXXXXXXXX';
mysql> grant all privileges on misp.* to misp@localhost ;
mysql> exit

cd /var/www/MISP

# Import the empty MySQL database from MYSQL.sql
mysql -u misp -p misp < INSTALL/MYSQL.sql


7/ Apache configuration
-----------------------
# Now configure your apache server with the DocumentRoot /var/www/MISP/app/webroot/
# A sample vhost can be found in /var/www/MISP/INSTALL/apache.misp.centos6

cp /var/www/MISP/INSTALL/apache.misp.centos6 /etc/httpd/conf.d/misp.conf

# Allow httpd to connect to the redis server and php-fpm over tcp/ip
setsebool -P httpd_can_network_connect on

# Enable and start the httpd service
chkconfig httpd on
service httpd start

# Open a hole in the iptables firewall
iptables -I INPUT 5 -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
service iptables save

# We seriously recommend using only SSL !
# Check out the apache.misp.ssl file for an example


8/ Log rotation
---------------
# MISP saves the stdout and stderr of its workers in /var/www/MISP/app/tmp/logs
# To rotate these logs install the supplied logrotate script:

cp INSTALL/misp.logrotate /etc/logrotate.d/misp
chmod 0640 /etc/logrotate.d/misp

9/ MISP configuration
---------------------
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
chown apache:apache /var/www/MISP/app/Config/config.php

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
chmod +x /var/www/MISP/app/Console/worker/start.sh
su -s /bin/bash apache -c 'scl enable rh-php56 /var/www/MISP/app/Console/worker/start.sh'

# To make the background workers start on boot
vi /etc/rc.local
# Add the following line at the end
su -s /bin/bash apache -c 'scl enable rh-php56 /var/www/MISP/app/Console/worker/start.sh'

# Now log in using the webinterface:
# The default user/pass = admin@admin.test/admin

# Using the server settings tool in the admin interface (Administration -> Server Settings), set MISP up to your preference
# It is especially vital that no critical issues remain!

Don't forget to change the email, password and authentication key after installation.

# Once done, have a look at the diagnostics

# If any of the directories that MISP uses to store files is not writeable to the apache user, change the permissions
# you can do this by running the following commands:

chmod -R 750 /var/www/MISP/<directory path with an indicated issue>
chown -R apache:apache /var/www/MISP/<directory path with an indicated issue>

# Make sure that the STIX libraries and GnuPG work as intended, if not, refer to INSTALL.txt's paragraphs dealing with these two items

# If anything goes wrong, make sure that you check MISP's logs for errors:
# /var/www/MISP/app/tmp/logs/error.log
# /var/www/MISP/app/tmp/logs/resque-worker-error.log
# /var/www/MISP/app/tmp/logs/resque-scheduler-error.log
# /var/www/MISP/app/tmp/logs/resque-2015-01-01.log //where the actual date is the current date

Recommended actions
-------------------
- By default CakePHP exposes his name and version in email headers. Apply a patch to remove this behavior.

- You should really harden your OS
- You should really harden the configuration of Apache
- You should really harden the configuration of MySQL
- Keep your software up2date (MISP, CakePHP and everything else)
- Log and audit
