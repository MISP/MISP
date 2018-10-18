INSTALLATION INSTRUCTIONS for RHEL 7.x
-------------------------

+----------------------------------------+
|   0/ Overview and Assumptions          |
+----------------------------------------+
This document details the steps to install MISP on Red Hat Enterprise Linux 7.x (RHEL 7.x). At time of this writing it
was tested on version 7.4.

The following assumptions with regard to this installation have been made.

0.1/ A valid support agreement allowing the system to register to the Red Hat Customer Portal and receive updates
0.2/ The ability to enable additional RPM repositories, specifically the EPEL and Software Collections (SCL) repos
0.3/ This system will have direct or proxy access to the Internet for updates. Or connected to a Red Hat Satellite Server
0.4/ This document is to get a MISP instance up and running over HTTP. I haven't done a full test of all features

+----------------------------------------------+
|   1/ OS Install and additional repositories  |
+----------------------------------------------+

1.1/ Complete a minimal RHEL installation, configure IP address to connect automatically.

1.2/ Configure system hostname
hostnamectl set-hostname misp # You're choice, in a production environment, it's best to use a FQDN

1.3/ Register the system for updates with Red Hat Subscription Manager
subscription-manager register # register your system to an account
subscription-manager attach   # attach your system to a current subscription

1.4/ Enable the optional, extras and Software Collections (SCL) repos
subscription-manager repos --enable rhel-7-server-optional-rpms
subscription-manager repos --enable rhel-7-server-extras-rpms
subscription-manager repos --enable rhel-server-rhscl-7-rpms

1.5a/ OPTIONAL: Install the deltarpm package to help reduce download size when installing updates
yum install deltarpm

1.5/ Update the system and reboot
yum update

## NOTE: As time of writing performing a yum update results in the rhel-7-server-rt-beta-rpms being forbidden
## The repo can be disabled using the following command
subscription-manager repos --disable rhel-7-server-rt-beta-rpms

1.6/ Install the EPEL repo
yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm

1.7/ Install the SCL repo
yum install centos-release-scl

+-----------------------------+
|   2/ Install Dependencies   |
+-----------------------------+
Once the system is installed and updated, the following steps can be performed as root

2.01/ Install some base system dependencies
yum install gcc git httpd zip python-devel libxslt-devel zlib-devel python-pip ssdeep-devel

2.02/ Install MariaDB 10.2 from SCL
yum install rh-mariadb102

2.03/ Start the MariaDB service and enable it to start on boot
systemctl start rh-mariadb102-mariadb.service
systemctl enable rh-mariadb102-mariadb.service

## MISP 2.4 requires PHP 5.5 as a minimum, we need a higher version than base RHEL provides.
## This guide installs PHP 7.1 from SCL

2.04/ Install PHP 7.1 from SCL
yum install rh-php71 rh-php71-php-fpm rh-php71-php-devel rh-php71-php-mysqlnd rh-php71-php-mbstring rh-php71-php-xml rh-php71-php-bcmath rh-php71-php-opcache

## If we want to use httpd from RHEL base we can use the rh-php71-php-fpm service instead
2.05/ Start the PHP FPM service and enable to start on boot
systemctl start rh-php71-php-fpm.service
systemctl enable rh-php71-php-fpm.service

2.06/ Install redis 3.2 from SCL
yum install rh-redis32

2.07/ Start redis service and enable to start on boot
systemctl start rh-redis32-redis.service
systemctl enable rh-redis32-redis.service

2.08/ Start a SCL shell with rh-mariadb102 rh-php71 and rh-redis32 enabled
scl enable rh-mariadb102 rh-php71 rh-redis32 bash

2.08/ Secure the MariaDB installation, run the following command and follow the prompts
mysql_secure_installation

2.10/ Update the PHP extension repository and install required package
pear channel-update pear.php.net
pear install Crypt_GPG

2.11/ Install haveged and enable to start on boot to provide entropy for GPG
yum install haveged
systemctl start haveged
systemctl enable haveged

2.12/ Install Python 3.6 from SCL
yum install rh-python36

+---------------------+
|   3/ MISP Download  |
+---------------------+

3.01/ Download MISP code using git in /var/www/ directory
cd /var/www
git clone https://github.com/MISP/MISP.git
git checkout tags/$(git describe --tags `git rev-list --tags --max-count=1`)
# if the last shortcut doesn't work, specify the latest version manually
# example: git checkout tags/v2.4.XY
# the message regarding a "detached HEAD state" is expected behaviour
# (you only have to create a new branch, if you want to change stuff and do a pull request for example)

3.02/ Make git ignore filesystem permission differences
git config core.filemode false

3.03/ Install Mitre's STIX and its dependencies by running the following commands:
pip install importlib
yum install python-six
cd /var/www/MISP/app/files/scripts
git clone https://github.com/CybOXProject/python-cybox.git
git clone https://github.com/STIXProject/python-stix.git
cd /var/www/MISP/app/files/scripts/python-cybox
git config core.filemode false
# If your umask has been changed from the default, it is a good idea to reset it to 0022 before installing python modules
UMASK=$(umask)
umask 0022
scl enable rh-python36 'python3 setup.py install'
cd /var/www/MISP/app/files/scripts/python-stix
git config core.filemode false
scl enable rh-python36 'python3 setup.py install'

3.04/ Install mixbox to accomodate the new STIX dependencies:
cd /var/www/MISP/app/files/scripts/
git clone https://github.com/CybOXProject/mixbox.git
cd /var/www/MISP/app/files/scripts/mixbox
git config core.filemode false
scl enable rh-python36 'python3 setup.py install'
umask $UMASK

3.05/ Enable python3 for php-fpm

echo 'source scl_source enable rh-python36' >> /etc/opt/rh/rh-php71/sysconfig/php-fpm
sed -i.org -e 's/^;\(clear_env = no\)/\1/' /etc/opt/rh/rh-php71/php-fpm.d/www.conf
systemctl restart rh-php71-php-fpm.service

+---------------------+
|   4/ CakePHP        |
+---------------------+

4.01/ CakePHP is now included as a submodule of MISP, execute the following commands to let git fetch it ignore this
message: No submodule mapping found in .gitmodules for path 'app/Plugin/CakeResque'
cd /var/www/MISP
git submodule update --init --recursive
# Make git ignore filesystem permission differences for submodules
git submodule foreach --recursive git config core.filemode false

4.02/ Install CakeResque along with its dependencies if you intend to use the built in background jobs
cd /var/www/MISP/app
php composer.phar require kamisama/cake-resque:4.1.2
php composer.phar config vendor-dir Vendor
php composer.phar install

4.03/ Install and configure php redis connector through pecl
pecl install redis
echo "extension=redis.so" > /etc/opt/rh/rh-php71/php-fpm.d/redis.ini
ln -s ../php-fpm.d/redis.ini /etc/opt/rh/rh-php71/php.d/99-redis.ini
systemctl restart rh-php71-php-fpm.service

4.04/ Set a timezone in php.ini
echo 'date.timezone = "Australia/Sydney"' > /etc/opt/rh/rh-php71/php-fpm.d/timezone.ini
ln -s ../php-fpm.d/timezone.ini /etc/opt/rh/rh-php71/php.d/99-timezone.ini

4.05/ To use the scheduler worker for scheduled tasks, do the following:
cp -fa /var/www/MISP/INSTALL/setup/config.php /var/www/MISP/app/Plugin/CakeResque/Config/config.php

+----------------------------+
|   5/ Set file permissions  |
+----------------------------+

5.01/ Make sure the permissions are set correctly using the following commands as root:
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

+--------------------------------+
|   6/ Create database and user  |
+--------------------------------+

6.01/ Set database to listen on localhost only
echo [mysqld] > /etc/opt/rh/rh-mariadb102/my.cnf.d/bind-address.cnf
echo bind-address=127.0.0.1 >> /etc/opt/rh/rh-mariadb102/my.cnf.d/bind-address.cnf
systemctl restart rh-mariadb102-mariadb

6.02/ Start MariaDB shell and create database
mysql -u root -p

MariaDB [(none)]> create database misp;
MariaDB [(none)]> grant usage on *.* to misp@localhost identified by 'XXXXXXXXX';
MariaDB [(none)]> grant all privileges on misp.* to misp@localhost ;
MariaDB [(none)]> exit

6.03/ Import the empty MySQL database from MYSQL.sql
cd /var/www/MISP
mysql -u misp -p misp < INSTALL/MYSQL.sql

+--------------------------------+
|   7/ Apache Configuration      |
+--------------------------------+

7.01/ Copy a sample vhost config to Apache configuration directory
cp /var/www/MISP/INSTALL/apache.misp.centos7 /etc/httpd/conf.d/misp.conf

7.02/ Since SELinux is enabled, we need to allow httpd to write to certain directories
chcon -t httpd_sys_rw_content_t /var/www/MISP/app/files
chcon -t httpd_sys_rw_content_t /var/www/MISP/app/files/terms
chcon -t httpd_sys_rw_content_t /var/www/MISP/app/files/scripts/tmp
chcon -t httpd_sys_rw_content_t /var/www/MISP/app/Plugin/CakeResque/tmp
chcon -R -t httpd_sys_rw_content_t /var/www/MISP/app/tmp
chcon -R -t httpd_sys_rw_content_t /var/www/MISP/app/webroot/img/orgs
chcon -R -t httpd_sys_rw_content_t /var/www/MISP/app/webroot/img/custom

7.02/ Allow httpd to connect to the redis server and php-fpm over tcp/ip
setsebool -P httpd_can_network_connect on

7.03/ Enable and start the httpd service
systemctl enable httpd.service
systemctl start httpd.service

7.04/ Open a hole in the firewalld service
firewall-cmd --zone=public --add-port=80/tcp --permanent
firewall-cmd --reload

# We seriously recommend using only HTTPS / SSL !
# Add SSL support by running: yum install mod_ssl
# Check out the apache.misp.ssl file for an example

+--------------------------------+
|   8/ Log Rotation              |
+--------------------------------+
# MISP saves the stdout and stderr of it's workers in /var/www/MISP/app/tmp/logs
# To rotate these logs install the supplied logrotate script:

cp INSTALL/misp.logrotate /etc/logrotate.d/misp
chmod 0640 /etc/logrotate.d/misp

8.01/ Allow logrotate to work under SELinux and modify the log files
semanage fcontext -a -t httpd_log_t "/var/www/MISP/app/tmp/logs(/.*)?"
chcon -R -t httpd_log_t /var/www/MISP/app/tmp/logs

8.02/ Allow logrotate to read /var/www
checkmodule -M -m -o /tmp/misplogrotate.mod INSTALL/misplogrotate.te
semodule_package -o /tmp/misplogrotate.pp -m /tmp/misplogrotate.mod
semodule -i /tmp/misplogrotate.pp

+--------------------------------+
|   9/ MISP Configuration        |
+--------------------------------+

9.01/ There are 4 sample configuration files in /var/www/MISP/app/Config that need to be copied
cd /var/www/MISP/app/Config
cp -a bootstrap.default.php bootstrap.php
cp -a database.default.php database.php
cp -a core.default.php core.php
cp -a config.default.php config.php

9.02/ Configure the fields in the newly created files
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

# Important! Change the salt key in /var/www/MISP/app/Config/config.php
# The admin user account will be generated on the first login, make sure that the salt is changed before you create that user
# If you forget to do this step, and you are still dealing with a fresh installation, just alter the salt,
# delete the user from mysql and log in again using the default admin credentials (admin@admin.test / admin)

9.03/ If you want to be able to change configuration parameters from the webinterface:
chown apache:apache /var/www/MISP/app/Config/config.php
chcon -t httpd_sys_rw_content_t /var/www/MISP/app/Config/config.php

9.04/ Generate an encryption key
gpg --gen-key
mv ~/.gnupg /var/www/MISP/
chown -R apache:apache /var/www/MISP/.gnupg
chcon -R -t httpd_sys_rw_content_t /var/www/MISP/.gnupg
## NOTE: There is a bug that if a passphrase is added MISP will produce an error on the diagnostic page.

# The email address should match the one set in the config.php configuration file
# Make sure that you use the same settings in the MISP Server Settings tool

9.05/ export the public key to the webroot
sudo -u apache gpg --homedir /var/www/MISP/.gnupg --export --armor YOUR-EMAIL > /var/www/MISP/app/webroot/gpg.asc

9.06/ Start the workers to enable background jobs
chmod +x /var/www/MISP/app/Console/worker/start.sh
su -s /bin/bash apache -c 'scl enable rh-php71 rh-redis32 rh-mariadb102 /var/www/MISP/app/Console/worker/start.sh'

9.07a/ To make the background workers start on boot
vi /etc/rc.local
9.07b/ Add the following line at the end
su -s /bin/bash apache -c 'scl enable rh-php71 rh-redis32 rh-mariadb102 /var/www/MISP/app/Console/worker/start.sh'
9.07c/ and make sure it will execute
chmod +x /etc/rc.local

# Now log in using the webinterface: http://misp/users/login
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

+---------------------------+
|   10/ Post Install        |
+---------------------------+

10.01/ Allow apache to write to /var/www/MISP/app/tmp/logs
# Result from diagnostic is that the directory is not writable.
chcon -R -t httpd_sys_rw_content_t /var/www/MISP/app/tmp/logs/
# NOTE: This may mean that logrotate cannot access the logs directory, will require further investigation

10.02/ Change php.ini settings to suggested limits from diagnostic page.
# Edit /etc/opt/rh/rh-php71/php.ini and set the following settings
max_execution_time = 300
memory_limit = 512M
upload_max_filesize = 50M
post_max_size = 50M

10.03/ Restart rh-php71 for settings to take effect
systemctl restart rh-php71-php-fpm

10.04/ Install pymisp and pydeep for Advanced Attachment handler
pip install pymisp
pip install git+https://github.com/kbandla/pydeep.git

10.05/ Install pymisp also in Python 3
scl enable rh-python36 pip3 install pymisp

+---------------------------+
|   11/ LIEF Installation   |
+---------------------------+
# lief is required for the Advanced Attachment Handler and requires manual compilation

11.01/ Install cmake3 devtoolset-7 from SCL
yum install devtoolset-7 cmake3

11.02/ Enable devtoolset-7
scl enable devtoolset-7 bash

11.03/ Set env variable, create directories and download source code
mkdir -p /tmp/LIEF
mkdir -p /tmp/LIEF_INSTALL
export LIEF_TMP=/tmp/LIEF
export LIEF_INSTALL=/tmp/LIEF_INSTALL
export LIEF_BRANCH=master
cd $LIEF_TMP
git clone --branch $LIEF_BRANCH --single-branch https://github.com/lief-project/LIEF.git LIEF

11.04/ Compile lief and install
cd $LIEF_TMP/LIEF
mkdir -p build
cd build
scl enable devtoolset-7 'bash -c "cmake3 \
-DLIEF_PYTHON_API=on \
-DLIEF_DOC=off \
-DCMAKE_INSTALL_PREFIX=$LIEF_INSTALL \
-DCMAKE_BUILD_TYPE=Release \
-DPYTHON_VERSION=2.7 \
.."'
make -j3
cd api/python
scl enable rh-python36 python3 setup.py install || :
# you can ignore the error about finding suitable distribution
cd $LIEF_TMP/LIEF/build
make install
make package

11.05/ Test lief installation, if no error, package installed
python
>> import lief

+---------------------------+
|   12/ Known Issues        |
+---------------------------+

12.01/ PHP CLI cannot determine version
# PHP CLI Version cannot be determined. Possibly due to PHP being installed through SCL

12.02/ Workers cannot be started or restarted from the web page
# Possible also due to package being installed via SCL, attempting to start workers through the web page will result in
# error. Worker's can be restarted via the CLI using the following command.
su -s /bin/bash apache -c 'scl enable rh-php71 rh-redis32 rh-mariadb102 /var/www/MISP/app/Console/worker/start.sh'

## NOTE: No other functions were tested after the conclusion of this install. There may be issue that aren't addressed
## via this guide and will need additional investigation.
