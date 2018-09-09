INSTALLATION INSTRUCTIONS
-------------------------
# For Ubuntu 18.04.1 server with Webmin
# Why Webmin/Virtualmin?
# Some may not be full time sysadmin and prefer a platform that once it has been setup works and is decently easy to manage.

# Assuming you created the subdomanin misp.yourserver.tld to where MISP will be installed
# and that the user "misp" is in the sudoers group
# and that you have already configured SSL with Lets Encrypt on the subdomain


1/ Minimal Ubuntu install
-------------------------
# Make sure your system is up2date:
sudo apt-get update
sudo apt-get upgrade

# Get Virtualmin
wget http://software.virtualmin.com/gpl/scripts/install.sh

# Install it
chmod +x install.sh
./install.sh

# Grab a coffee while it does its magic

2/ Configure basic Virtualmin environment
------------------------------
Once the system is installed you can perform the following steps:

# Install the dependencies: (some might already be installed)
sudo apt-get install curl gcc git gnupg-agent make python openssl redis-server sudo vim zip

# Stop MySQL and install MariaDB (a MySQL fork/alternative)
# MariaDB will replace MySQL and it will work with the latests versions of Webmin without modifications
# WARNING: Databases and data will be lost! It is assumed you are installing on a new server with no existing DBs
# NOTE: at present, a simple...
# 'sudo service mysql stop && sudo apt-get install mariadb-client mariadb-server'
# ... doesn't work well with 18.04.1 so you should do the following:
sudo apt purge mysql-client-5.7 mysql-client-core-5.7 mysql-common mysql-server-5.7 mysql-server-core-5.7 mysql-server
# Issues may crop up if you leave MySQL configuration there so remove also config files in /etc/mysql.
# Remove and cleanup packages
sudo apt autoremove && sudo apt -f install
# Add repositories for Mariadb 10.3 and install it
sudo apt-get install software-properties-common
sudo apt-key adv --recv-keys --keyserver hkp://keyserver.ubuntu.com:80 0xF1656F24C74CD1D8
sudo add-apt-repository 'deb [arch=amd64,arm64,ppc64el] http://mariadb.mirrors.ovh.net/MariaDB/repo/10.3/ubuntu bionic main'
sudo apt update
sudo apt install mariadb-server


# Secure the MariaDB installation (especially by setting a strong root password) if it hasn't been asked during the setup process.
sudo mysql_secure_installation

# Go through the post-installation Wizard and configure your misp.yourdomain.tld virtual server
# That should create the misp user and related directories
# Add the misp user to the sudo group

# Install PHP and dependencies
sudo apt-get install libapache2-mod-php php php-cli php-gnupg php-dev php-json php-mysql php-opcache php-readline php-redis php-xml
sudo pear channel-update pear.php.net
sudo pear install Crypt_GPG

# Apply all changes
sudo systemctl restart apache2

3/ MISP code
------------
# Assuming you created the subdomanin misp.yourserver.tld
# Download MISP using git in the /home/misp/public_html/ as misp

sudo - misp
# or log out root and log back in as misp

git clone https://github.com/MISP/MISP.git /home/misp/public_html/MISP
cd /home/misp/public_html/MISP
git checkout tags/$(git describe --tags `git rev-list --tags --max-count=1`)
# if the last shortcut doesn't work, specify the latest version manually
# example: git checkout tags/v2.4.XY
# the message regarding a "detached HEAD state" is expected behaviour
# (you only have to create a new branch, if you want to change stuff and do a pull request for example)

git submodule update --init --recursive

# Make git ignore filesystem permission differences
git submodule foreach --recursive git config core.filemode false

# install Mitre's STIX and its dependencies by running the following commands:
sudo apt-get install python3-dev python3-pip libxml2-dev libxslt1-dev zlib1g-dev python-setuptools python-pip
cd /home/misp/public_html/MISP/app/files/scripts
git clone https://github.com/CybOXProject/python-cybox.git
git clone https://github.com/STIXProject/python-stix.git
cd /home/misp/public_html/MISP/app/files/scripts/python-cybox
sudo python3 setup.py install
cd /home/misp/public_html/MISP/app/files/scripts/python-stix
sudo python3 setup.py install

# install mixbox to accomodate the new STIX dependencies:
cd /home/misp/public_html/MISP/app/files/scripts/
git clone https://github.com/CybOXProject/mixbox.git
cd /home/misp/public_html/MISP/app/files/scripts/mixbox
sudo python3 setup.py install

# install PyMISP
pip install jsonschema
cd /home/misp/public_html/MISP/PyMISP
sudo python3 setup.py install

4/ CakePHP
-----------
# CakePHP is included as a submodule of MISP

# Install CakeResque along with its dependencies if you intend to use the built in background jobs:
cd /home/misp/public_html/MISP/app
php composer.phar require kamisama/cake-resque:4.1.2
php composer.phar config vendor-dir Vendor
php composer.phar install

# Enable CakeResque with php-redis
sudo phpenmod redis

# To use the scheduler worker for scheduled tasks, do the following:
cp -fa /home/misp/public_html/MISP/INSTALL/setup/config.php /home/misp/public_html/MISP/app/Plugin/CakeResque/Config/config.php


5/ Set the permissions
----------------------

# Check if the permissions are set correctly using the following commands:
sudo chmod -R 770 /home/misp/public_html/MISP
sudo chmod -R g+ws /home/misp/public_html/MISP/app/tmp
sudo chmod -R g+ws /home/misp/public_html/MISP/app/files
sudo chmod -R g+ws /home/misp/public_html/MISP/app/files/scripts/tmp


6/ Create a database and user
-----------------------------
# Enter the mysql shell
sudo mysql -u root -p

# If all went well when you created the misp user in Virtualmin you should already have a misp database
# otherwise create it with:
create database misp;
# Make sure password and all privileges are set
grant usage on *.* to misp@localhost identified by 'XXXXdbpasswordhereXXXXX';
grant all privileges on misp.* to misp@localhost;
flush privileges;
exit

# Import the empty MISP database from MYSQL.sql
mysql -u misp -p misp < /home/misp/public_html/MISP/INSTALL/MYSQL.sql
# enter the password you set previously


7/ Apache configuration
-----------------------
# Most of it should have been done when you created the subdomain but add these changes as well


# Under <VirtualHost <IP, FQDN, or *>:80>
#        ServerName <your.FQDN.here>
# add

        Redirect permanent / https://<your.FQDN.here>
        ServerSignature Off

# Closing tag </VirtualHost>


# Under <VirtualHost <IP, FQDN, or *>:443>
#        ServerAdmin admin@<your.FQDN.here>
#        ServerName <your.FQDN.here>
# etc...
# find the document root and change it as follows

        DocumentRoot /home/misp/public_html/MISP/app/webroot

# The Directory tag should be changed to:

        <Directory /home/misp/public_html/MISP/app/webroot>

# The rest should't require modifications. Restart Apache

sudo service apache2 restart

9/ MISP configuration
---------------------
# There are 4 sample configuration files in /home/misp/public_html/MISP/app/Config that need to be copied
cp -a /home/misp/public_html/MISP/app/Config/bootstrap.default.php /home/misp/public_html/MISP/app/Config/bootstrap.php
cp -a /home/misp/public_html/MISP/app/Config/database.default.php /home/misp/public_html/MISP/app/Config/database.php
cp -a /home/misp/public_html/MISP/app/Config/core.default.php /home/misp/public_html/MISP/app/Config/core.php
cp -a /home/misp/public_html/MISP/app/Config/config.default.php /home/misp/public_html/MISP/app/Config/config.php

# Configure the fields in the newly created files:
vi /home/misp/public_html/MISP/app/Config/database.php
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

# Important! Change the salt key in /home/misp/public_html/MISP/app/Config/config.php
# see line 7 (may change)
# 'salt' => 'yoursaltkeyhere' 
# The salt key must be a string at least 32 bytes long.
# The admin user account will be generated on the first login, make sure that the salt is changed before you create that user
# If you forget to do this step, and you are still dealing with a fresh installation, just alter the salt,
# delete the user from mysql and log in again using the default admin credentials (admin@admin.test / admin)

# Change base url in config.php
vi /home/misp/public_html/MISP/app/Config/config.php
# example: 'baseurl' => 'https://<your.FQDN.here>',
# alternatively, you can leave this field empty if you would like to use relative pathing in MISP
# 'baseurl' => '',
# 'email' => 'anemail@yourdomain.tld, set an email address that will be used for gpg

# and make sure the file permissions are still OK
chmod -R 750 /home/misp/public_html/MISP/app/Config

# Generate a GPG encryption key.
mkdir /home/misp/public_html/MISP/.gnupg
chmod 700 /home/misp/public_html/MISP/.gnupg


# If you get no satisfaction with your entropy install this:
sudo apt-get install haveged pv

#Generate entropy for the next step, open a new shell and run the following command:
haveged -n 0 | pv > /dev/null

# It should start saying something like "Writing unlimited bytes to stdout"
# let it run and go back to the previous shell

gpg --homedir /home/misp/public_html/MISP/.gnupg --gen-key
# The email address should match the one set in the config.php / set in the configuration menu in the administration menu configuration file

# You can now Ctrel+C the running haveged in the other shell
# and return to the "install" shell

# Export the public key to the webroot
gpg --homedir /home/misp/public_html/MISP/.gnupg --export --armor YOUR-KEYS-EMAIL-HERE > /home/misp/public_html/MISP/app/webroot/gpg.asc

# To make the background workers start on boot
chmod +x /home/misp/public_html/MISP/app/Console/worker/start.sh

# Activate rc.local in systemd
# Systemd developers, in their wisdom, decided to complicate things a bit so you'll have to
# create the rc-local.service
sudo vi /etc/systemd/system/rc-local.service
# and paste the following in it
[Unit]
 Description=/etc/rc.local Compatibility
 ConditionPathExists=/etc/rc.local

[Service]
 Type=forking
 ExecStart=/etc/rc.local start
 TimeoutSec=0
 StandardOutput=tty
 RemainAfterExit=yes
 SysVStartPriority=99

[Install]
 WantedBy=multi-user.target

# Hit the "esc" button then type :wq! to write the file and exit vi

# Create/edit /etc/rc.local
sudo vi /etc/rc.local
# If the file is empty add the following including the #
#!/bin/bash

# Then add this
sudo -u misp bash /home/misp/public_html/MISP/app/Console/worker/start.sh

# If the file was empty add this as the last line
exit 0

# save, quit vi and set permissions
sudo chmod +x /etc/rc.local

# Enable it in systemd
sudo systemctl enable rc-local

#Start the rc-local compatibility layer and check if AOK
sudo systemctl start rc-local.service
sudo systemctl status rc-local.service

# Now log in using the webinterface:
# The default user/pass = admin@admin.test/admin

# Using the server settings tool in the admin interface (Administration -> Server Settings), set MISP up to your preference
# It is especially vital that no critical issues remain!
# start the workers by navigating to the workers tab and clicking restart all workers

# Don't forget to change the email, password and authentication key after installation.

# Once done, have a look at the diagnostics

# If any of the directories that MISP uses to store files is not writeable to the apache user, change the permissions
# you can do this by running the following commands:

sudo chmod -R 770 /home/misp/public_html/MISP/<directory path with an indicated issue>
sudo chown -R misp:www-data /home/misp/public_html/MISP/<directory path with an indicated issue>

# Make sure that the STIX libraries and GnuPG work as intended, if not, refer to INSTALL.txt's paragraphs dealing with these two items

# If anything goes wrong, make sure that you check MISP's logs for errors:
# /home/misp/public_html/MISP/app/tmp/logs/error.log
# /home/misp/public_html/MISP/app/tmp/logs/resque-worker-error.log
# /home/misp/public_html/MISP/app/tmp/logs/resque-scheduler-error.log
# /home/misp/public_html/MISP/app/tmp/logs/resque-2015-01-01.log // where the actual date is the current date


Recommended actions
-------------------
- By default CakePHP exposes its name and version in email headers. Apply a patch to remove this behavior.

- You should really harden your OS
- You should really harden the configuration of Apache
- You should really harden the configuration of MySQL/MariaDB
- Keep your software up2date (OS, MISP, CakePHP and everything else)
- Log and audit


Optional features
-----------------
# MISP has a new pub/sub feature, using ZeroMQ. To enable it, simply run the following command
sudo pip install pyzmq
# ZeroMQ depends on the Python client for Redis
sudo pip install redis

# For the experimental ssdeep correlations, run the following installation:
# installing ssdeep
wget http://downloads.sourceforge.net/project/ssdeep/ssdeep-2.13/ssdeep-2.13.tar.gz
tar zxvf ssdeep-2.13.tar.gz
cd ssdeep-2.13
./configure
make
sudo make install
ssdeep -h # test

#installing ssdeep_php
sudo pecl install ssdeep

# You should add "extension=ssdeep.so" to mods-available - Check /etc/php for your current version
echo "extension=ssdeep.so" | sudo tee /etc/php/7.2/mods-available/ssdeep.ini
sudo phpenmod ssdeep
sudo service apache2 restart

Optional features: misp-modules
-------------------------------
# If you want to add the misp modules functionality, follow the setup procedure described in misp-modules:
# https://github.com/MISP/misp-modules#how-to-install-and-start-misp-modules
# Then the enrichment, export and import modules can be enabled in MISP via the settings.
