# INSTALLATION INSTRUCTIONS
## for Ubuntu 18.04.1-server with Webmin

### 0/ MISP Ubuntu 18.04-server install - status
-------------------------
!!! notice
    Tested semi-working by @SteveClement on 20181120.

{% comment %}
{% include_relative generic/community.md %}
{% endcomment %}

{% comment %}
{% include_relative generic/globalVariables.md %}
{% endcomment %}

```bash
PHP_ETC_BASE=/etc/php/7.2
PHP_INI=${PHP_ETC_BASE}/apache2/php.ini
VIRT_USER=misp.misp-vm.local
PATH_TO_MISP=/home/${VIRT_USER}/public_html/MISP
```

#### Why Webmin/Virtualmin?
Some may not be full time sysadmin and prefer a platform that once it has been setup works and is decently easy to manage.

#### Assumptions
Assuming you created the subdomanin misp.yourserver.tld to where MISP will be installed and that the user "misp" is in the sudoers group and that you have already configured SSL with Lets Encrypt on the subdomain.

### 1/ Minimal Ubuntu install
-------------------------

#### Install a minimal Ubuntu 18.04-server system with the software:
- OpenSSH server
- This guide assumes a user name of 'misp' with sudo working

{% comment %}
{% include_relative generic/sudo_etckeeper.md %}
{% endcomment %}

{% comment %}
{% include_relative generic/ethX.md %}
{% endcomment %}

#### Make sure your system is up2date
```bash
sudo apt-get update
sudo apt-get upgrade
```

#### Get Virtualmin
```
wget -O /tmp/install.sh http://software.virtualmin.com/gpl/scripts/install.sh
```

#### Install it
```
chmod +x /tmp/install.sh
sudo /tmp/install.sh
```

### 2/ Configure basic Virtualmin environment
------------------------------
Once the system is installed you can perform the following steps:

#### Install the dependencies: (some might already be installed)
```bash
sudo apt-get install curl gcc git gnupg-agent make python openssl redis-server sudo vim zip virtualenv -y
```

#### Stop MySQL and install MariaDB (a MySQL fork/alternative)

#### MariaDB will replace MySQL and it will work with the latests versions of Webmin without modifications
!!! warning
    Databases and data will be lost! It is assumed you are installing on a new server with no existing DBs

!!! notice
    At present, a simple...
    ```bash
    sudo service mysql stop && sudo apt-get install mariadb-client mariadb-server'
    ```
    ... doesn't work well with 18.04.1 so you should do the following:
    ```bash
    sudo apt purge mysql-client-5.7 mysql-client-core-5.7 mysql-common mysql-server-5.7 mysql-server-core-5.7 mysql-server
    ```
    ---> NOT VERIFIED, NEED TO CLARIFY <---

Issues may arise if you leave the MySQL configuration in place, remove config files in /etc/mysql if needed.

#### Remove and cleanup packages
```bash
sudo apt autoremove && sudo apt -f install
```

#### Add repositories for Mariadb 10.3 and install it
```bash
sudo apt-get install software-properties-common
sudo apt-key adv --recv-keys --keyserver hkp://keyserver.ubuntu.com:80 0xF1656F24C74CD1D8
sudo add-apt-repository 'deb [arch=amd64,arm64,ppc64el] http://mariadb.mirrors.ovh.net/MariaDB/repo/10.3/ubuntu bionic main'
sudo apt update
# Install MariaDB (a MySQL fork/alternative)
sudo apt-get install mariadb-client mariadb-server -y

# Make sure auth_socket.so is loaded
grep auth_socket /etc/mysql/mariadb.conf.d/50-server.cnf
## If not add this in the [mysqld] section
### [mysqld]
### plugin-load-add = auth_socket.so
sudo systemctl restart mariadb.service

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
```

Go through the Webmin post-installation Wizard and configure your misp.yourdomain.tld virtual server

That should create the 'misp' user and related directories
Add the 'misp' user to the sudo group

Also make sure the variable ${VIRT_USER} is set to the user you created when you created the virtual server. This might NOT be 'misp' but something completely different, like: 'misp.misp-vm.local' or 'misp.example.com' or 'misp-virtual'.

#### Install PHP and dependencies
```bash
sudo apt-get install libapache2-mod-php php php-cli php-gnupg php-dev php-json php-mysql php-opcache php-readline php-redis php-xml php-mbstring php-gd php-zip -y
```

# Apply all changes
sudo systemctl restart apache2

### 3/ MISP code
------------

Assuming you created the subdomain virtual server misp.yourserver.tld
Download MISP using git in the /home/${VIRT_USER}/public_html/ as ${VIRT_USER}

```
sudo su - ${VIRT_USER}
# or log out root and log back in as your virtual server user

git clone https://github.com/MISP/MISP.git ${PATH_TO_MISP}
cd ${PATH_TO_MISP}
git checkout tags/$(git describe --tags `git rev-list --tags --max-count=1`)
# if the last shortcut doesn't work, specify the latest version manually
# example: git checkout tags/v2.4.XY
# the message regarding a "detached HEAD state" is expected behaviour
# (you only have to create a new branch, if you want to change stuff and do a pull request for example)

git submodule update --init --recursive

# Make git ignore filesystem permission differences
git submodule foreach --recursive git config core.filemode false

# Create a python3 virtualenv
virtualenv -p python3 ${PATH_TO_MISP}/venv

cd ${PATH_TO_MISP}/app/files/scripts
git clone https://github.com/CybOXProject/python-cybox.git
git clone https://github.com/STIXProject/python-stix.git
git clone https://github.com/MAECProject/python-maec.git
cd ${PATH_TO_MISP}/app/files/scripts/python-cybox
$SUDO_WWW git config core.filemode false
${PATH_TO_MISP}/venv/bin/pip install .
cd ${PATH_TO_MISP}/app/files/scripts/python-stix
$SUDO_WWW git config core.filemode false
${PATH_TO_MISP}/venv/bin/pip install .
cd ${PATH_TO_MISP}/app/files/scripts/python-maec
$SUDO_WWW git config core.filemode false
${PATH_TO_MISP}/venv/bin/pip install .

# install mixbox to accommodate the new STIX dependencies:
cd ${PATH_TO_MISP}/app/files/scripts/
git clone https://github.com/CybOXProject/mixbox.git
cd ${PATH_TO_MISP}/app/files/scripts/mixbox
$SUDO_WWW git config core.filemode false
${PATH_TO_MISP}/venv/bin/pip install .

# install PyMISP
cd ${PATH_TO_MISP}/PyMISP
${PATH_TO_MISP}/venv/bin/pip install .
```

### 4/ CakePHP
-----------
```bash
# CakePHP is included as a submodule of MISP

# Install CakeResque along with its dependencies if you intend to use the built in background jobs:
cd ${PATH_TO_MISP}/app
php composer.phar install --no-dev

# Enable CakeResque with php-redis
sudo phpenmod redis
sudo phpenmod gnupg

# To use the scheduler worker for scheduled tasks, do the following:
cp -fa ${PATH_TO_MISP}/INSTALL/setup/config.php ${PATH_TO_MISP}/app/Plugin/CakeResque/Config/config.php

# If you have multiple MISP instances on the same system, don't forget to have a different Redis per MISP instance for the CakeResque workers
# The default Redis port can be updated in Plugin/CakeResque/Config/config.php
```

### 5/ Set the permissions
----------------------

```bash
# Check if the permissions are set correctly using the following commands:
sudo chown -R ${VIRT_USER}:${VIRT_USER} ${PATH_TO_MISP}
sudo chmod -R 750 ${PATH_TO_MISP}
sudo chmod -R g+ws ${PATH_TO_MISP}/app/tmp
sudo chmod -R g+ws ${PATH_TO_MISP}/app/files
sudo chmod -R g+ws ${PATH_TO_MISP}/app/files/scripts/tmp
```

### 6/ Create a database and user
-----------------------------
```bash
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
sudo -u ${VIRT_USER} cat ${PATH_TO_MISP}/INSTALL/MYSQL.sql | mysql -u $DBUSER_MISP -p$DBPASSWORD_MISP $DBNAME
```


### 7/ Apache configuration
-----------------------
Most of it should have been done when you created the subdomain but add these changes as well

```bash
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

# The rest shouldn't require modifications. Restart Apache

sudo service apache2 restart
```

### 9/ MISP configuration
---------------------
```bash
# There are 4 sample configuration files in ${PATH_TO_MISP}/app/Config that need to be copied
cp -a ${PATH_TO_MISP}/app/Config/bootstrap.default.php ${PATH_TO_MISP}/app/Config/bootstrap.php
cp -a ${PATH_TO_MISP}/app/Config/database.default.php ${PATH_TO_MISP}/app/Config/database.php
cp -a ${PATH_TO_MISP}/app/Config/core.default.php ${PATH_TO_MISP}/app/Config/core.php
cp -a ${PATH_TO_MISP}/app/Config/config.default.php ${PATH_TO_MISP}/app/Config/config.php

# Configure the fields in the newly created files:
vi ${PATH_TO_MISP}/app/Config/database.php
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

# Important! Change the salt key in ${PATH_TO_MISP}/app/Config/config.php
# see line 7 (may change)
# 'salt' => 'yoursaltkeyhere' 
# The salt key must be a string at least 32 bytes long.
# The admin user account will be generated on the first login, make sure that the salt is changed before you create that user
# If you forget to do this step, and you are still dealing with a fresh installation, just alter the salt,
# delete the user from mysql and log in again using the default admin credentials (admin@admin.test / admin)

# Change base url in config.php
vi ${PATH_TO_MISP}/app/Config/config.php
# example: 'baseurl' => 'https://<your.FQDN.here>',
# alternatively, you can leave this field empty if you would like to use relative pathing in MISP
# 'baseurl' => '',
# 'email' => 'anemail@yourdomain.tld, set an email address that will be used for gpg

# and make sure the file permissions are still OK
chmod -R 750 ${PATH_TO_MISP}/app/Config

# Generate a GPG encryption key.

mkdir ${PATH_TO_MISP}/.gnupg
chmod 700 ${PATH_TO_MISP}/.gnupg

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

gpg --homedir ${PATH_TO_MISP}/.gnupg --batch --gen-key /tmp/gen-key-script
# The email address should match the one set in the config.php / set in the configuration menu in the administration menu configuration file

# And export the public key to the webroot
sh -c "gpg --homedir ${PATH_TO_MISP}/.gnupg --export --armor $GPG_EMAIL_ADDRESS" | tee ${PATH_TO_MISP}/app/webroot/gpg.asc

# If you get no satisfaction with your entropy install this:
sudo apt-get install haveged pv

#Generate entropy for the next step, open a new shell and run the following command:
haveged -n 0 | pv > /dev/null

# It should start saying something like "Writing unlimited bytes to stdout"
# let it run and go back to the previous shell

# You can now Ctrl+C the running haveged in the other shell
# and return to the "install" shell

# To make the background workers start on boot
chmod +x ${PATH_TO_MISP}/app/Console/worker/start.sh

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
sudo -u ${VIRT_USER} bash ${PATH_TO_MISP}/app/Console/worker/start.sh

# If the file was empty add this as the last line
exit 0

# save, quit vi and set permissions
sudo chmod +x /etc/rc.local

# Enable it in systemd
sudo systemctl enable rc-local

#Start the rc-local compatibility layer and check if AOK
sudo systemctl start rc-local.service
sudo systemctl status rc-local.service
```

!!! notice
    Once done, have a look at the diagnostics
    If any of the directories that MISP uses to store files is not writeable to the apache user, change the permissions
    you can do this by running the following commands:
    ```
    sudo chmod -R 770 ${PATH_TO_MISP}/<directory path with an indicated issue>
    sudo chown -R misp:www-data ${PATH_TO_MISP}/<directory path with an indicated issue>
    ```

!!! notice
    If anything goes wrong, make sure that you check MISP's logs for errors:
    ```
    # ${PATH_TO_MISP}/app/tmp/logs/error.log
    # ${PATH_TO_MISP}/app/tmp/logs/resque-worker-error.log
    # ${PATH_TO_MISP}/app/tmp/logs/resque-scheduler-error.log
    # ${PATH_TO_MISP}/app/tmp/logs/resque-2015-01-01.log // where the actual date is the current date
```

{% comment %}
{% include_relative generic/INSTALL.done.md %}
{% endcomment %}

{% comment %}
{% include_relative generic/recommended.actions.md %}
{% endcomment %}

{% comment %}
{% include_relative generic/hardening.md %}
{% endcomment %}

### Optional features
-----------------
#### MISP has a new pub/sub feature, using ZeroMQ. To enable it, simply run the following command
```bash
sudo pip3 install pyzmq
# ZeroMQ depends on the Python client for Redis
sudo pip3 install redis
```

#### MISP has a feature for publishing events to Kafka. To enable it, simply run the following commands
```bash
apt-get install librdkafka-dev php-dev
pecl install rdkafka
find /etc -name php.ini | while read f; do echo 'extension=rdkafka.so' | tee -a "$f"; done
```

#### Experimental ssdeep correlations
```bash
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
```

#### misp-modules
-------------------------------
!!! notice
    If you want to add the misp modules functionality, follow the setup procedure described in misp-modules:<br />
    https://github.com/MISP/misp-modules#how-to-install-and-start-misp-modules<br />
    Then the enrichment, export and import modules can be enabled in MISP via the settings.
