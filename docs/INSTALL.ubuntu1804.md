# INSTALLATION INSTRUCTIONS
## for Ubuntu 18.04.1-server

### 0/ MISP Ubuntu 18.04-server install - status
-------------------------
!!! notice
    Tested working by @SteveClement on 20190118 (works with **Ubuntu 18.10** too)
    As of 20190118 on **Ubuntu 19.04** you need to use Python 3.6 as LIEF with 3.7 is not "eggED" yet.
    You will need to **sudo apt install python3.6-dev** to make everything work according to this guide.

{!generic/community.md!}

{!generic/globalVariables.md!}

```bash
## TODO: Move this away, this should be done depending on using php7.2 or php7.3
# <snippet-begin 1_php-vars.sh>
PHP_ETC_BASE=/etc/php/7.2
PHP_INI=${PHP_ETC_BASE}/apache2/php.ini
# <snippet-end 1_php-vars.sh>
```

### 1/ Minimal Ubuntu install
-------------------------

#### Install a minimal Ubuntu 18.04-server system with the software:
- OpenSSH server
- This guide assumes a user name of 'misp' with sudo working

{!generic/sudo_etckeeper.md!}

{!generic/ethX.md!}

#### Make sure your system is up2date
```bash
# <snippet-begin apt-upgrade.sh>
sudo apt-get update
sudo apt-get upgrade
# <snippet-end apt-upgrade.sh>
```

#### install postfix, there will be some questions.
```bash
# <snippet-begin postfix.sh>
sudo apt-get install postfix dialog -y
# <snippet-begin postfix.sh>
```

!!! notice
    Postfix Configuration: Satellite system<br />
    change the relay server later with:
    ```bash
    sudo postconf -e 'relayhost = example.com'
    sudo postfix reload
    ```

### 2/ Install LAMP & dependencies
------------------------------
Once the system is installed you can perform the following steps.
```bash
# Make sure you have enabled the Universe repository
# (ie. for redis-server), enable it with:
# sudo add-apt-repository universe

# Install the dependencies: (some might already be installed)
sudo apt-get install curl gcc git gpg-agent make python python3 openssl redis-server sudo vim zip virtualenv -y

# Install MariaDB (a MySQL fork/alternative)
sudo apt-get install mariadb-client mariadb-server -y

sudo apt install expect -y

# Add your credentials if needed, if sudo has NOPASS, comment out the relevant lines
pw="Password1234"

expect -f - <<-EOF
  set timeout 10

  spawn sudo -k mysql_secure_installation
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

# Install Apache2
sudo apt-get install apache2 apache2-doc apache2-utils -y

# Enable modules, settings, and default of SSL in Apache
sudo a2dismod status
sudo a2enmod ssl
sudo a2enmod rewrite
sudo a2enmod headers
sudo a2dissite 000-default
sudo a2ensite default-ssl

# Install PHP and dependencies
sudo apt-get install libapache2-mod-php php php-cli php-gnupg php-dev php-json php-mysql php-opcache php-readline php-redis php-xml php-mbstring -y

# Apply all changes
sudo systemctl restart apache2
```

### 3/ MISP code
------------
```bash
# Download MISP using git in the /var/www/ directory.
sudo mkdir ${PATH_TO_MISP}
sudo chown www-data:www-data ${PATH_TO_MISP}
cd ${PATH_TO_MISP}
sudo -u www-data git clone https://github.com/MISP/MISP.git ${PATH_TO_MISP}
sudo -u www-data git submodule update --init --recursive
# Make git ignore filesystem permission differences for submodules
sudo -u www-data git submodule foreach --recursive git config core.filemode false

# Make git ignore filesystem permission differences
sudo -u www-data git config core.filemode false

# Create a python3 virtualenv
sudo apt-get install python3-pip -y
pip3 install virtualenv
sudo -u www-data virtualenv -p python3.6 ${PATH_TO_MISP}/venv

# make pip happy
sudo mkdir /var/www/.cache/
sudo chown www-data:www-data /var/www/.cache

# install Mitre's STIX and its dependencies by running the following commands:
sudo apt-get install python3-dev python3-pip libxml2-dev libxslt1-dev zlib1g-dev python-setuptools -y
cd ${PATH_TO_MISP}/app/files/scripts
sudo -u www-data git clone https://github.com/CybOXProject/python-cybox.git
sudo -u www-data git clone https://github.com/STIXProject/python-stix.git
sudo -u www-data git clone https://github.com/MAECProject/python-maec.git
# install mixbox to accommodate the new STIX dependencies:
sudo -u www-data git clone https://github.com/CybOXProject/mixbox.git
cd ${PATH_TO_MISP}/app/files/scripts/mixbox
sudo -H -u www-data ${PATH_TO_MISP}/venv/bin/pip install .
cd ${PATH_TO_MISP}/app/files/scripts/python-cybox
sudo -H -u www-data ${PATH_TO_MISP}/venv/bin/pip install .
cd ${PATH_TO_MISP}/app/files/scripts/python-stix
sudo -H -u www-data ${PATH_TO_MISP}/venv/bin/pip install .
cd $PATH_TO_MISP/app/files/scripts/python-maec
sudo -H -u www-data ${PATH_TO_MISP}/venv/bin/pip install .
# install STIX2.0 library to support STIX 2.0 export:
cd ${PATH_TO_MISP}/cti-python-stix2
sudo -H -u www-data ${PATH_TO_MISP}/venv/bin/pip install .

# install PyMISP
cd ${PATH_TO_MISP}/PyMISP
sudo -H -u www-data ${PATH_TO_MISP}/venv/bin/pip install .

# Install Crypt_GPG and Console_CommandLine
sudo pear install ${PATH_TO_MISP}/INSTALL/dependencies/Console_CommandLine/package.xml
sudo pear install ${PATH_TO_MISP}/INSTALL/dependencies/Crypt_GPG/package.xml
```

### 4/ CakePHP
-----------

```bash
# Once done, install CakeResque along with its dependencies 
# if you intend to use the built in background jobs:
cd ${PATH_TO_MISP}/app
# Make composer cache happy
# /!\ composer on Ubuntu when invoked with sudo -u doesn't set $HOME to /var/www but keeps it /home/misp \!/
sudo mkdir /var/www/.composer ; sudo chown www-data:www-data /var/www/.composer
sudo -H -u www-data php composer.phar require kamisama/cake-resque:4.1.2
sudo -H -u www-data php composer.phar config vendor-dir Vendor
sudo -H -u www-data php composer.phar install

# Enable CakeResque with php-redis
sudo phpenmod redis
sudo phpenmod gnupg

# To use the scheduler worker for scheduled tasks, do the following:
sudo -u www-data cp -fa ${PATH_TO_MISP}/INSTALL/setup/config.php ${PATH_TO_MISP}/app/Plugin/CakeResque/Config/config.php

# If you have multiple MISP instances on the same system, don't forget to have a different Redis per MISP instance for the CakeResque workers
# The default Redis port can be updated in Plugin/CakeResque/Config/config.php
```

### 5/ Set the permissions
----------------------

```bash
# Check if the permissions are set correctly using the following commands:
sudo chown -R www-data:www-data ${PATH_TO_MISP}
sudo chmod -R 750 ${PATH_TO_MISP}
sudo chmod -R g+ws ${PATH_TO_MISP}/app/tmp
sudo chmod -R g+ws ${PATH_TO_MISP}/app/files
```

### 6/ Create a database and user
-----------------------------

#### Manual procedure:
```bash
# Enter the mysql shell
sudo mysql -u root -p
```

```
MariaDB [(none)]> create database misp;
MariaDB [(none)]> grant usage on *.* to misp@localhost identified by 'XXXXdbpasswordhereXXXXX';
MariaDB [(none)]> grant all privileges on misp.* to misp@localhost;
MariaDB [(none)]> flush privileges;
MariaDB [(none)]> exit
```

#### Same as Manual but for copy/paste foo:
```bash
sudo mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e "create database $DBNAME;"
sudo mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e "grant usage on *.* to $DBNAME@localhost identified by '$DBPASSWORD_MISP';"
sudo mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e "grant all privileges on $DBNAME.* to '$DBUSER_MISP'@'localhost';"
sudo mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e "flush privileges;"
```

#### Import the empty MISP database from MYSQL.sql
```bash
# Import the empty MISP database from MYSQL.sql
sudo -u www-data cat $PATH_TO_MISP/INSTALL/MYSQL.sql | mysql -u $DBUSER_MISP -p$DBPASSWORD_MISP $DBNAME
```

### 7/ Apache configuration
-----------------------
Now configure your Apache webserver with the DocumentRoot ${PATH_TO_MISP}/app/webroot/

#### Apache version 2.4 config:
```bash
sudo cp ${PATH_TO_MISP}/INSTALL/apache.24.misp.ssl /etc/apache2/sites-available/misp-ssl.conf
```

!!! notice
    Be aware that the configuration files for apache 2.4 and up have changed.
    The configuration file has to have the .conf extension in the sites-available directory
    For more information, visit http://httpd.apache.org/docs/2.4/upgrading.html

```bash
# If a valid SSL certificate is not already created for the server,
# create a self-signed certificate:
sudo openssl req -newkey rsa:4096 -days 365 -nodes -x509 \
-subj "/C=${OPENSSL_C}/ST=${OPENSSL_ST}/L=${OPENSSL_L}/O=${OPENSSL_O}/OU=${OPENSSL_OU}/CN=${OPENSSL_CN}/emailAddress=${OPENSSL_EMAILADDRESS}" \
-keyout /etc/ssl/private/misp.local.key -out /etc/ssl/private/misp.local.crt
```

!!! notice
    Please find a sample conf file for an SSL enabled conf file in-line below (alternatively use one of the samples provided in /var/www/MISP/INSTALL).<br />
    Also remember to verify the SSLCertificateChainFile property in your config file.<br />
    This is usually commented out for the self-generated certificate in the sample configurations, such as the one pasted below.<br />
    Otherwise, copy the SSLCertificateFile, SSLCertificateKeyFile, and SSLCertificateChainFile to /etc/ssl/private/. (Modify path and config to fit your environment)

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
        DocumentRoot /var/www/MISP/app/webroot
        <Directory /var/www/MISP/app/webroot>
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
```

```bash
# activate new vhost
sudo a2dissite default-ssl
sudo a2ensite misp-ssl

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
# MISP saves the stdout and stderr of its workers in ${PATH_TO_MISP}/app/tmp/logs
# To rotate these logs install the supplied logrotate script:

sudo cp ${PATH_TO_MISP}/INSTALL/misp.logrotate /etc/logrotate.d/misp
sudo chmod 0640 /etc/logrotate.d/misp
```

### 9/ MISP configuration
---------------------
```bash
# There are 4 sample configuration files in ${PATH_TO_MISP}/app/Config that need to be copied
sudo -u www-data cp -a ${PATH_TO_MISP}/app/Config/bootstrap.default.php ${PATH_TO_MISP}/app/Config/bootstrap.php
sudo -u www-data cp -a ${PATH_TO_MISP}/app/Config/database.default.php ${PATH_TO_MISP}/app/Config/database.php
sudo -u www-data cp -a ${PATH_TO_MISP}/app/Config/core.default.php ${PATH_TO_MISP}/app/Config/core.php
sudo -u www-data cp -a ${PATH_TO_MISP}/app/Config/config.default.php ${PATH_TO_MISP}/app/Config/config.php

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

# Important! Change the salt key in ${PATH_TO_MISP}/app/Config/config.php
# The salt key must be a string at least 32 bytes long.
# The admin user account will be generated on the first login, make sure that the salt is changed before you create that user
# If you forget to do this step, and you are still dealing with a fresh installation, just alter the salt,
# delete the user from mysql and log in again using the default admin credentials (admin@admin.test / admin)

# and make sure the file permissions are still OK
sudo chown -R www-data:www-data ${PATH_TO_MISP}/app/Config
sudo chmod -R 750 ${PATH_TO_MISP}/app/Config

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
```

!!! notice
    If entropy is not high enough, you can install havegd and then start the service
    ```bash
    sudo apt install haveged -y
    sudo service haveged start
    ```

```bash

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

{!generic/misp-modules-debian.md!}


```bash
# Add the following lines before the last line (exit 0). Make sure that you replace www-data with your apache user:
sudo sed -i -e '$i \echo never > /sys/kernel/mm/transparent_hugepage/enabled\n' /etc/rc.local
sudo sed -i -e '$i \echo 1024 > /proc/sys/net/core/somaxconn\n' /etc/rc.local
sudo sed -i -e '$i \sysctl vm.overcommit_memory=1\n' /etc/rc.local
sudo sed -i -e '$i \sudo -u www-data bash ${PATH_TO_MISP}/app/Console/worker/start.sh > /tmp/worker_start_rc.local.log\n' /etc/rc.local

# Start the workers
sudo -u www-data bash $PATH_TO_MISP/app/Console/worker/start.sh

echo "Admin (root) DB Password: $DBPASSWORD_ADMIN"
echo "User  (misp) DB Password: $DBPASSWORD_MISP"
```

{!generic/INSTALL.done.md!}

{!generic/recommended.actions.md!}

### Optional features
-----------------
#### MISP has a new pub/sub feature, using ZeroMQ. To enable it, simply run the following command
```bash
sudo -H -u www-data ${PATH_TO_MISP}/venv/bin/pip install pyzmq
```

{!generic/misp-dashboard-debian.md!}

{!generic/viper-debian.md!}

{!generic/ssdeep-debian.md!}

{!generic/mail_to_misp-debian.md!}

{!generic/hardening.md!}

#### misp-modules (section deprecated)
-------------------------------
!!! notice
    If you want to add the misp modules functionality, follow the setup procedure described in misp-modules:<br />
    https://github.com/MISP/misp-modules#how-to-install-and-start-misp-modules<br />
    Then the enrichment, export and import modules can be enabled in MISP via the settings.

# INSTALL.debian.sh

!!! notice
    The following section is an administrative section that is used by the "[INSTALL.debian.sh](https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.debian.sh)" script.
    Please ignore.

{!generic/supportFunctions.md!}
