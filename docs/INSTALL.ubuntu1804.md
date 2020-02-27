# INSTALLATION INSTRUCTIONS
## for Ubuntu 18.04.3-server

### -1/ Installer and Manual install instructions

Make sure you are reading the parsed version of this Document. When in doubt [click here](https://misp.github.io/MISP/INSTALL.ubuntu1804/).

To install MISP on a fresh Ubuntu 18.04, all you need to do is the following:

```bash
# Please check the installer options first to make the best choice for your install
wget -O /tmp/INSTALL.sh https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.sh
bash /tmp/INSTALL.sh

# This will install MISP Core
wget -O /tmp/INSTALL.sh https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.sh
bash /tmp/INSTALL.sh -c
```

### 0/ MISP Ubuntu 18.04-server install - status
-------------------------
!!! notice
    Installer tested working by [@SteveClement](https://twitter.com/SteveClement) on 20190513 (works with **Ubuntu 18.10/19.04** too)

!!! notice
    This document also serves as a source for the [INSTALL-misp.sh](https://github.com/MISP/MISP/blob/2.4/INSTALL/INSTALL.sh) script.
    Which explains why you will see the use of shell *functions* in various steps.
    Henceforth the document will also follow a more logical flow. In the sense that all the dependencies are installed first then config files are generated, etc...

!!! notice
    If the next line is `[!generic/core.md!]()` [click here](https://misp.github.io/MISP/INSTALL.ubuntu1804/).

{!generic/core.md!}

### 1/ Minimal Ubuntu install
-------------------------

#### Install a minimal Ubuntu 18.04-server system with the software:
- OpenSSH server
- This guide assumes a user name of 'misp' with sudo working

#### Make sure your system is up2date
```bash
# <snippet-begin 0_apt-upgrade.sh>
aptUpgrade () {
  debug "Upgrading system"
  checkAptLock
  sudo apt-get update

  # If we run in non-interactive mode, make sure we do not stop all of a sudden
  if [[ "${PACKER}" == "1" || "${UNATTENDED}" == "1" ]]; then
    export DEBIAN_FRONTEND=noninteractive
    export DEBIAN_PRIORITY=critical
    sudo -E apt-get -qy -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold" upgrade
    sudo -E apt-get -qy autoclean
  else
    sudo apt-get upgrade -qy
  fi
}
# <snippet-end 0_apt-upgrade.sh>
```

{!generic/sudo_etckeeper.md!}

{!generic/ethX.md!}

#### install postfix, there will be some questions.
```bash
# <snippet-begin postfix.sh>
sudo apt-get install postfix dialog -qy
# <snippet-end postfix.sh>
```

!!! notice
    Postfix Configuration: Satellite system<br />
    change the relay server later with:
    ```bash
    sudo postconf -e 'relayhost = example.com'
    sudo postfix reload
    ```

{!generic/globalVariables.md!}

### 2/ Install LAMP & dependencies
------------------------------
Once the system is installed you can perform the following steps.
```bash
# <snippet-begin 0_installCoreDeps.sh>
installCoreDeps () {
  debug "Installing core dependencies"
  # Install the dependencies: (some might already be installed)
  sudo apt-get install curl gcc git gpg-agent make python python3 openssl redis-server sudo vim zip unzip virtualenv libfuzzy-dev sqlite3 moreutils -qy

  # Install MariaDB (a MySQL fork/alternative)
  sudo apt-get install mariadb-client mariadb-server -qy

  # Install Apache2
  sudo apt-get install apache2 apache2-doc apache2-utils -qy

  # install Mitre's STIX and its dependencies by running the following commands:
  sudo apt-get install python3-dev python3-pip libxml2-dev libxslt1-dev zlib1g-dev python-setuptools -qy

  sudo apt install expect -qy
}
# <snippet-end 0_installCoreDeps.sh>

# <snippet-begin 0_installDepsPhp72.sh>
# Install Php 7.2 dependencies
installDepsPhp72 () {
  debug "Installing PHP 7.2 dependencies"
  PHP_ETC_BASE=/etc/php/7.2
  PHP_INI=${PHP_ETC_BASE}/apache2/php.ini
  sudo apt update
  sudo apt install -qy \
  libapache2-mod-php \
  php php-cli \
  php-dev \
  php-json php-xml php-mysql php7.2-opcache php-readline php-mbstring \
  php-redis php-gnupg \
  php-gd

  for key in upload_max_filesize post_max_size max_execution_time max_input_time memory_limit
  do
      sudo sed -i "s/^\($key\).*/\1 = $(eval echo \${$key})/" $PHP_INI
  done
}
# <snippet-end 0_installDepsPhp72.sh>
```

### 3/ MISP code
------------
```bash
# <snippet-begin 1_mispCoreInstall.sh>
installCore () {
  debug "Installing ${LBLUE}MISP${NC} core"
  # Download MISP using git in the /var/www/ directory.
  sudo mkdir ${PATH_TO_MISP}
  sudo chown $WWW_USER:$WWW_USER ${PATH_TO_MISP}
  cd ${PATH_TO_MISP}
  $SUDO_WWW git clone https://github.com/MISP/MISP.git ${PATH_TO_MISP}
  $SUDO_WWW git submodule update --init --recursive
  # Make git ignore filesystem permission differences for submodules
  $SUDO_WWW git submodule foreach --recursive git config core.filemode false

  # Make git ignore filesystem permission differences
  $SUDO_WWW git config core.filemode false

  # Create a python3 virtualenv
  $SUDO_WWW virtualenv -p python3 ${PATH_TO_MISP}/venv

  # make pip happy
  sudo mkdir /var/www/.cache/
  sudo chown $WWW_USER:$WWW_USER /var/www/.cache

  cd ${PATH_TO_MISP}/app/files/scripts
  $SUDO_WWW git clone https://github.com/CybOXProject/python-cybox.git
  $SUDO_WWW git clone https://github.com/STIXProject/python-stix.git
  $SUDO_WWW git clone https://github.com/MAECProject/python-maec.git

  # install mixbox to accommodate the new STIX dependencies:
  $SUDO_WWW git clone https://github.com/CybOXProject/mixbox.git
  cd ${PATH_TO_MISP}/app/files/scripts/mixbox
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install .
  cd ${PATH_TO_MISP}/app/files/scripts/python-cybox
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install .
  cd ${PATH_TO_MISP}/app/files/scripts/python-stix
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install .
  cd $PATH_TO_MISP/app/files/scripts/python-maec
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install .
  # FIXME: Remove once stix-fixed
  $SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -I antlr4-python3-runtime==4.7.2
  # install STIX2.0 library to support STIX 2.0 export:
  cd ${PATH_TO_MISP}/cti-python-stix2
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install .

  # install PyMISP
  cd ${PATH_TO_MISP}/PyMISP
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install .

  # install pydeep
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install git+https://github.com/kbandla/pydeep.git

  # install lief
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install https://github.com/lief-project/packages/raw/lief-master-latest/pylief-0.9.0.dev.zip

  # install zmq needed by mispzmq
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install zmq redis

  # install python-magic
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install python-magic

  # install plyara
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install plyara
}
# <snippet-end 1_mispCoreInstall.sh>
```

### 4/ CakePHP
-----------

```bash
# <snippet-begin 1_installCake.sh>
installCake () {
  debug "Installing CakePHP"
  # Once done, install CakeResque along with its dependencies 
  # if you intend to use the built in background jobs:
  cd ${PATH_TO_MISP}/app
  # Make composer cache happy
  # /!\ composer on Ubuntu when invoked with sudo -u doesn't set $HOME to /var/www but keeps it /home/misp \!/
  sudo mkdir /var/www/.composer ; sudo chown $WWW_USER:$WWW_USER /var/www/.composer
  $SUDO_WWW php composer.phar install

  # Enable CakeResque with php-redis
  sudo phpenmod redis
  sudo phpenmod gnupg

  # To use the scheduler worker for scheduled tasks, do the following:
  $SUDO_WWW cp -fa ${PATH_TO_MISP}/INSTALL/setup/config.php ${PATH_TO_MISP}/app/Plugin/CakeResque/Config/config.php

  # If you have multiple MISP instances on the same system, don't forget to have a different Redis per MISP instance for the CakeResque workers
  # The default Redis port can be updated in Plugin/CakeResque/Config/config.php
}
# <snippet-end 1_installCake.sh>
```

### 5/ Set the permissions
----------------------

```bash
# <snippet-begin 2_permissions.sh>
# Main function to fix permissions to something sane
permissions () {
  debug "Setting permissions"
  sudo chown -R ${WWW_USER}:${WWW_USER} ${PATH_TO_MISP}
  sudo chmod -R 750 ${PATH_TO_MISP}
  sudo chmod -R g+ws ${PATH_TO_MISP}/app/tmp
  sudo chmod -R g+ws ${PATH_TO_MISP}/app/files
  sudo chmod -R g+ws $PATH_TO_MISP/app/files/scripts/tmp
}
# <snippet-end 2_permissions.sh>
```

### 6/ Create a database and user
-----------------------------

#### Set-up DB, User and import empty MISP DB

```bash
# <snippet-begin 1_prepareDB.sh>
prepareDB () {
  if [[ ! -e /var/lib/mysql/misp/users.ibd ]]; then
    debug "Setting up database"

    # FIXME: If user 'misp' exists, and has a different password, the below WILL fail.
    # Add your credentials if needed, if sudo has NOPASS, comment out the relevant lines
    if [[ "${PACKER}" == "1" ]]; then
      pw="Password1234"
    else
      pw=${MISP_PASSWORD}
    fi

    expect -f - <<-EOF
      set timeout 10

      spawn sudo -k mysql_secure_installation
      expect "*?assword*"
      send -- "${pw}\r"
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
    sudo apt-get purge -y expect ; sudo apt autoremove -qy
  fi 

  sudo mysql -u ${DBUSER_ADMIN} -p${DBPASSWORD_ADMIN} -e "CREATE DATABASE ${DBNAME};"
  sudo mysql -u ${DBUSER_ADMIN} -p${DBPASSWORD_ADMIN} -e "CREATE USER '${DBUSER_MISP}'@'localhost' IDENTIFIED BY '${DBPASSWORD_MISP}';"
  sudo mysql -u ${DBUSER_ADMIN} -p${DBPASSWORD_ADMIN} -e "GRANT USAGE ON *.* to ${DBUSER_MISP}@localhost;"
  sudo mysql -u ${DBUSER_ADMIN} -p${DBPASSWORD_ADMIN} -e "GRANT ALL PRIVILEGES on ${DBNAME}.* to '${DBUSER_MISP}'@'localhost';"
  sudo mysql -u ${DBUSER_ADMIN} -p${DBPASSWORD_ADMIN} -e "FLUSH PRIVILEGES;"
  # Import the empty MISP database from MYSQL.sql
  ${SUDO_WWW} cat ${PATH_TO_MISP}/INSTALL/MYSQL.sql | mysql -u ${DBUSER_MISP} -p${DBPASSWORD_MISP} ${DBNAME}
}
# <snippet-end 1_prepareDB.sh>
```

### 7/ Apache configuration
-----------------------
Now configure your Apache webserver with the DocumentRoot ${PATH_TO_MISP}/app/webroot/

#### Apache version 2.4 config:

!!! notice
    Be aware that the configuration files for apache 2.4 and up have changed.
    The configuration file has to have the .conf extension in the sites-available directory
    For more information, visit http://httpd.apache.org/docs/2.4/upgrading.html

```bash
# <snippet-begin 1_apacheConfig.sh>
apacheConfig () {
  debug "Generating Apache config, if this hangs, make sure you have enough entropy (install: haveged or wait)"
  sudo cp ${PATH_TO_MISP}/INSTALL/apache.24.misp.ssl /etc/apache2/sites-available/misp-ssl.conf

  if [[ ! -z ${MISP_BASEURL} ]] && [[ "$(echo $MISP_BASEURL|cut -f 1 -d :)" == "http" || "$(echo $MISP_BASEURL|cut -f 1 -d :)" == "https" ]]; then

    echo "Potentially replacing misp.local with $MISP_BASEURL in misp-ssl.conf"

  fi

  # If a valid SSL certificate is not already created for the server,
  # create a self-signed certificate:
  sudo openssl req -newkey rsa:4096 -days 365 -nodes -x509 \
  -subj "/C=${OPENSSL_C}/ST=${OPENSSL_ST}/L=${OPENSSL_L}/O=${OPENSSL_O}/OU=${OPENSSL_OU}/CN=${OPENSSL_CN}/emailAddress=${OPENSSL_EMAILADDRESS}" \
  -keyout /etc/ssl/private/misp.local.key -out /etc/ssl/private/misp.local.crt

  # Enable modules, settings, and default of SSL in Apache
  sudo a2dismod status
  sudo a2enmod ssl
  sudo a2enmod rewrite
  sudo a2enmod headers
  sudo a2dissite 000-default
  sudo a2ensite default-ssl

  # Apply all changes
  sudo systemctl restart apache2
  # activate new vhost
  sudo a2dissite default-ssl
  sudo a2ensite misp-ssl

  # Restart apache
  sudo systemctl restart apache2
}
# <snippet-end 1_apacheConfig.sh>
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

### 8/ Log rotation
---------------
```bash
# <snippet-begin 2_logRotation.sh>
logRotation () {
  # MISP saves the stdout and stderr of its workers in ${PATH_TO_MISP}/app/tmp/logs
  # To rotate these logs install the supplied logrotate script:
  sudo cp ${PATH_TO_MISP}/INSTALL/misp.logrotate /etc/logrotate.d/misp
  sudo chmod 0640 /etc/logrotate.d/misp
}
# <snippet-end 2_logRotation.sh>
```

### 9/ MISP configuration
---------------------
```bash
# <snippet-begin 2_configMISP.sh>
configMISP () {
  debug "Generating ${LBLUE}MISP${NC} config files"
  # There are 4 sample configuration files in ${PATH_TO_MISP}/app/Config that need to be copied
  $SUDO_WWW cp -a ${PATH_TO_MISP}/app/Config/bootstrap.default.php ${PATH_TO_MISP}/app/Config/bootstrap.php
  $SUDO_WWW cp -a ${PATH_TO_MISP}/app/Config/database.default.php ${PATH_TO_MISP}/app/Config/database.php
  $SUDO_WWW cp -a ${PATH_TO_MISP}/app/Config/core.default.php ${PATH_TO_MISP}/app/Config/core.php
  $SUDO_WWW cp -a ${PATH_TO_MISP}/app/Config/config.default.php ${PATH_TO_MISP}/app/Config/config.php

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
  }" | $SUDO_WWW tee $PATH_TO_MISP/app/Config/database.php

  # Important! Change the salt key in ${PATH_TO_MISP}/app/Config/config.php
  # The salt key must be a string at least 32 bytes long.
  # The admin user account will be generated on the first login, make sure that the salt is changed before you create that user
  # If you forget to do this step, and you are still dealing with a fresh installation, just alter the salt,
  # delete the user from mysql and log in again using the default admin credentials (admin@admin.test / admin)

  # and make sure the file permissions are still OK
  sudo chown -R $WWW_USER:$WWW_USER ${PATH_TO_MISP}/app/Config
  sudo chmod -R 750 ${PATH_TO_MISP}/app/Config
}
# <snippet-end 2_configMISP.sh>
```

{!generic/gnupg.md!}

!!! notice
    If entropy is not high enough, you can install havegd and then start the service
    ```bash
    sudo apt install haveged -qy
    sudo service haveged start
    ```

```bash
# <snippet-begin 2_backgroundWorkers.sh>
backgroundWorkers () {
  debug "Setting up background workers"
  # To make the background workers start on boot
  sudo chmod +x $PATH_TO_MISP/app/Console/worker/start.sh

  if [ ! -e /etc/rc.local ]
  then
      echo '#!/bin/sh -e' | sudo tee -a /etc/rc.local
      echo 'exit 0' | sudo tee -a /etc/rc.local
      sudo chmod u+x /etc/rc.local
  fi

  echo "[Unit]
Description=MISP background workers
After=network.target

[Service]
Type=forking
User=${WWW_USER}
Group=${WWW_USER}
ExecStart=${PATH_TO_MISP}/app/Console/worker/start.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target" | sudo tee /etc/systemd/system/misp-workers.service

  sudo systemctl daemon-reload
  sudo systemctl enable --now misp-workers

  # Add the following lines before the last line (exit 0). Make sure that you replace www-data with your apache user:
  sudo sed -i -e '$i \echo never > /sys/kernel/mm/transparent_hugepage/enabled\n' /etc/rc.local
  sudo sed -i -e '$i \echo 1024 > /proc/sys/net/core/somaxconn\n' /etc/rc.local
  sudo sed -i -e '$i \sysctl vm.overcommit_memory=1\n' /etc/rc.local
}
# <snippet-end 2_backgroundWorkers.sh>
```

```bash
echo "Admin (root) DB Password: $DBPASSWORD_ADMIN"
echo "User  (misp) DB Password: $DBPASSWORD_MISP"
```

{!generic/MISP_CAKE_init.md!}

{!generic/misp-modules-debian.md!}

{!generic/INSTALL.done.md!}

{!generic/recommended.actions.md!}

### Optional features
-----------------
#### MISP has a new pub/sub feature, using ZeroMQ. To enable it, simply run the following command
```bash
$SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install pyzmq
```

#### MISP has a feature for publishing events to Kafka. To enable it, simply run the following commands
```bash
# <snippet-begin 4_kafka.sh>
installKafka () {
  sudo apt-get install librdkafka-dev php-dev -y
  sudo pecl channel-update pecl.php.net
  sudo pecl install rdkafka
  echo "extension=rdkafka.so" | sudo tee ${PHP_ETC_BASE}/mods-available/rdkafka.ini
  sudo phpenmod rdkafka
  sudo service apache2 restart
}
# <snippet-end 4_kafka.sh>
```

{!generic/misp-dashboard-debian.md!}

{!generic/viper-debian.md!}

{!generic/ssdeep-debian.md!}

{!generic/mail_to_misp-debian.md!}

{!generic/hardening.md!}

# INSTALL.sh

!!! notice
    The following section is an administrative section that is used by the "[INSTALL.sh](https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.sh)" script.
    Please ignore.

{!generic/supportFunctions.md!}
