# INSTALLATION INSTRUCTIONS
## for CentOS 6.10

### -1/ Installer and Manual install instructions

Make sure you are reading the parsed version of this Document. When in doubt [click here](https://misp.github.io/MISP/xINSTALL.centos6/).

!!! warning
    In the **future**, to install MISP on a fresh CentOS 6 install all you need to do is:

    ```bash
    # Please check the installer options first to make the best choice for your install
    wget -O /tmp/INSTALL.sh https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.sh
    bash /tmp/INSTALL.sh

    # This will install MISP Core
    wget -O /tmp/INSTALL.sh https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.sh
    bash /tmp/INSTALL.sh -c
    ```
    **The above does NOT work yet**

### 0/ MISP CentOS 6 Minimal NetInstall - Status
--------------------------------------------

{!generic/community.md!}

{!generic/rhelVScentos.md!}

!!! notice
    Semi-maintained and tested by @SteveClement, CentOS 6.10 on 20190417<br />
    It is still considered experimental as not everything works seemlessly.

!!! notice
    Maintenance will end on: November 30th, 2020 [Source[0]](https://wiki.centos.org/About/Product) [Source[1]](https://linuxlifecycle.com/)

CentOS 6.10 [NetInstallURL](http://mirrors.sonic.net/centos/6.10/os/x86_64/)

{!generic/globalVariables.md!}

```bash
# CentOS Specific
RUN_PHP='/usr/bin/scl enable rh-php70 '
RUN_PYTHON='/usr/bin/scl enable rh-python36 '
SUDO_WWW='sudo -H -u apache'

PHP_INI=/etc/opt/rh/rh-php70/php.ini
```

### 1/ Minimal CentOS install
-------------------------

Install a minimal CentOS 6.x system with the software:

- OpenSSH server
- LAMP server (actually, this is done below)
- Mail server


```bash
# Make sure you set your hostname CORRECTLY vs. like an brute (manually in /etc/hostname)
sudo hostnamectl set-hostname misp.local # Your choice, in a production environment, it's best to use a FQDN

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

# php 7.2
# sudo rpm -Uvh http://rpms.famillecollet.com/enterprise/remi-release-6.rpm
# sudo yum install yum-utils
# sudo yum-config-manager --enable remi-php72
# sudo yum update


# Since MISP 2.4 PHP 5.5 is a minimal requirement, so we need a newer version than CentOS base provides
# Software Collections is a way do to this, see https://wiki.centos.org/AdditionalResources/Repositories/SCL
sudo yum install centos-release-scl -y

# Because vim is just so practical
sudo yum install vim -y

# Install the dependencies:
sudo yum install gcc git zip \
       httpd \
       mod_ssl \
       redis \
       mysql-server \
       python-devel python-pip python-zmq \
       libxslt-devel zlib-devel ssdeep-devel -y

# Install PHP 7.0 from SCL, see https://www.softwarecollections.org/en/scls/rhscl/rh-php70/
sudo yum install rh-php70 rh-php70-php-fpm rh-php70-php-devel rh-php70-php-mysqlnd rh-php70-php-mbstring rh-php70-php-xml rh-php70-php-bcmath rh-php70-php-gd

# Install Python 3.6 from SCL, see https://www.softwarecollections.org/en/scls/rhscl/rh-python36/
sudo yum install rh-python36 -y

# rh-php70-php only provided mod_php for httpd24-httpd from SCL
# if we want to use httpd from CentOS base we can use rh-php70-php-fpm instead
sudo chkconfig rh-php70-php-fpm on
sudo service rh-php70-php-fpm start

# php-fpm is accessed using the fcgi interface
sudo yum install mod_fcgid mod_proxy_fcgi
```

!!! notice
    $RUN_PHP makes php available for you if using rh-php70. e.g: $RUN_PHP "pear list | grep Crypt_GPG"

```bash
# GPG needs lots of entropy, haveged provides entropy
sudo yum install haveged -y
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
sudo mkdir $PATH_TO_MISP
sudo chown apache:apache $PATH_TO_MISP
cd /var/www
$SUDO_WWW git clone https://github.com/MISP/MISP.git
cd $PATH_TO_MISP
##$SUDO_WWW git checkout tags/$(git describe --tags `git rev-list --tags --max-count=1`)
# if the last shortcut doesn't work, specify the latest version manually
# example: git checkout tags/v2.4.XY
# the message regarding a "detached HEAD state" is expected behaviour
# (you only have to create a new branch, if you want to change stuff and do a pull request for example)

# Fetch submodules
$SUDO_WWW git submodule update --init --recursive
# Make git ignore filesystem permission differences for submodules
$SUDO_WWW git submodule foreach --recursive git config core.filemode false

# Create a python3 virtualenv
$SUDO_WWW $RUN_PYTHON "virtualenv -p python3 $PATH_TO_MISP/venv"
sudo mkdir /var/www/.cache
sudo chown apache:apache /var/www/.cache
$SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U pip setuptools

# install Mitre's STIX and its dependencies by running the following commands:
sudo yum install python-importlib python-lxml python-dateutil python-six -y
cd $PATH_TO_MISP/app/files/scripts
$SUDO_WWW git clone https://github.com/CybOXProject/python-cybox.git
$SUDO_WWW git clone https://github.com/STIXProject/python-stix.git
cd $PATH_TO_MISP/app/files/scripts/python-cybox
# If you umask is has been changed from the default, it is a good idea to reset it to 0022 before installing python modules
UMASK=$(umask)
umask 0022
cd $PATH_TO_MISP/app/files/scripts/python-stix
$SUDO_WWW $PATH_TO_MISP/venv/bin/pip install .

# install maec
$SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U maec

# install zmq
$SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U zmq

# install redis
$SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U redis

# lief needs manual compilation
sudo yum install devtoolset-7 cmake3 -y

sudo yum install http://opensource.wandisco.com/centos/6/git/x86_64/wandisco-git-release-6-1.noarch.rpm
sudo yum install git -y
cd $PATH_TO_MISP/app/files/scripts
$SUDO_WWW git clone --branch master --single-branch https://github.com/lief-project/LIEF.git lief

# TODO: Fix static path with PATH_TO_MISP
cd $PATH_TO_MISP/app/files/scripts/lief
$SUDO_WWW mkdir build
cd build
$SUDO_WWW scl enable devtoolset-7 rh-python36 'bash -c "cmake3 \
-DLIEF_PYTHON_API=on \
-DLIEF_DOC=off \
-DCMAKE_INSTALL_PREFIX=$LIEF_INSTALL \
-DCMAKE_BUILD_TYPE=Release \
-DPYTHON_VERSION=3.6 \
-DPYTHON_EXECUTABLE=/var/www/MISP/venv/bin/python \
.."'
$SUDO_WWW make -j3
sudo make install
cd api/python/lief_pybind11-prefix/src/lief_pybind11
$SUDO_WWW $PATH_TO_MISP/venv/bin/python setup.py install
$SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install https://github.com/lief-project/packages/raw/lief-master-latest/pylief-0.9.0.dev.zip

# install magic, pydeep
$SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U python-magic
## pydeep does not compile ):
## git+https://github.com/kbandla/pydeep.git

# install mixbox to accommodate the new STIX dependencies:
cd $PATH_TO_MISP/app/files/scripts/
$SUDO_WWW git clone https://github.com/CybOXProject/mixbox.git
cd $PATH_TO_MISP/app/files/scripts/mixbox
$SUDO_WWW $PATH_TO_MISP/venv/bin/pip install .

# FIXME: Remove once stix-fixed
$SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -I antlr4-python3-runtime==4.7.2

# install STIX2.0 library to support STIX 2.0 export:
cd $PATH_TO_MISP/cti-python-stix2
$SUDO_WWW $PATH_TO_MISP/venv/bin/pip install .

# install PyMISP
cd $PATH_TO_MISP/PyMISP
$SUDO_WWW $PATH_TO_MISP/venv/bin/pip install .

# Enable python3 for php-fpm
echo 'source scl_source enable rh-python36' | sudo tee -a /etc/opt/rh/rh-php70/sysconfig/php-fpm
sudo sed -i.org -e 's/^;\(clear_env = no\)/\1/' /etc/opt/rh/rh-php70/php-fpm.d/www.conf
sudo service rh-php70-php-fpm restart

umask $UMASK

# Enable dependencies detection in the diagnostics page
# This allows MISP to detect GnuPG, the Python modules' versions and to read the PHP settings.
echo "env[PATH] =/opt/rh/rh-python36/root/usr/bin:/opt/rh/rh-php70/root/usr/bin:/usr/local/bin:/usr/bin:/bin" |sudo tee -a /etc/opt/rh/rh-php70/php-fpm.d/www.conf
sudo service rh-php70-php-fpm restart
```

### 4/ CakePHP
-----------
#### CakePHP is now included as a submodule of MISP and has been fetch by a previous step.
#### Install CakeResque along with its dependencies if you intend to use the built in background jobs.
```bash
sudo chown -R apache:apache $PATH_TO_MISP
sudo mkdir /var/www/.composer/
sudo chown apache:apache /var/www/.composer/
cd $PATH_TO_MISP/app
# Update composer.phar (optional)
#EXPECTED_SIGNATURE="$(wget -q -O - https://composer.github.io/installer.sig)"
#$SUDO_WWW $RUN_PHP -- php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
#$SUDO_WWW $RUN_PHP -- php -r "if (hash_file('SHA384', 'composer-setup.php') === '$EXPECTED_SIGNATURE') { echo 'Installer verified'; } else { echo 'Installer corrupt'; unlink('composer-setup.php'); } echo PHP_EOL;"
#$SUDO_WWW $RUN_PHP "php composer-setup.php"
#$SUDO_WWW $RUN_PHP -- php -r "unlink('composer-setup.php');"
$SUDO_WWW $RUN_PHP "php composer.phar install"

sudo yum install php-redis -y
sudo service rh-php70-php-fpm restart

# If you have not yet set a timezone in php.ini
echo 'date.timezone = "Europe/Luxembourg"' |sudo tee /etc/opt/rh/rh-php70/php-fpm.d/timezone.ini
sudo ln -s ../php-fpm.d/timezone.ini /etc/opt/rh/rh-php70/php.d/99-timezone.ini

# Recommended: Change some PHP settings in /etc/opt/rh/rh-php70/php.ini
# max_execution_time=300
# memory_limit=2048M
# upload_max_filesize=50M
# post_max_size=50M
for key in upload_max_filesize post_max_size max_execution_time max_input_time memory_limit
do
    sudo sed -i "s/^\($key\).*/\1 = $(eval echo \${$key})/" $PHP_INI
done
sudo service rh-php70-php-fpm restart
# To use the scheduler worker for scheduled tasks, do the following:
sudo cp -fa $PATH_TO_MISP/INSTALL/setup/config.php $PATH_TO_MISP/app/Plugin/CakeResque/Config/config.php
```

### 5/ Set the permissions
----------------------
```bash
# Make sure the permissions are set correctly using the following commands as root:
sudo chown -R apache:apache $PATH_TO_MISP
sudo find $PATH_TO_MISP -type d -exec chmod g=rx {} \;
sudo chmod -R g+r,o= $PATH_TO_MISP
sudo chmod -R 750 $PATH_TO_MISP
sudo chmod -R g+xws $PATH_TO_MISP/app/tmp
sudo chmod -R g+ws $PATH_TO_MISP/app/files
sudo chmod -R g+ws $PATH_TO_MISP/app/files/scripts/tmp
sudo chmod -R g+rw $PATH_TO_MISP/venv
sudo chmod -R g+rw $PATH_TO_MISP/.git
sudo chown apache:apache $PATH_TO_MISP/app/files
sudo chown apache:apache $PATH_TO_MISP/app/files/terms
sudo chown apache:apache $PATH_TO_MISP/app/files/scripts/tmp
sudo chown apache:apache $PATH_TO_MISP/app/Plugin/CakeResque/tmp
sudo chown -R apache:apache $PATH_TO_MISP/app/Config
sudo chown -R apache:apache $PATH_TO_MISP/app/tmp
sudo chown -R apache:apache $PATH_TO_MISP/app/webroot/img/orgs
sudo chown -R apache:apache $PATH_TO_MISP/app/webroot/img/custom
```

### 6/ Create a database and user
-----------------------------
```bash
# Enable, start and secure your mysql database server
sudo chkconfig mysqld on
sudo service mysqld start
sudo yum install expect -y

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

sudo yum remove tcl expect -y

# Additionally, it is probably a good idea to make the database server listen on localhost only
echo [mysqld] |sudo tee /etc/my.cnf.d/bind-address.cnf
echo bind-address=127.0.0.1 |sudo tee -a /etc/my.cnf.d/bind-address.cnf
sudo service mysqld restart
```


#### Manual procedure:
```bash
# Enter the mysql shell
mysql -u root -p
```

```
mysql> create database misp;
mysql> grant usage on *.* to misp@localhost identified by 'XXXXXXXXX';
mysql> grant all privileges on misp.* to misp@localhost ;
mysql> exit
```

#### Same as Manual but for copy/paste foo:
```bash
sudo mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e "create database $DBNAME;"
sudo mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e "grant usage on *.* to $DBNAME@localhost identified by '$DBPASSWORD_MISP';"
sudo mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e "grant all privileges on $DBNAME.* to '$DBUSER_MISP'@'localhost';"
sudo mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e "flush privileges;"
```

#### Import the empty MySQL database from MYSQL.sql
```bash
$SUDO_WWW cat $PATH_TO_MISP/INSTALL/MYSQL.sql | mysql -u $DBUSER_MISP -p$DBPASSWORD_MISP $DBNAME
```


### 7/ Apache configuration
-----------------------

!!! notice
    SELinux note, to check if it is running:
    ```bash
    $ sestatus
    SELinux status:                 disabled
    ```
    If it is disabled, you can ignore the **chcon/setsebool/semanage/checkmodule/semodule*** commands.

```bash
# Now configure your apache server with the DocumentRoot $PATH_TO_MISP/app/webroot/
# A sample vhost can be found in $PATH_TO_MISP/INSTALL/old/apache.misp.centos6

sudo cp $PATH_TO_MISP/INSTALL/old/apache.misp.centos6 /etc/httpd/conf.d/misp.conf

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
# MISP saves the stdout and stderr of its workers in $PATH_TO_MISP/app/tmp/logs
# To rotate these logs install the supplied logrotate script:

sudo cp $PATH_TO_MISP/INSTALL/misp.logrotate /etc/logrotate.d/misp
sudo chmod 0640 /etc/logrotate.d/misp

# Now make logrotate work under SELinux as well
# Allow logrotate to modify the log files
sudo semanage fcontext -a -t httpd_log_t "$PATH_TO_MISP/app/tmp/logs(/.*)?"
sudo chcon -R -t httpd_log_t $PATH_TO_MISP/app/tmp/logs
sudo chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/app/tmp/logs

# Allow logrotate to read /var/www
sudo checkmodule -M -m -o /tmp/misplogrotate.mod $PATH_TO_MISP/INSTALL/misplogrotate.te
sudo semodule_package -o /tmp/misplogrotate.pp -m /tmp/misplogrotate.mod
sudo semodule -i /tmp/misplogrotate.pp
```

### 9/ MISP configuration
---------------------
```bash
# There are 4 sample configuration files in $PATH_TO_MISP/app/Config that need to be copied
$SUDO_WWW cp -a $PATH_TO_MISP/app/Config/bootstrap.default.php $PATH_TO_MISP/app/Config/bootstrap.php
$SUDO_WWW cp -a $PATH_TO_MISP/app/Config/database.default.php $PATH_TO_MISP/app/Config/database.php
$SUDO_WWW cp -a $PATH_TO_MISP/app/Config/core.default.php $PATH_TO_MISP/app/Config/core.php
$SUDO_WWW cp -a $PATH_TO_MISP/app/Config/config.default.php $PATH_TO_MISP/app/Config/config.php

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

# Important! Change the salt key in $PATH_TO_MISP/app/Config/config.php
# The admin user account will be generated on the first login, make sure that the salt is changed before you create that user
# If you forget to do this step, and you are still dealing with a fresh installation, just alter the salt,
# delete the user from mysql and log in again using the default admin credentials (admin@admin.test / admin)

# If you want to be able to change configuration parameters from the webinterface:
sudo chown apache:apache $PATH_TO_MISP/app/Config/config.php
sudo chcon -t httpd_sys_rw_content_t $PATH_TO_MISP/app/Config/config.php

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

sudo gpg --homedir $PATH_TO_MISP/.gnupg --batch --gen-key /tmp/gen-key-script
sudo rm -f /tmp/gen-key-script
sudo chown -R apache:apache $PATH_TO_MISP/.gnupg

# And export the public key to the webroot
sudo gpg --homedir $PATH_TO_MISP/.gnupg --export --armor $GPG_EMAIL_ADDRESS |sudo tee $PATH_TO_MISP/app/webroot/gpg.asc
sudo chown apache:apache $PATH_TO_MISP/app/webroot/gpg.asc

# Start the workers to enable background jobs
sudo chmod +x $PATH_TO_MISP/app/Console/worker/start.sh
$SUDO_WWW $RUN_PHP $PATH_TO_MISP/app/Console/worker/start.sh

if [ ! -e /etc/rc.local ]
then
    echo '#!/bin/sh -e' | sudo tee -a /etc/rc.local
    echo 'exit 0' | sudo tee -a /etc/rc.local
    sudo chmod u+x /etc/rc.local
fi

# TODO: Fix static path with PATH_TO_MISP
sudo sed -i -e '$i \su -s /bin/bash apache -c "scl enable rh-php70 /var/www/MISP/app/Console/worker/start.sh" > /tmp/worker_start_rc.local.log\n' /etc/rc.local
# Make sure it will execute
sudo chmod +x /etc/rc.local

echo "Admin (root) DB Password: $DBPASSWORD_ADMIN"
echo "User  (misp) DB Password: $DBPASSWORD_MISP"
```

```
# some misp-modules dependencies
sudo yum install -y openjpeg-devel

sudo chmod 2777 /usr/local/src
sudo chown root:users /usr/local/src
cd /usr/local/src/
$SUDO_WWW git clone https://github.com/MISP/misp-modules.git
cd misp-modules
# pip install
$SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -I -r REQUIREMENTS
# The following fails
$SUDO_WWW $PATH_TO_MISP/venv/bin/pip install .
sudo yum install rubygem-rouge rubygem-asciidoctor -y
##sudo gem install asciidoctor-pdf --pre

# install additional dependencies for extended object generation and extraction
$SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install maec python-magic pathlib
$SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install git+https://github.com/kbandla/pydeep.git

# Start misp-modules
$SUDO_WWW ${PATH_TO_MISP}/venv/bin/misp-modules -l 0.0.0.0 -s &

# TODO: Fix static path with PATH_TO_MISP
sudo sed -i -e '$i \sudo -u apache /var/www/MISP/venv/bin/misp-modules -l 127.0.0.1 -s &\n' /etc/rc.local
```

{!generic/misp-dashboard-centos.md!}

{!generic/MISP_CAKE_init.md!}

{!generic/INSTALL.done.md!}

{!generic/recommended.actions.md!}

{!generic/hardening.md!}
