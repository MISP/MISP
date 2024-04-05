# INSTALLATION INSTRUCTIONS for RHEL 7.x and CentOS 7.x
-------------------------

### -2/ RHEL7/CentOS7 - status
-------------------------
!!! notice
    Tested fully working without SELinux by [@SteveClement](https://twitter.com/SteveClement) on 20210401
    TODO: Fix SELinux permissions, *pull-requests welcome*.

{% include_relative generic/manual-install-notes.md %}

!!! notice
    If the next line is `[!generic/community.md!]()` [click here](https://misp.github.io/MISP/INSTALL.rhel7).

{% include_relative generic/community.md %}

### 0/ Overview and Assumptions

{% include_relative generic/rhelVScentos.md %}

!!! warning
    The core MISP team cannot easily verify if this guide is working or not. Please help us in keeping it up to date and accurate.
    Thus we also have difficulties in supporting RHEL issues but will do a best effort on a similar yet slightly different setup.

!!! notice
    Maintenance for CentOS 7 will end on: June 30th, 2024 [Source[0]](https://wiki.centos.org/About/Product) [Source[1]](https://linuxlifecycle.com/)
    CentOS 7-1908 [NetInstallURL](http://mirror.centos.org/centos/7/os/x86_64/)

{% include_relative generic/manual-install-notes.md %}

This document details the steps to install MISP on Red Hat Enterprise Linux 7.x (RHEL 7.x) and CentOS 7.x.
This is a joint RHEL/CentOS install guide. The authors tried to make it contextually evident what applies to which flavor.

The following assumptions with regard to this installation have been made.

- A valid support agreement allowing the system to register to the Red Hat Customer Portal and receive updates
- The ability to enable additional RPM repositories, specifically the EPEL and Software Collections (SCL) repos
- This system will have direct or proxy access to the Internet for updates. Or connected to a Red Hat Satellite Server
- This document will bootstrap a MISP instance running over HTTPS. A full test of all features have yet to be done. [The following GitHub issue](https://github.com/MISP/MISP/issues/4084) details some shortcomings.

{% include_relative generic/globalVariables.md %}

!!! note
    For fresh installs the following tips might be handy.<br />
    Allow ssh to pass the firewall on the CLI
    ```bash
    firewall-cmd --zone=public --add-port=22/tcp --permanent
    firewall-cmd --reload
    ```
    <br />
    To quickly make sure if NetworkManager handles your network interface on boot, check in the following location:
    ```
    /etc/sysconfig/network-scripts/ifcfg-*
    ```

### 1/ OS Install and additional repositories

## 1.1/ Complete a minimal RHEL/CentOS installation, configure IP address to connect automatically.

## 1.2/ Configure system hostname (if not done during install)
```bash
sudo hostnamectl set-hostname misp.local # Your choice, in a production environment, it's best to use a FQDN
```

## 1.3/ **[RHEL]** Register the system for updates with Red Hat Subscription Manager
```bash
# <snippet-begin 0_RHEL_register.sh>
registerRHEL () {
  sudo subscription-manager register --auto-attach # register your system to an account and attach to a current subscription
}
# <snippet-end 0_RHEL_register.sh>
```

## 1.4/ **[RHEL]** Enable the optional, extras and Software Collections (SCL) repos
```bash
# <snippet-begin 0_RHEL7_SCL.sh>
enableReposRHEL7 () {
  sudo subscription-manager refresh
  sudo subscription-manager repos --enable rhel-7-server-optional-rpms
  sudo subscription-manager repos --enable rhel-7-server-extras-rpms
}
# <snippet-end 0_RHEL7_SCL.sh>
```

## 1.4c/ **[CentOS]** Enable EPEL for additional dependencies
```bash
# <snippet-begin 0_CentOS_EPEL.sh>
centosEPEL () {
  # We need some packages from the Extra Packages for Enterprise Linux repository
  sudo yum install dnf -y
  sudo dnf install epel-release -y

  # Since MISP 2.4 PHP 5.5 is a minimal requirement, so we need a newer version than CentOS base provides
  # Software Collections is a way do to this, see https://wiki.centos.org/AdditionalResources/Repositories/SCL
  sudo dnf install centos-release-scl -y
  sudo dnf install yum-utils -y
  sudo dnf install http://rpms.remirepo.net/enterprise/remi-release-7.rpm -y
  sudo yum-config-manager --enable remi-php74
}
# <snippet-end 0_CentOS_EPEL.sh>
```

## 1.5a/ Install the deltarpm package to help reduce download size when installing updates (optional)
```bash
sudo dnf install deltarpm -y
```

## 1.5.b/ Install vim (optional)
```bash
# Because (neo)vim is just so practical
sudo dnf install neovim -y
# For RHEL, it's vim and after enabling epel neovim is available too
```

## 1.5.c/ Install ntpdate (optional)
```bash
# In case you time is wrong, this will fix it.
sudo dnf install ntpdate -y
sudo ntpdate pool.ntp.org
```

## 1.5/ Update the system and reboot
```bash
# <snippet-begin 0_yum-update.sh>
yumUpdate () {
  sudo dnf update -y
}
# <snippet-end 0_yum-update.sh>
```

## 1.6/ **[RHEL]** Install the EPEL and remi repo
```bash
# <snippet-begin 0_RHEL7_EPEL.sh>
enableEPEL () {
  sudo yum install dnf -y
  sudo dnf install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm -y
  sudo dnf install http://rpms.remirepo.net/enterprise/remi-release-7.rpm -y
  sudo dnf install yum-utils policycoreutils-python -y
  sudo yum-config-manager --enable remi-php74
}
# <snippet-end 0_RHEL7_EPEL.sh>
```

### 2/ Dependencies

!!! note
    This guide installs PHP 7.4 from Remi's repo

!!! warning
    [PHP 5.6 and 7.0 aren't supported since December 2018](https://secure.php.net/supported-versions.php). Please update accordingly. In the future only PHP7 will be supported.

## 2.01/ Install some base system dependencies
```bash
# <snippet-begin 0_yumInstallCoreDeps7.sh>
yumInstallCoreDeps7 () {
  # Install the dependencies:
  PHP_BASE="/etc/"
  PHP_INI="/etc/php.ini"
  sudo dnf install gcc git zip unzip \
                   mod_ssl \
                   moreutils \
                   redis \
                   libxslt-devel zlib-devel ssdeep-devel -y

  # Enable and start redis
  sudo systemctl enable --now redis.service

  # Install MariaDB
  sudo dnf install wget -y
  wget https://downloads.mariadb.com/MariaDB/mariadb_repo_setup && chmod +x mariadb_repo_setup && sudo ./mariadb_repo_setup && rm mariadb_repo_setup
  sudo dnf install MariaDB-server -y

  # Install PHP 7.4 from Remi's repo, see https://rpms.remirepo.net/enterprise/7/php74/x86_64/repoview/
  sudo dnf install php php-fpm php-devel \
                   php-mysqlnd \
                   php-mbstring \
                   php-xml \
                   php-bcmath \
                   php-opcache \
                   php-zip \
                   php-pear \
                   php-brotli \
                   php-intl \
                   php-gd -y

  # cake has php baked in, thus we link to it if necessary.
  [[ ! -e "/usr/bin/php" ]] && sudo ln -s /usr/bin/php74 /usr/bin/php

  # Python 3.6 is now available in RHEL 7.7 base
  sudo dnf install python3 python3-devel python3-virtualenv -y

  sudo systemctl enable --now php-fpm.service
}
# <snippet-end 0_yumInstallCoreDeps7.sh>
```

```bash
# <snippet-begin 0_yumInstallHaveged.sh>
installEntropyRHEL () {
  # GPG needs lots of entropy, haveged provides entropy
  # /!\ Only do this if you're not running rngd to provide randomness and your kernel randomness is not sufficient.
  sudo dnf install haveged -y
  sudo systemctl enable --now haveged.service
}
# <snippet-end 0_yumInstallHaveged.sh>
```

### 3/ MISP code
## 3.01/ Download MISP code using git in /var/www/ directory

```bash
# <snippet-begin 1_mispCoreInstall_RHEL7.sh>
installCoreRHEL7 () {
  # Download MISP using git in the $PATH_TO_MISP directory.
  sudo mkdir -p $(dirname $PATH_TO_MISP)
  sudo chown $WWW_USER:$WWW_USER $(dirname $PATH_TO_MISP)
  cd $(dirname $PATH_TO_MISP)
  $SUDO_WWW git clone https://github.com/MISP/MISP.git
  cd $PATH_TO_MISP

  # Fetch submodules
  $SUDO_WWW git submodule sync
  $SUDO_WWW git submodule update --init --recursive
  # Make git ignore filesystem permission differences for submodules
  $SUDO_WWW git submodule foreach --recursive git config core.filemode false
  # Make git ignore filesystem permission differences
  $SUDO_WWW git config core.filemode false

  # Create a python3 virtualenv
  [[ -e $(which virtualenv-3 2>/dev/null) ]] && $SUDO_WWW virtualenv-3 -p python3 $PATH_TO_MISP/venv
  [[ -e $(which virtualenv 2>/dev/null) ]] && $SUDO_WWW virtualenv -p python3 $PATH_TO_MISP/venv
  $SUDO_WWW python3 -m venv $PATH_TO_MISP/venv
  sudo mkdir /usr/share/httpd/.cache
  sudo chown $WWW_USER:$WWW_USER /usr/share/httpd/.cache
  $SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U pip setuptools

  # If you umask is has been changed from the default, it is a good idea to reset it to 0022 before installing python modules
  UMASK=$(umask)
  umask 0022

  # install python-stix dependencies
  $SUDO_WWW $PATH_TO_MISP/venv/bin/pip install ordered-set python-dateutil six weakrefmethod

  # install zmq
  $SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U zmq

  # install redis
  $SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U redis

  # install magic, pydeep, lief
  $SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U python-magic git+https://github.com/kbandla/pydeep.git plyara lief

  # install PyMISP
  cd $PATH_TO_MISP/PyMISP
  $SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U .

  # FIXME: Remove libfaup etc once the egg has the library baked-in
  # BROKEN: This needs to be tested on RHEL/CentOS
  sudo dnf install libcaca-devel cmake3 -y
  cd /tmp
  [[ ! -d "faup" ]] && $SUDO_CMD git clone https://github.com/stricaud/faup.git faup
  [[ ! -d "gtcaca" ]] && $SUDO_CMD git clone https://github.com/stricaud/gtcaca.git gtcaca
  sudo chown -R ${MISP_USER}:${MISP_USER} faup gtcaca
  cd gtcaca
  $SUDO_CMD mkdir -p build
  cd build
  $SUDO_CMD cmake3 .. && $SUDO_CMD make
  sudo make install
  cd ../../faup
  $SUDO_CMD mkdir -p build
  cd build
  $SUDO_CMD cmake3 .. && $SUDO_CMD make
  sudo make install
  sudo ldconfig

  # Enable dependencies detection in the diagnostics page
  # This allows MISP to detect GnuPG, the Python modules' versions and to read the PHP settings.
  echo "env[PATH] = /usr/local/bin:/usr/bin:/bin" |sudo tee -a ${PHP_BASE}/php-fpm.d/www.conf
  sudo sed -i.org -e 's/^;\(clear_env = no\)/\1/' ${PHP_BASE}/php-fpm.d/www.conf
  sudo sed -i.org -e 's/^\(listen =\) \/run\/php-fpm\/www\.sock/\1 127.0.0.1:9000/' ${PHP_BASE}/php-fpm.d/www.conf

  sudo systemctl restart php-fpm.service
  umask $UMASK
}
# <snippet-end 1_mispCoreInstall_RHEL7.sh>
```

### 4/ CakePHP
## 4.01/ Install CakeResque along with its dependencies if you intend to use the built in background jobs

!!! notice
    CakePHP is now included as a submodule of MISP and has been fetch by a previous step.

```bash
# <snippet-begin 1_installCake_RHEL.sh>
installCake_RHEL ()
{
  sudo chown -R $WWW_USER:$WWW_USER $PATH_TO_MISP
  sudo mkdir /usr/share/httpd/.composer
  sudo chown $WWW_USER:$WWW_USER /usr/share/httpd/.composer
  cd $PATH_TO_MISP/app
  $SUDO_WWW php composer.phar install

  sudo dnf install php-pecl-redis php-pecl-ssdeep php-pecl-gnupg -y

  sudo systemctl restart php-fpm.service

  # If you have not yet set a timezone in php.ini
  echo 'date.timezone = "Asia/Tokyo"' |sudo tee /etc/php-fpm.d/timezone.ini
  sudo ln -s ../php-fpm.d/timezone.ini /etc/php.d/99-timezone.ini

  # Recommended: Change some PHP settings in /etc/php.ini
  # max_execution_time = 300
  # memory_limit = 2048M
  # upload_max_filesize = 50M
  # post_max_size = 50M
  for key in upload_max_filesize post_max_size max_execution_time max_input_time memory_limit
  do
      sudo sed -i "s/^\($key\).*/\1 = $(eval echo \${$key})/" $PHP_INI
  done
  sudo sed -i "s/^\(session.sid_length\).*/\1 = $(eval echo \${session0sid_length})/" $PHP_INI
  sudo sed -i "s/^\(session.use_strict_mode\).*/\1 = $(eval echo \${session0use_strict_mode})/" $PHP_INI
  sudo systemctl restart php-fpm.service

  # To use the scheduler worker for scheduled tasks, do the following:
  sudo cp -fa $PATH_TO_MISP/INSTALL/setup/config.php $PATH_TO_MISP/app/Plugin/CakeResque/Config/config.php
}
# <snippet-end 1_installCake_RHEL.sh>
```

### 5/ Set file permissions
```bash
# <snippet-begin 2_permissions_RHEL7.sh>
# Main function to fix permissions to something sane
permissions_RHEL7 () {
  sudo chown -R $WWW_USER:$WWW_USER $PATH_TO_MISP
  ## ? chown -R root:$WWW_USER $PATH_TO_MISP
  sudo find $PATH_TO_MISP -type d -exec chmod g=rx {} \;
  sudo chmod -R g+r,o= $PATH_TO_MISP
  ## **Note :** For updates through the web interface to work, apache must own the $PATH_TO_MISP folder and its subfolders as shown above, which can lead to security issues. If you do not require updates through the web interface to work, you can use the following more restrictive permissions :
  sudo chmod -R 750 $PATH_TO_MISP
  sudo chmod -R g+xws $PATH_TO_MISP/app/tmp
  sudo chmod -R g+ws $PATH_TO_MISP/app/files
  sudo chmod -R g+ws $PATH_TO_MISP/app/files/scripts/tmp
  sudo chmod -R g+rw $PATH_TO_MISP/venv
  sudo chmod -R g+rw $PATH_TO_MISP/.git
  sudo chown $WWW_USER:$WWW_USER $PATH_TO_MISP/app/files
  sudo chown $WWW_USER:$WWW_USER $PATH_TO_MISP/app/files/terms
  sudo chown $WWW_USER:$WWW_USER $PATH_TO_MISP/app/files/scripts/tmp
  sudo chown $WWW_USER:$WWW_USER $PATH_TO_MISP/app/Plugin/CakeResque/tmp
  sudo chown -R $WWW_USER:$WWW_USER $PATH_TO_MISP/app/Config
  sudo chown -R $WWW_USER:$WWW_USER $PATH_TO_MISP/app/tmp
  sudo chown -R $WWW_USER:$WWW_USER $PATH_TO_MISP/app/webroot/img/orgs
  sudo chown -R $WWW_USER:$WWW_USER $PATH_TO_MISP/app/webroot/img/custom
}
# <snippet-end 2_permissions_RHEL7.sh>
```

### 6/ Create database and user

## 6.01/ Set database to listen on localhost only
```bash
# <snippet-begin 1_prepareDB_RHEL.sh>
prepareDB_RHEL () {
  sudo systemctl enable --now mariadb.service
  echo [mysqld] |sudo tee /etc/my.cnf.d/bind-address.cnf
  echo bind-address=127.0.0.1 |sudo tee -a /etc/my.cnf.d/bind-address.cnf
  sudo systemctl restart mariadb

  # Kill the anonymous users
  sudo mysql -h $DBHOST -e "DROP USER IF EXISTS ''@'localhost'"
  # Because our hostname varies we'll use some Bash magic here.
  sudo mysql -h $DBHOST -e "DROP USER IF EXISTS ''@'$(hostname)'"
  # Kill off the demo database
  sudo mysql -h $DBHOST -e "DROP DATABASE IF EXISTS test"
  # No root remote logins
  sudo mysql -h $DBHOST -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1')"
  # Make sure that NOBODY can access the server without a password
  sudo mysqladmin -h $DBHOST -u "${DBUSER_ADMIN}" password "${DBPASSWORD_ADMIN}"
  # Make our changes take effect
  sudo mysql -h $DBHOST -u "${DBUSER_ADMIN}" -p"${DBPASSWORD_ADMIN}" -e "FLUSH PRIVILEGES"

  sudo mysql -h $DBHOST -u "${DBUSER_ADMIN}" -p"${DBPASSWORD_ADMIN}" -e "CREATE DATABASE ${DBNAME};"
  sudo mysql -h $DBHOST -u "${DBUSER_ADMIN}" -p"${DBPASSWORD_ADMIN}" -e "CREATE USER '${DBUSER_MISP}'@'localhost' IDENTIFIED BY '${DBPASSWORD_MISP}';"
  sudo mysql -h $DBHOST -u "${DBUSER_ADMIN}" -p"${DBPASSWORD_ADMIN}" -e "GRANT USAGE ON *.* to '${DBUSER_MISP}'@'localhost';"
  sudo mysql -h $DBHOST -u "${DBUSER_ADMIN}" -p"${DBPASSWORD_ADMIN}" -e "GRANT ALL PRIVILEGES on ${DBNAME}.* to '${DBUSER_MISP}'@'localhost';"
  sudo mysql -h $DBHOST -u "${DBUSER_ADMIN}" -p"${DBPASSWORD_ADMIN}" -e "FLUSH PRIVILEGES;"
  # Import the empty MISP database from MYSQL.sql
  ${SUDO_WWW} cat ${PATH_TO_MISP}/INSTALL/MYSQL.sql | mysql -h $DBHOST -u "${DBUSER_MISP}" -p"${DBPASSWORD_MISP}" ${DBNAME}
}
# <snippet-end 1_prepareDB_RHEL.sh>
```

### 7/ Apache Configuration

!!! notice
    SELinux note, to check if it is running:
    ```bash
    $ sestatus
    SELinux status:                 disabled
    ```
    If it is disabled, you can ignore the **chcon/setsebool/semanage/checkmodule/semodule*** commands.

```bash
# <snippet-begin 1_apacheConfig_RHEL7.sh>
apacheConfig_RHEL7 () {
  # Now configure your apache server with the DocumentRoot $PATH_TO_MISP/app/webroot/
  # A sample vhost can be found in $PATH_TO_MISP/INSTALL/apache.misp.centos7

  sudo cp $PATH_TO_MISP/INSTALL/apache.misp.centos7.ssl /etc/httpd/conf.d/misp.ssl.conf
  #sudo sed -i "s/SetHandler/\#SetHandler/g" /etc/httpd/conf.d/misp.ssl.conf
  sudo rm /etc/httpd/conf.d/ssl.conf
  sudo chmod 644 /etc/httpd/conf.d/misp.ssl.conf
  if ! grep -x "Listen 443" /etc/httpd/conf/httpd.conf; then
  sudo sed -i '/Listen 80/a Listen 443' /etc/httpd/conf/httpd.conf
  fi

  # If a valid SSL certificate is not already created for the server, create a self-signed certificate:
  echo "The Common Name used below will be: ${OPENSSL_CN}"
  # This will take a rather long time, be ready. (13min on a VM, 8GB Ram, 1 core)
  if [[ ! -e "/etc/pki/tls/certs/dhparam.pem" ]]; then
    sudo openssl dhparam -out /etc/pki/tls/certs/dhparam.pem 4096
  fi
  sudo openssl genrsa -des3 -passout pass:xxxx -out /tmp/misp.local.key 4096
  sudo openssl rsa -passin pass:xxxx -in /tmp/misp.local.key -out /etc/pki/tls/private/misp.local.key
  sudo rm /tmp/misp.local.key
  sudo openssl req -new -subj "/C=${OPENSSL_C}/ST=${OPENSSL_ST}/L=${OPENSSL_L}/O=${OPENSSL_O}/OU=${OPENSSL_OU}/CN=${OPENSSL_CN}/emailAddress=${OPENSSL_EMAILADDRESS}" -key /etc/pki/tls/private/misp.local.key -out /etc/pki/tls/certs/misp.local.csr
  sudo openssl x509 -req -days 365 -in /etc/pki/tls/certs/misp.local.csr -signkey /etc/pki/tls/private/misp.local.key -out /etc/pki/tls/certs/misp.local.crt
  sudo ln -s /etc/pki/tls/certs/misp.local.csr /etc/pki/tls/certs/misp-chain.crt
  cat /etc/pki/tls/certs/dhparam.pem |sudo tee -a /etc/pki/tls/certs/misp.local.crt

  sudo systemctl restart httpd.service

  # Since SELinux is enabled, we need to allow httpd to write to certain directories
  sudo chcon -t httpd_sys_rw_content_t $PATH_TO_MISP/app/files
  sudo chcon -t httpd_sys_rw_content_t $PATH_TO_MISP/app/files/terms
  sudo chcon -t httpd_sys_rw_content_t $PATH_TO_MISP/app/files/scripts/tmp
  sudo chcon -t httpd_sys_rw_content_t $PATH_TO_MISP/app/Plugin/CakeResque/tmp
  sudo chcon -t httpd_sys_script_exec_t $PATH_TO_MISP/app/Console/cake
  sudo sh -c "chcon -t httpd_sys_script_exec_t $PATH_TO_MISP/app/Console/worker/*.sh"
  sudo sh -c "chcon -t httpd_sys_script_exec_t $PATH_TO_MISP/app/files/scripts/*.py"
  sudo sh -c "chcon -t httpd_sys_script_exec_t $PATH_TO_MISP/app/files/scripts/*/*.py"
  sudo chcon -t httpd_sys_script_exec_t $PATH_TO_MISP/app/Vendor/pear/crypt_gpg/scripts/crypt-gpg-pinentry
  sudo sh -c "chcon -R -t bin_t $PATH_TO_MISP/venv/bin/*"
  sudo find $PATH_TO_MISP/venv -type f -name "*.so*" -or -name "*.so.*" | xargs sudo chcon -t lib_t
  # Only run these if you want to be able to update MISP from the web interface
  sudo chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/.git
  sudo chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/app/tmp
  sudo chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/app/Lib
  sudo chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/app/Config
  sudo chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/app/webroot/img/orgs
  sudo chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/app/webroot/img/custom
  sudo chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/app/files/scripts/mispzmq
}
# <snippet-end 1_apacheConfig_RHEL7.sh>
```

!!! warning
    Todo: Revise all permissions so update in Web UI works.

```bash
# <snippet-begin 1_firewall_RHEL.sh>
firewall_RHEL () {
  # Allow httpd to connect to the redis server and php-fpm over tcp/ip
  sudo setsebool -P httpd_can_network_connect on

  # Allow httpd to send emails from php
  sudo setsebool -P httpd_can_sendmail on

  # Enable and start the httpd service
  sudo systemctl enable --now httpd.service

  # Open a hole in the iptables firewall
  sudo firewall-cmd --zone=public --add-port=80/tcp --permanent
  sudo firewall-cmd --zone=public --add-port=443/tcp --permanent
  sudo firewall-cmd --reload
}
# <snippet-end 1_firewall_RHEL.sh>
```

### 8/ Log Rotation
## 8.01/ Enable log rotation
MISP saves the stdout and stderr of its workers in $PATH_TO_MISP/app/tmp/logs
To rotate these logs install the supplied logrotate script:

FIXME: The below does not work

```bash
# <snippet-begin 2_logRotation_RHEL.sh>
logRotation_RHEL () {
  # MISP saves the stdout and stderr of its workers in $PATH_TO_MISP/app/tmp/logs
  # To rotate these logs install the supplied logrotate script:

  sudo cp $PATH_TO_MISP/INSTALL/misp.logrotate /etc/logrotate.d/misp
  sudo chmod 0640 /etc/logrotate.d/misp

  # Now make logrotate work under SELinux as well
  # Allow logrotate to modify the log files
  sudo semanage fcontext -a -t httpd_sys_rw_content_t "$PATH_TO_MISP(/.*)?"
  sudo semanage fcontext -a -t httpd_log_t "$PATH_TO_MISP/app/tmp/logs(/.*)?"
  sudo chcon -R -t httpd_log_t $PATH_TO_MISP/app/tmp/logs
  # Impact of the following: ?!?!?!!?111
  ##sudo restorecon -R $PATH_TO_MISP

  # Allow logrotate to read /var/www
  sudo checkmodule -M -m -o /tmp/misplogrotate.mod $PATH_TO_MISP/INSTALL/misplogrotate.te
  sudo semodule_package -o /tmp/misplogrotate.pp -m /tmp/misplogrotate.mod
  sudo semodule -i /tmp/misplogrotate.pp
}
# <snippet-end 2_logRotation_RHEL.sh>
```

### 9/ MISP Configuration

```bash
# <snippet-begin 2_configMISP_RHEL.sh>
configMISP_RHEL () {
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
  sudo chown $WWW_USER:$WWW_USER $PATH_TO_MISP/app/Config/config.php
  sudo chmod 660 $PATH_TO_MISP/app/Config/config.php
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
  sudo chown -R $WWW_USER:$WWW_USER $PATH_TO_MISP/.gnupg
  sudo chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/.gnupg

  # And export the public key to the webroot
  sudo gpg --homedir $PATH_TO_MISP/.gnupg --export --armor $GPG_EMAIL_ADDRESS |sudo tee $PATH_TO_MISP/app/webroot/gpg.asc
  sudo chown $WWW_USER:$WWW_USER $PATH_TO_MISP/app/webroot/gpg.asc

  echo "Admin (root) DB Password: $DBPASSWORD_ADMIN"
  echo "User  (misp) DB Password: $DBPASSWORD_MISP"
}
# <snippet-end 2_configMISP_RHEL.sh>
```

!!! note
    There is a bug that if a passphrase is added MISP will produce an error on the diagnostic page.<br />
    /!\ THIS WANTS TO BE VERIFIED AND LINKED WITH A CORRESPONDING ISSUE.

!!! note
    The email address should match the one set in the config.php configuration file
    Make sure that you use the same settings in the MISP Server Settings tool

## 9.06/ Use MISP background workers

```bash
# <snippet-begin 3_configWorkers_RHEL.sh>
configWorkersRHEL () {
  echo "[Unit]
  Description=MISP background workers
  After=mariadb.service redis.service php-fpm.service

  [Service]
  Type=forking
  User=$WWW_USER
  Group=$WWW_USER
  ExecStart=$PATH_TO_MISP/app/Console/worker/start.sh
  Restart=always
  RestartSec=10

  [Install]
  WantedBy=multi-user.target" |sudo tee /etc/systemd/system/misp-workers.service

  sudo chmod +x $PATH_TO_MISP/app/Console/worker/start.sh
  sudo systemctl daemon-reload

  sudo systemctl enable --now misp-workers.service
}
# <snippet-end 3_configWorkers_RHEL.sh>
```

{% include_relative generic/MISP_CAKE_init.md %}

{% include_relative generic/misp-modules-rhel.md %}

{% include_relative generic/misp-modules-cake.md %}

{% include_relative generic/misp-dashboard-rhel.md %}

{% include_relative generic/misp-dashboard-cake.md %}

{% include_relative generic/INSTALL.done.md %}

{% include_relative generic/recommended.actions.md %}

### 11/ Known Issues
## 11.01/ Workers cannot be started or restarted from the web page
Possible also due to package being installed via SCL, attempting to start workers through the web page will result in error. Worker's can be restarted via the CLI using the following command.
```bash
systemctl restart misp-workers.service
```

!!! note
    No other functions were tested after the conclusion of this install. There may be issue that aren't addressed<br />
    via this guide and will need additional investigation.

{% include_relative generic/hardening.md %}
