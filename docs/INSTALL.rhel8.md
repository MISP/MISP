# INSTALLATION INSTRUCTIONS for RHEL 8.x based distros
-------------------------

### -2/ RHEL8/Rocky8.4/Rocky8.5/Fedora34/Fedora35 - status
-------------------------
!!! notice
    Tested fully working without SELinux by [@SteveClement](https://twitter.com/SteveClement) on 20210702

!!! notice
    TODO: Fix SELinux permissions, *pull-requests welcome*.

{% include_relative generic/manual-install-notes.md %}

!!! notice
    If the next line is `[!generic/community.md!]()` [click here](https://misp.github.io/MISP/INSTALL.rhel8).

{% include_relative generic/community.md %}

### 0/ Overview and Assumptions

!!! warning
    The core MISP team cannot easily verify if this guide is working or not. Please help us in keeping it up to date and accurate.
    Thus we also have difficulties in supporting RHEL issues but will do a best effort on a similar yet slightly different setup.

!!! notice
    Maintenance for CentOS 8 will end on: December 31st, 2021 [Source[0]](https://wiki.centos.org/About/Product) [Source[1]](https://linuxlifecycle.com/)
    Consider using [Rocky Linux](https://rockylinux.org/)
    CentOS 8 [NetInstallURL](http://mirrorlist.centos.org/?release=8&arch=x86_64&repo=BaseOS)

{% include_relative generic/manual-install-notes.md %}

This document details the steps to install MISP on Red Hat Enterprise Linux 8.x (RHEL 8.x) and Rocky Linux 8.x.
This is a joint RHEL/Rocky install guide. The authors tried to make it contextually evident what applies to which flavor.

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

## 1.1/ Complete a minimal RHEL/Rocky installation, configure IP address to connect automatically.

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

## 1.4/ **[RHEL]** Enable the optional repos (obsolete in v8)
```bash
# <snippet-begin 0_RHEL8_SCL.sh>
enableOptionalRHEL8 () {
  sudo subscription-manager refresh

  # The following is needed for -devel repos and ONLY for misp-modules, ignore if not needed
  sudo subscription-manager repos --enable codeready-builder-for-rhel-8-x86_64-rpms
  # Software Collections is available for Red Hat Enterprise Linux 7 and previous supported releases. Starting with Red Hat Enterprise Linux 8, the content traditionally consumed via Software Collections is now part of Application Streams. Please see the Application Streams Life Cycle documentation for that release. Source: https://access.redhat.com/support/policy/updates/rhscl
}
# <snippet-end 0_RHEL8_SCL.sh>
```

## 1.5a/ Install the deltarpm package to help reduce download size when installing updates (optional)
```bash
sudo dnf install drpm -y
```

## 1.5.b/ Install vim (optional)
```bash
# Because (neo)vim is just so practical
sudo dnf install neovim -y || sudo dnf install vim -y || echo "neovim is not in the catalog"
# For RHEL, it's vim and after enabling epel neovim is available too
```

## 1.5.c/ Install ntpdate (optional)
```bash
# In case you time is wrong, this will fix it.
sudo dnf install ntpdate -y || sudo dnf install ntpsec -y || sudo dnf install chrony -y
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

## 1.6/ Install the EPEL and remi repo
```bash
# <snippet-begin 0_EPEL_REMI.sh>
enableEPEL_REMI_8 () {
  sudo dnf install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm -y
  sudo dnf install http://rpms.remirepo.net/enterprise/remi-release-8.rpm -y
  sudo dnf install dnf-utils -y
  sudo dnf module enable php:remi-7.4 -y
  ([[ ${DISTRI} == "centos8stream" ]] || [[ ${DISTRI} == "centos8" ]] || [[ ${DISTRI} == "rocky8.4" ]] || [[ ${DISTRI} == "rocky8.5" ]]) && sudo dnf config-manager --set-enabled powertools
}

enableREMI_fedora () {
  [[ "${DISTRI%??}" == "fedora" ]] && sudo dnf install http://rpms.remirepo.net/fedora/remi-release-${DISTRI:6}.rpm -y
  dnf list installed mod_lua && sudo dnf remove mod_lua -y
  sudo dnf install dnf-utils -y
  sudo dnf module enable php:remi-7.4 -y
}
# <snippet-end 0_EPEL_REMI.sh>
```

### 2/ Dependencies

!!! note
    This guide installs PHP 7.4 from Remi's repo

!!! warning
    [PHP 5.6 and 7.0 aren't supported since December 2018](https://secure.php.net/supported-versions.php). Please update accordingly. In the future only PHP7 will be supported.

## 2.01/ Install some base system dependencies
```bash
# <snippet-begin 0_yumInstallCoreDeps8.sh>
yumInstallCoreDeps8 () {
  # Install the dependencies:
  PHP_BASE="/etc/"
  PHP_INI="/etc/php.ini"
  # If the install group @httpd is not existent, fallback to httpd
  sudo dnf install @httpd -y || sudo dnf install httpd -y
  sudo dnf install gcc git zip unzip \
                   httpd \
                   mod_ssl \
                   moreutils \
                   redis \
                   mariadb \
                   mariadb-server \
                   python3-devel python3-pip python3-virtualenv \
                   python3-policycoreutils \
                   policycoreutils-python-utils \
                   langpacks-en glibc-all-langpacks \
                   libxslt-devel zlib-devel ssdeep-devel -y
  readlink -f /usr/bin/python | grep python3 || sudo alternatives --set python /usr/bin/python3

  # Enable and start redis
  sudo systemctl enable --now redis.service

  # Install PHP 7.4 from Remi's repo, see https://rpms.remirepo.net/enterprise/8/php74/x86_64/repoview/
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

  sudo systemctl enable --now php-fpm.service
}
# <snippet-end 0_yumInstallCoreDeps8.sh>
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
# <snippet-begin 1_mispCoreInstall_RHEL8.sh>
compileLiefRHEL8 () {
  cd $PATH_TO_MISP/app/files/scripts
  $SUDO_WWW git clone --branch master --single-branch https://github.com/lief-project/LIEF.git lief
  # lief might need manual compilation
  sudo dnf groupinstall "Development Tools" -y

  cd $PATH_TO_MISP/app/files/scripts/lief
  $SUDO_WWW git config core.filemode false
  $SUDO_WWW mkdir build
  cd build
  $SUDO_WWW ${CMAKE_BIN} \
    -DLIEF_PYTHON_API=on \
    -DPYTHON_VERSION=3.6 \
    -DPYTHON_EXECUTABLE=$PATH_TO_MISP/venv/bin/python \
    -DLIEF_DOC=off \
    -DCMAKE_BUILD_TYPE=Release \
  ..
  $SUDO_WWW make -j3 pyLIEF

  if [ $? == 2 ]; then
    # In case you get "internal compiler error: Killed (program cc1plus)"
    # You ran out of memory.
    # Create some swap
    TEMP_DIR=$(mktemp -d)
    TEMP_SWAP=${TEMP_DIR}/swap.img
    sudo dd if=/dev/zero of=${TEMP_SWAP} bs=1024k count=4000
    sudo mkswap ${TEMP_SWAP}
    sudo swapon ${TEMP_SWAP}
    # And compile again
    ${SUDO_WWW} make -j3 pyLIEF
    sudo swapoff ${TEMP_SWAP}
    sudo rm -r ${TEMP_DIR}
  fi

  # The following adds a PYTHONPATH to where the pyLIEF module has been compiled
  echo /var/www/MISP/app/files/scripts/lief/build/api/python |$SUDO_WWW tee /var/www/MISP/venv/lib/python3.6/site-packages/lief.pth
  ([[ "${DISTRI}" == "fedora33" ]] || [[ ${DISTRI} == 'fedora34' ]]) && (echo /var/www/MISP/app/files/scripts/lief/build/api/python |$SUDO_WWW tee /var/www/MISP/venv/lib/python3.9/site-packages/lief.pth)
  [[ "${DISTRI}" == "fedora35" ]] && (echo /var/www/MISP/app/files/scripts/lief/build/api/python |$SUDO_WWW tee /var/www/MISP/venv/lib/python3.10/site-packages/lief.pth)
$SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U python-magic plyara
}

installCoreRHEL8 () {
  # Download MISP using git in the $PATH_TO_MISP directory.
  sudo mkdir -p $(dirname $PATH_TO_MISP)
  sudo chown $WWW_USER:$WWW_USER $(dirname $PATH_TO_MISP)
  cd $(dirname $PATH_TO_MISP)
  $SUDO_WWW git clone https://github.com/MISP/MISP.git
  cd $PATH_TO_MISP

  # Fetch submodules
  $SUDO_WWW git submodule update --init --recursive
  # Make git ignore filesystem permission differences for submodules
  $SUDO_WWW git submodule foreach --recursive git config core.filemode false
  # Make git ignore filesystem permission differences
  $SUDO_WWW git config core.filemode false

  # Create a python3 virtualenv
  [[ -e $(which virtualenv-3 2>/dev/null) ]] && $SUDO_WWW virtualenv-3 -p python3 $PATH_TO_MISP/venv
  [[ -e $(which virtualenv 2>/dev/null) ]] && $SUDO_WWW virtualenv -p python3 $PATH_TO_MISP/venv
  [[ ! -e ${PATH_TO_MISP}/venv ]] && ${SUDO_WWW} python -m venv ${PATH_TO_MISP}/venv
  sudo mkdir /usr/share/httpd/.cache
  sudo chown $WWW_USER:$WWW_USER /usr/share/httpd/.cache
  $SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U pip setuptools

  # If you umask is has been changed from the default, it is a good idea to reset it to 0022 before installing python modules
  ([[ ${DISTRI} == 'fedora33' ]] || [[ ${DISTRI} == 'fedora34' ]] || [[ ${DISTRI} == 'fedora35' ]] || [[ ${DISTRI} == 'rhel8.3' ]] || [[ ${DISTRI} == 'rhel8.4' ]] || [[ ${DISTRI} == 'rhel8.5' ]]) && sudo dnf install cmake3 -y && CMAKE_BIN='cmake3'
  ([[ ${DISTRI} == 'centos8stream' ]] || [[ ${DISTRI} == 'centos8' ]] || [[ ${DISTRI} == 'rocky8.4' ]] || [[ ${DISTRI} == 'rocky8.5' ]]) && sudo dnf install cmake -y && CMAKE_BIN='cmake'

  UMASK=$(umask)
  umask 0022

  # install python-stix dependencies
  $SUDO_WWW $PATH_TO_MISP/venv/bin/pip install ordered-set python-dateutil six weakrefmethod
  debug "Install misp-stix"
  ${SUDO_WWW} ${PATH_TO_MISP}/venv/bin/pip install ${PATH_TO_MISP}/app/files/scripts/misp-stix

  # install zmq, redis
  $SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U zmq redis

  # install magic, pydeep
  $SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U python-magic git+https://github.com/kbandla/pydeep.git plyara

  # install lief
  $SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U lief || compileLiefRHEL8

  # install PyMISP
  cd $PATH_TO_MISP/PyMISP
  $SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U .

  # FIXME: Remove libfaup etc once the egg has the library baked-in
  # BROKEN: This needs to be tested on RHEL/Rocky
  sudo dnf install libcaca-devel -y
  cd /tmp
  [[ ! -d "faup" ]] && $SUDO_CMD git clone https://github.com/stricaud/faup.git faup
  [[ ! -d "gtcaca" ]] && $SUDO_CMD git clone https://github.com/stricaud/gtcaca.git gtcaca
  sudo chown -R ${MISP_USER}:${MISP_USER} faup gtcaca
  cd gtcaca
  $SUDO_CMD mkdir -p build
  cd build
  $SUDO_CMD ${CMAKE_BIN} .. && $SUDO_CMD make
  sudo make install
  cd ../../faup
  $SUDO_CMD mkdir -p build
  cd build
  $SUDO_CMD ${CMAKE_BIN} .. && $SUDO_CMD make
  sudo make install
  sudo ldconfig

  # Enable dependencies detection in the diagnostics page
  # This allows MISP to detect GnuPG, the Python modules' versions and to read the PHP settings.
  echo "env[PATH] = /usr/local/bin:/usr/bin:/bin" |sudo tee -a ${PHP_BASE}/php-fpm.d/www.conf
  sudo sed -i.org -e 's/^;\(clear_env = no\)/\1/' ${PHP_BASE}/php-fpm.d/www.conf
  sudo sed -i.org -e 's/^\(listen =\) \/run\/php-fpm\/www\.sock/\1 127.0.0.1:9000/' ${PHP_BASE}/php-fpm.d/www.conf

  umask $UMASK

  sudo systemctl restart php-fpm.service
}
# <snippet-end 1_mispCoreInstall_RHEL8.sh>
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
  $SUDO_WWW php composer.phar install --no-dev

  sudo dnf install php-pecl-redis php-pecl-ssdeep php-pecl-gnupg -y

  sudo systemctl restart php-fpm.service

  # If you have not yet set a timezone in php.ini
  echo 'date.timezone = "Asia/Tokyo"' |sudo tee /etc/php-fpm.d/timezone.ini
  sudo ln -s ../php-fpm.d/timezone.ini /etc/php.d/99-timezone.ini

  # Recommended: Change some PHP settings in /etc/opt/remi/php74/php.ini
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
# <snippet-begin 2_permissions_RHEL8.sh>
# Main function to fix permissions to something sane
permissions_RHEL8 () {
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
# <snippet-end 2_permissions_RHEL8.sh>
```

### 6/ Create database and user

## 6.01/ Set database to listen on localhost only
```bash
# <snippet-begin 1_prepareDB_RHEL.sh>
prepareDB_RHEL () {
  # Enable, start and secure your mysql database server
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
# <snippet-begin 1_apacheConfig_RHEL8.sh>
apacheConfig_RHEL8 () {
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
  [[ -e ${PATH_TO_MISP}/app/files/scripts/lief/build/api/python/lief.so ]] && sudo chcon -t httpd_sys_script_exec_t $PATH_TO_MISP/app/files/scripts/lief/build/api/python/lief.so
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
# <snippet-end 1_apacheConfig_RHEL8.sh>
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
  sudo chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/app/tmp/logs
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

### 11/ LIEF Installation
*lief* is required for the Advanced Attachment Handler and requires manual compilation

The installation is explained in section **[3.01](https://misp.github.io/MISP/INSTALL.rhel8/#301-download-misp-code-using-git-in-varwww-directory)**

### 12/ Known Issues
## 12.01/ Workers cannot be started or restarted from the web page
Possible also due to package being installed via SCL, attempting to start workers through the web page will result in error. Worker's can be restarted via the CLI using the following command.
```bash
systemctl restart misp-workers.service
```

!!! note
    No other functions were tested after the conclusion of this install. There may be issue that aren't addressed<br />
    via this guide and will need additional investigation.

{% include_relative generic/hardening.md %}
