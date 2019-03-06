# INSTALLATION INSTRUCTIONS for RHEL 7.x
-------------------------

## 0/ Overview and Assumptions

{!generic/rhelVScentos.md!}

!!! warning
    The core MISP team cannot verify if this guide is working or not. Please help us in keeping it up to date and accurate.
    Thus we also have difficulties in supporting RHEL issues but will do a best effort on a similar yet slightly different setup.

This document details the steps to install MISP on Red Hat Enterprise Linux 7.x (RHEL 7.x). At time of this writing it
was tested on version 7.6.

The following assumptions with regard to this installation have been made.

### 0.1/ A valid support agreement allowing the system to register to the Red Hat Customer Portal and receive updates
### 0.2/ The ability to enable additional RPM repositories, specifically the EPEL and Software Collections (SCL) repos
### 0.3/ This system will have direct or proxy access to the Internet for updates. Or connected to a Red Hat Satellite Server
### 0.4/ This document is to get a MISP instance up and running over HTTP. I haven't done a full test of all features

# 1/ OS Install and additional repositories

## 1.1/ Complete a minimal RHEL installation, configure IP address to connect automatically.

## 1.2/ Configure system hostname
```bash
sudo hostnamectl set-hostname misp # Your choice, in a production environment, it's best to use a FQDN
```

## 1.3/ Register the system for updates with Red Hat Subscription Manager
```bash
sudo subscription-manager register --auto-attach # register your system to an account and attach to a current subscription
```

## 1.4/ Enable the optional, extras and Software Collections (SCL) repos
```bash
sudo subscription-manager refresh 
sudo subscription-manager repos --enable rhel-7-server-optional-rpms
sudo subscription-manager repos --enable rhel-7-server-extras-rpms
sudo subscription-manager repos --enable rhel-server-rhscl-7-rpms
```

### 1.5a/ OPTIONAL: Install the deltarpm package to help reduce download size when installing updates
```bash
sudo yum install deltarpm -y
```

## 1.5/ Update the system and reboot
```bash
yum update -y
```

!!! note
    As time of writing performing a yum update results in the rhel-7-server-rt-beta-rpms being forbidden.<br />
    The repo can be disabled using the following command
    ```bash
    subscription-manager repos --disable rhel-7-server-rt-beta-rpms
    ```

## 1.6/ Install the EPEL repo
```bash
yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm -y
```

# 2/ Install Dependencies
Once the system is installed and updated, the following steps can be performed as root

## 2.01/ Install some base system dependencies
```bash
yum install gcc git httpd zip python-devel libxslt-devel zlib-devel python-pip ssdeep-devel
```

## 2.02/ Install MariaDB 10.2 from SCL
```bash
yum install rh-mariadb102
```

## 2.03/ Start the MariaDB service and enable it to start on boot
```bash
systemctl enable --now rh-mariadb102-mariadb.service
```

!!! note
    MISP 2.4 requires PHP 5.6 as a minimum, so we need a higher version than base RHEL provides.<br />
    This guide installs PHP 7.2 from SCL

!!! warning
    [PHP 5.6 and 7.0 aren't supported since December 2018](https://secure.php.net/supported-versions.php). Please update accordingly. In the future only PHP7 will be supported.

## 2.04/ Install PHP 7.2 from SCL
```bash
yum install rh-php72 rh-php72-php-fpm rh-php72-php-devel rh-php72-php-mysqlnd rh-php72-php-mbstring rh-php72-php-xml rh-php72-php-bcmath rh-php72-php-opcache
```

!!! note
    If we want to use httpd from RHEL base we can use the rh-php72-php-fpm service instead

## 2.05/ Start the PHP FPM service and enable to start on boot
```bash
systemctl enable --now rh-php72-php-fpm.service
```

## 2.06/ Install redis 3.2 from SCL
```bash
yum install rh-redis32
```

## 2.07/ Start redis service and enable to start on boot
```bash
systemctl enable --now rh-redis32-redis.service
```

## 2.08/ Secure the MariaDB installation
```bash
scl enable rh-mariadb102 'mysql_secure_installation'
```

## 2.09/ Optional: install haveged and enable to start on boot to provide entropy for GPG
```bash
yum install haveged
systemctl enable --now haveged
```
Only do this if you're not running rngd to provide randomness and your kernel randomness is not sufficient.

## 2.10/ Install Python 3.6 from SCL
```bash
yum install rh-python36
```

## 2.11/ Install Git 2.18 from SCL
```bash
yum install rh-git218
```

# 3/ MISP Download
## 3.01/ Download MISP code using git in /var/www/ directory
```bash
cd /var/www
git clone https://github.com/MISP/MISP.git
cd MISP
git checkout tags/$(git describe --tags `git rev-list --tags --max-count=1`)
# if the last shortcut doesn't work, specify the latest version manually
# example: git checkout tags/v2.4.XY
# the message regarding a "detached HEAD state" is expected behaviour
# (you only have to create a new branch, if you want to change stuff and do a pull request for example)
git submodule update --init --recursive
# Make git ignore filesystem permission differences for submodules
git submodule foreach --recursive git config core.filemode false
```

## 3.02/ Make git ignore filesystem permission differences
```bash
git config core.filemode false
```

## 3.03/ Install Mitre's STIX, STIX2 and their dependencies by running the following commands
```bash
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
cd /var/www/MISP/cti-python-stix2
scl enable rh-python36 'python3 setup.py install'
```


## 3.04/ Install mixbox to accommodate the new STIX dependencies
```bash
cd /var/www/MISP/app/files/scripts/
git clone https://github.com/CybOXProject/mixbox.git
cd /var/www/MISP/app/files/scripts/mixbox
git config core.filemode false
scl enable rh-python36 'python3 setup.py install'
umask $UMASK
```

## 3.05/ Enable python3 for php-fpm
```bash
echo 'source scl_source enable rh-python36' >> /etc/opt/rh/rh-php72/sysconfig/php-fpm
sed -i.org -e 's/^;\(clear_env = no\)/\1/' /etc/opt/rh/rh-php72/php-fpm.d/www.conf
systemctl restart rh-php72-php-fpm.service
```

## 3.06/ Enable dependencies detection in the diagnostics page
Add the following content to `/etc/opt/rh/rh-php72/php-fpm.d/www.conf` :
```
env[PATH]=/opt/rh/rh-git218/root/usr/bin:/opt/rh/rh-redis32/root/usr/bin:/opt/rh/rh-python36/root/usr/bin:/opt/rh/rh-php72/root/usr/bin:/usr/local/bin:/usr/bin:/bin
env[LD_LIBRARY_PATH]=/opt/rh/httpd24/root/usr/lib64/
```
Then run `systemctl restart rh-php72-php-fpm.service`.
This allows MISP to detect GnuPG, the Python modules' versions and to read the PHP settings. The LD_LIBRARY_PATH setting is needed for rh-git218 to work, one might think to install httpd24 and not just httpd ...

# 4/ CakePHP
## 4.01/ Install CakeResque along with its dependencies if you intend to use the built in background jobs
```bash
cd /var/www/MISP/app
php composer.phar require kamisama/cake-resque:4.1.2
php composer.phar config vendor-dir Vendor
php composer.phar install
```

## 4.02/ Install and configure php redis connector through pecl
```bash
scl enable rh-php72 'pecl install redis'
echo "extension=redis.so" > /etc/opt/rh/rh-php72/php-fpm.d/redis.ini
ln -s /etc/opt/rh/rh-php72/php-fpm.d/redis.ini /etc/opt/rh/rh-php72/php.d/99-redis.ini
systemctl restart rh-php72-php-fpm.service
```

## 4.03/ Set a timezone in php.ini
```bash
echo 'date.timezone = "Australia/Sydney"' > /etc/opt/rh/rh-php72/php-fpm.d/timezone.ini
ln -s /etc/opt/rh/rh-php72/php-fpm.d/timezone.ini /etc/opt/rh/rh-php72/php.d/99-timezone.ini
```

## 4.04/ To use the scheduler worker for scheduled tasks, do the following:
```bash
cp -fa /var/www/MISP/INSTALL/setup/config.php /var/www/MISP/app/Plugin/CakeResque/Config/config.php
```

## 4.05/ Install Crypt_GPG and Console_CommandLine
```bash
sudo -H -u apache scl enable rh-php72 'pear install ${PATH_TO_MISP}/INSTALL/dependencies/Console_CommandLine/package.xml'
sudo -H -u apache scl enable rh-php72 'pear install ${PATH_TO_MISP}/INSTALL/dependencies/Crypt_GPG/package.xml'
```

# 5/ Set file permissions
```bash
chown -R apache:apache /var/www/MISP
find /var/www/MISP -type d -exec chmod g=rx {} \;
chmod -R g+r,o= /var/www/MISP
```
**Note :** For updates through the web interface to work, apache must own the /var/www/MISP folder and its subfolders as shown above, which can lead to security issues. If you do not require updates through the web interface to work, you can use the following more restrictive permissions :
```bash
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
```

# 6/ Create database and user
## 6.01/ Set database to listen on localhost only
```bash
echo [mysqld] > /etc/opt/rh/rh-mariadb102/my.cnf.d/bind-address.cnf
echo bind-address=127.0.0.1 >> /etc/opt/rh/rh-mariadb102/my.cnf.d/bind-address.cnf
systemctl restart rh-mariadb102-mariadb
```

## 6.02/ Start a MariaDB shell and create the database
```bash
scl enable rh-mariadb102 'mysql -u root -p'
```

```
MariaDB [(none)]> create database misp;
MariaDB [(none)]> grant usage on *.* to misp@localhost identified by 'XXXXXXXXX';
MariaDB [(none)]> grant all privileges on misp.* to misp@localhost ;
MariaDB [(none)]> exit
```

## 6.03/ Import the empty MySQL database from MYSQL.sql
```bash
cd /var/www/MISP
mysql -u misp -p misp < INSTALL/MYSQL.sql
```

# 7/ Apache Configuration
## 7.01/ Copy a sample vhost config to Apache configuration directory
```bash
cp /var/www/MISP/INSTALL/apache.misp.centos7 /etc/httpd/conf.d/misp.conf
```

## 7.02/ Since SELinux is enabled, we need to allow httpd to write to certain directories
```bash
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/MISP(/.*)?"
restorecon -R /var/www/MISP/
```
We're providing write access to the whole MISP tree, otherwise updates via the web interface won't work.

## 7.03/ Allow httpd to connect to the redis server and php-fpm over tcp/ip
```bash
setsebool -P httpd_can_network_connect on
```

## 7.04/ Enable and start the httpd service
```bash
systemctl enable --now httpd.service
```

## 7.05/ Open a hole in the firewalld service
```bash
firewall-cmd --zone=public --add-port=80/tcp --permanent
firewall-cmd --reload
```

!!! warning
    We seriously recommend using only HTTPS / SSL !
    Add SSL support by running: yum install mod_ssl
    Check out the apache.misp.ssl file for an example

# 8/ Log Rotation
## 8.01/ Enable log rotation
MISP saves the stdout and stderr of it's workers in /var/www/MISP/app/tmp/logs
To rotate these logs install the supplied logrotate script:
```
cp INSTALL/misp.logrotate /etc/logrotate.d/misp
chmod 0640 /etc/logrotate.d/misp
```

## 8.02/ Allow logrotate to read /var/www
```bash
checkmodule -M -m -o /tmp/misplogrotate.mod INSTALL/misplogrotate.te
semodule_package -o /tmp/misplogrotate.pp -m /tmp/misplogrotate.mod
semodule -i /tmp/misplogrotate.pp
```

# 9/ MISP Configuration
## 9.01/ There are 4 sample configuration files in /var/www/MISP/app/Config that need to be copied
```bash
cd /var/www/MISP/app/Config
cp -a bootstrap.default.php bootstrap.php
cp -a database.default.php database.php
cp -a core.default.php core.php
cp -a config.default.php config.php
```

## 9.02/ Configure the fields in the newly created files
```bash
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
```

## 9.03/ If you want to be able to change configuration parameters from the webinterface:
Handled by 7.02

## 9.04/ Generate an encryption key
```bash
gpg --gen-key
mv ~/.gnupg /var/www/MISP/
restorecon -R /var/www/MISP
```

!!! note
    There is a bug that if a passphrase is added MISP will produce an error on the diagnostic page.<br />
    /!\ THIS WANTS TO BE VERIFIED AND LINKED WITH A CORRESPONDING ISSUE.

!!! note
    The email address should match the one set in the config.php configuration file
    Make sure that you use the same settings in the MISP Server Settings tool

## 9.05/ Export the public key to the webroot
```bash
sudo -u apache gpg --homedir /var/www/MISP/.gnupg --export --armor YOUR-EMAIL > /var/www/MISP/app/webroot/gpg.asc
```

## 9.06/ Use MISP's background workers
### 9.06a/ Create a systemd unit for the workers
Create the following file :
`/etc/systemd/system/misp-workers.service`
```
[Unit]
Description=MISP's background workers
After=rh-mariadb102-mariadb.service rh-redis32-redis.service rh-php72-php-fpm.service

[Service]
Type=forking
User=apache
Group=apache
ExecStart=/usr/bin/scl enable rh-php72 rh-redis32 rh-mariadb102 /var/www/MISP/app/Console/worker/start.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```
Make the workers' script executable and reload the systemd units :
```bash
chmod +x /var/www/MISP/app/Console/worker/start.sh
systemctl daemon-reload
```

### 9.06b/ Start the workers and enable them on boot
```bash
systemctl enable --now misp-workers.service
```

{!generic/INSTALL.done.md!}

{!generic/recommended.actions.md!}

# 10/ Post Install
## 10.01/ Change php.ini settings to suggested limits from diagnostic page.
```bash
# Edit /etc/opt/rh/rh-php72/php.ini and set the following settings
max_execution_time = 300
memory_limit = 512M
upload_max_filesize = 50M
post_max_size = 50M
```

## 10.02/ Restart rh-php72 for settings to take effect
```bash
systemctl restart rh-php72-php-fpm
```

## 10.03/ Install pydeep and pymisp
```bash
scl enable rh-python36 'python3 -m pip install pymisp git+https://github.com/kbandla/pydeep.git'
```

# 11/ LIEF Installation
*lief* is required for the Advanced Attachment Handler and requires manual compilation

## 11.01/ Install cmake3 devtoolset-7 from SCL
```bash
yum install devtoolset-7 cmake3
```

## 11.02/ Create the directory and download the source code
```bash
cd /var/www/MISP/app/files/scripts
git clone --branch master --single-branch https://github.com/lief-project/LIEF.git lief
```

## 11.03/ Compile lief and install it
```bash
cd /var/www/MISP/app/files/scripts/lief
mkdir build
cd build
scl enable devtoolset-7 rh-python36 'bash -c "cmake3 \
-DLIEF_PYTHON_API=on \
-DLIEF_DOC=off \
-DCMAKE_INSTALL_PREFIX=$LIEF_INSTALL \
-DCMAKE_BUILD_TYPE=Release \
-DPYTHON_VERSION=3.6 \
.."'
make -j3
cd api/python
scl enable rh-python36 'python3 setup.py install || :'
# when running setup.py, pip will download and install remote LIEF packages that will prevent MISP from detecting the packages that you compiled ; remove them
find /opt/rh/rh-python36/root/ -name "*lief*" -exec rm -rf {} \;
```

## 11.04/ Test lief installation, if no error, package installed
```bash
scl enable rh-python36 python3
>> import lief
```

# 12/ Known Issues
## 12.01/ Workers cannot be started or restarted from the web page
Possible also due to package being installed via SCL, attempting to start workers through the web page will result in
error. Worker's can be restarted via the CLI using the following command.
```bash
systemctl restart misp-workers.service
```

!!! note 
    No other functions were tested after the conclusion of this install. There may be issue that aren't addressed<br />
    via this guide and will need additional investigation.

{!generic/hardening.md!}
