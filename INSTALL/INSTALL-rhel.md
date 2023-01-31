# Installing Cerebrate on RedHat Enterprise Linux (RHEL 8)
>This installation instructions assume SELinux is enabled, and in Enforcing mode.
>and that you want to keep it that way :)
>You need to be root when running these commands.

## Prerequisites
>Install needed packages:
```Shell
dnf install @httpd mariadb-server git @php unzip sqlite vim wget  php-intl php-ldap php-mysqlnd php-pdo php-zip
```
## Install composer 
>Instructions taken from https://getcomposer.org/download/
```PHP
cd /root
php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
php -r "if (hash_file('sha384', 'composer-setup.php') === '55ce33d7678c5a611085589f1f3ddf8b3c52d662cd01d4ba75c0ee0459970c2200a51f492d557530c71c15d8dba01eae') { echo 'Installer verified'; } else { echo 'Installer corrupt'; unlink('composer-setup.php'); } echo PHP_EOL;"
php composer-setup.php --install-dir=/usr/bin --filename=composer
php -r "unlink('composer-setup.php');"
```

## Prepare MySQL for cerebrate
>Enable and start mysql database. Select a secure password for root user, delete test user and database. 

```Shell
systemctl start mariadb
systemctl enable mariadb
mysql_secure_installation
```
### Create a new database, user and password for cerebrate
```Shell
mysql -u root -p
```
```SQL
CREATE DATABASE cerebrate;
CREATE USER 'cerebrate'@'localhost' IDENTIFIED BY 'CHANGE_ME_PASSWORD';
GRANT USAGE ON *.* to cerebrate@localhost;
GRANT ALL PRIVILEGES ON cerebrate.* to cerebrate@localhost;
FLUSH PRIVILEGES;
QUIT;
```
## Allow ports through the firewall
```Shell
firewall-cmd --zone=public --add-service=http         --permanent 
firewall-cmd --zone=public --add-port=8001/tcp        --permanent
```
> reload firewall and show applied firewall rules
```Shell
firewall-cmd --reload
firewall-cmd --zone public --list-all
```

## Main Cerebrate Installation
>Steps to install Cerebrate on RHEL

### Clone this repository
```Shell
mkdir /var/www/cerebrate
git clone https://github.com/cerebrate-project/cerebrate.git /var/www/cerebrate
```

### Run composer
```Shell
mkdir -p /var/www/.composer
chown -R apache.apache  /var/www/.composer
chown -R apache.apache  /var/www/cerebrate
cd /var/www/cerebrate
composer install 
```
>you will see a prompt: \
>`Do you trust "cakephp/plugin-installer" to execurte code and wish to enable it now? (writes "allow-plugins" to composer.json) [y,n,d,?]` \
>*repond with* `y` \
>`Do you trust "dealerdirect/phpcodesniffer-composer-installer" to execute code and wish to enable it now? (writes "allow-plugins" to composer.json) [y,n,d,?]` \
>*repond with* `y`

### Create your local configuration and set the db credentials
```Shell
cp -a /var/www/cerebrate/config/app_local.example.php /var/www/cerebrate/config/app_local.php
cp -a /var/www/cerebrate/config/config.example.json /var/www/cerebrate/config/config.json
```

### Modify the Datasource -> default array's in file `app_local.php`
>Simply modify the `Datasources` section, to reflect your values for: username, password, and database 
>fields, as configured in the above [#create-a-new-database-user-and-password-for-cerebrate](<#create-a-new-database-user-and-password-for-cerebrate>)
```Shell
vim /var/www/cerebrate/config/app_local.php
```
```PHP
    'Datasources' => [
        'default' => [
            'host' => 'localhost',
            'username' => 'cerebrate',
            'password' => 'CHANGE_ME_PASSWORD',
            'database' => 'cerebrate',
            ...
```

### Run the database schema migrations
```Shell
usermod -s /bin/bash apache

chown -R apache.apache  /var/www/.composer
chown -R apache.apache  /var/www/cerebrate

su apache <<'EOFi'
/var/www/cerebrate/bin/cake migrations migrate
/var/www/cerebrate/bin/cake migrations migrate -p tags
/var/www/cerebrate/bin/cake migrations migrate -p ADmad/SocialAuth
EOFi

usermod -s /sbin/nologin apache
```


### Clean cakephp caches
```Shell
rm /var/www/cerebrate/tmp/cache/models/*
rm /var/www/cerebrate/tmp/cache/persistent/*
```

### copy the Apache httpd template to the default apache configuration folder
> in our case we used apache to serve this website, NGINX could also be used.
```Shell
cp -v /var/www/cerebrate/INSTALL/cerebrate_apache_dev.conf /etc/httpd/conf.d/.
mkdir /var/log/apache2
chown apache.root -R /var/log/apache2
restorecon -Rv /etc/httpd/conf.d/*
restorecon -Rv /var/log/*
```
### Make changes to the apache httpd site configuration file
>Edit the file `/etc/httpd/conf.d/cerebrate_apache_dev.conf` change the two references of port 8000 to 8001
```Shell
vi /etc/httpd/conf.d/cerebrate_apache_dev.conf
```
### Make changes to SELinux
>From the SELinux Manual page [services with non standard ports](<https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/using_selinux/configuring-selinux-for-applications-and-services-with-non-standard-configurations_using-selinux>)
>We need SELinux to allow httpd to connect to our custom port 8001/tcp
```SELinux Policy
semanage port -a -t http_port_t -p tcp 8001
```
>Change SELinux context for folder /var/www/cerebrate
```SELinux Policy
semanage fcontext -a -t httpd_sys_content_t "/var/www/cerebrate(/.*)?"
restorecon -Rv /var/www/cerebrate/
chown apache.apache /var/www/cerebrate
```

## Apply changes/restart Apache httpd
>Look out for any errors during restart.
```
systemctl enable httpd
systemctl restart httpd
```

## Point your browser to: http://localhost:8001
> If everything worked, you should be able to log in using the default credentials below:

```
Username: admin
Password: Password1234
```
