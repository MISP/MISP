## Important

** NOTE: CURRENTLY MISP 3.x IS IN DEVELOPMENT ONLY MODE LACKING MOST MAJOR FEATURES **

## Requirements

An Ubuntu server (22.04 at least highly recommended) - though other linux installations should work too.

- apache2 (or nginx), mysql/mariadb, sqlite need to be installed and running
- php version 8.1+ is required
- php extensions for intl, mysql, sqlite3, mbstring, xml need to be installed and running
- php extention for curl (not required but makes composer run a little faster)
- composer

## Network requirements

MISP communicates via HTTPS so in order to be able to connect to other MISP nodes, requiring the following ports to be open:
- port 443 needs to be open for outbound connections to be able to pull data in
- MISP also needs to be accessible (via port 443) from the outside if:
    - you wish to act as a hub node for a community where members are expected to pull data from your node or push data to it
    - you wish to be a member of a community and expect other parties to push data to you in real-time when they publish it


## MISP installation instructions

It should be sufficient to issue the following command to install the dependencies:

- for apache

```bash
sudo apt install apache2 mariadb-server git composer php-intl php-mbstring php-dom php-xml unzip php-ldap php-sqlite3 php-curl sqlite libapache2-mod-php php-mysql
```

- for nginx
```bash
sudo apt install nginx mariadb-server git composer php-intl php-mbstring php-dom php-xml unzip php-ldap php-sqlite3 sqlite php-fpm php-curl php-mysql
```

Clone this repository (for example into /var/www/MISP)

```bash
sudo mkdir /var/www/MISP
sudo chown www-data:www-data /var/www/MISP
sudo -u www-data git clone https://github.com/MISP/MISP.git /var/www/MISP
cd /var/www/MISP
sudo -u www-data git checkout 3.x
```

Run composer

```bash
sudo mkdir -p /var/www/.composer
sudo chown www-data:www-data /var/www/.composer
cd /var/www/MISP
sudo -H -u www-data composer install
```

Create a database for MISP

With a fresh install of Ubuntu sudo to the (system) root user before logging in as the mysql root
```Bash
sudo -i mysql -u root
```

From SQL shell:
```mysql
CREATE DATABASE misp;
CREATE USER 'misp'@'localhost' IDENTIFIED BY 'YOUR_PASSWORD';
GRANT USAGE ON *.* to misp@localhost;
GRANT ALL PRIVILEGES ON misp.* to misp@localhost;
FLUSH PRIVILEGES;
QUIT;
```

Or from Bash:
```bash
sudo mysql -e "CREATE DATABASE misp;"
sudo mysql -e "CREATE USER 'misp'@'localhost' IDENTIFIED BY 'YOUR_PASSWORD';"
sudo mysql -e "GRANT USAGE ON *.* to misp@localhost;"
sudo mysql -e "GRANT ALL PRIVILEGES ON misp.* to misp@localhost;"
sudo mysql -e "FLUSH PRIVILEGES;"
```

create your local configuration and set the db credentials

```bash
sudo -u www-data cp -a /var/www/MISP/config/app_local.example.php /var/www/MISP/config/app_local.php
sudo -u www-data cp -a /var/www/MISP/config/config.example.json /var/www/MISP/config/config.json
sudoedit -u www-data /var/www/MISP/config/app_local.php
```

Simply modify the Datasource -> default array's username, password, database fields
This would be, when following the steps above:

```php
    'Datasources' => [
        'default' => [
            'host' => 'localhost',
            'username' => 'misp',
            'password' => 'YOUR_PASSWORD',
            'database' => 'misp',
```

### WARNING: DURING THE PRE-RELEASE STATE, USE AN EXISTING MISP DB'S DUMP AS A STARTING POINT

From your old MISP:

```
mysqldump -u misp -p misp > misp_bkup.sql
```
From the development 3.x branch MISP:

```
mysql -u misp -p misp < misp_bkup.sql
```

### Make sure you apply any pending deltas from TODO.TXT until migration scripts exist for them


Run the database schema migrations
```bash
sudo -u www-data /var/www/MISP/bin/cake migrations migrate
```

Clean cakephp caches
```bash
sudo rm /var/www/MISP/tmp/cache/models/*
sudo rm /var/www/MISP/tmp/cache/persistent/*
```

Create an apache config file for misp / ssh key and point the document root to /var/www/MISP/webroot and you're good to go

For development installs the following can be done for either apache or nginx:

```bash
# Apache
# This configuration is purely meant for local installations for development / testing
# Using HTTP on an unhardened apache is by no means meant to be used in any production environment
sudo cp /var/www/MISP/INSTALL/apache.misp.ubuntu /etc/apache2/sites-available/misp_apache_dev.conf
sudo ln -s /etc/apache2/sites-available/misp_apache_dev.conf /etc/apache2/sites-enabled/
sudo a2enmod headers
sudo a2enmod rewrite
sudo service apache2 restart
```

OR

```bash
# NGINX
# This configuration is purely meant for local installations for development / testing
# Using HTTP on an unhardened apache is by no means meant to be used in any production environment
sudo cp /var/www/MISP/INSTALL/misp_nginx.conf /etc/nginx/sites-available/
sudo ln -s /etc/nginx/sites-available/misp_nginx.conf /etc/nginx/sites-enabled/
sudo systemctl disable apache2 # may be required if apache is using port
sudo service nginx restart
sudo systemctl enable nginx

```

Now you can point your browser to: http://localhost:8000

To log in use the default credentials below:

- Username: admin
- Password: Password1234
