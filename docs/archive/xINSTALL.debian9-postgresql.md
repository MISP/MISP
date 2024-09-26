# INSTALLATION INSTRUCTIONS
## for Debian --->8<--- "jessie" server + PostgreSQL

!!! note
    This is the old Deian 8 jessie Guide, needs updating.

!!! warning
    PostgreSQL support in MISP is experimental.
    We strongly discourage you from use on production systems.
    Testing & development: most recent MISP codebase on Debian 8 "jessie" (PHP 5.6 & PostgreSQL 9.4).
    There may be serious bugs!
    We also don't support updates (e.g. 2.4.49 -> 2.4.50) on PostgreSQL yet, so your installation may break.

!!! notice
    If you want to help improving PostgreSQL-support,
    Please make sure you have tried the newest commit from GitHub first.
    Also, please activate debug mode.
    After that, you may open an issue on Github and provide us with as much information on the issue as possible.



please follow Debian 8 install instructions - INSTALL.debian8.txt
-------------------------

# when it comes to installing mariadb in step 2, skip that part, instead:
sudo apt-get install postgresql

# instead of installing the php5-mysql package in step 2, install php5-pgsql
sudo apt-get install php5-pgsql
# activate the module
sudo php5enmod pgsql
# restart apache
sudo service apache2 restart


# in step 6 of the Debian install, you skip creating a mysql user, instead:
# create user
sudo -u postgres createuser misp
# create database
sudo -u postgres createdb -O misp misp
# set password
sudo -u postgres psql -U postgres
postgres=# ALTER USER misp with password 'XXXXXXXXX';
postgres=# \q

# after that, load the basic database structure
psql -U misp -d misp -f /var/www/MISP/INSTALL/POSTGRESQL-structure.sql -h localhost -W

# ATTENTION: skip this step if you want to migrate from MySQL/MariaDB!
# and load initial data
psql -U misp -d misp -f /var/www/MISP/INSTALL/POSTGRESQL-data-initial.sql -h localhost -W


# in step 8 of the Debian install, you configure Postgres instead of MySQL
# the necessary lines are already there, you just have to activate them instead of the MySQL-lines
# file: /var/www/MISP/app/Config/database.php
# necessary changes:
# 'datasource' => 'Database/Postgres',
# 'port' => 5432,


# ATTENTION: skip this step if you want to migrate from MySQL/MariaDB!
# perhaps you accidentally installed MySQL/MariaDB, too - but you can clean it up like this
sudo apt-get remove mysql-server mysql-client mariadb-client mariadb-server php5-mysql




### MIGRATION from MySQL/MariaDB
# migration of data is done using latest "pgloader" release (3.2.2 at the time of writing)

# add official postgres repository to apt sources
sudo sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt/ $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list'

# make sure packages from official postgres repository aren't used by default, only when explicitly specifying it
sudo cat <<EOF > /etc/apt/preferences.d/pgdg.pref
Package: *
Pin: release o=apt.postgresql.org
Pin-Priority: 200
EOF

# install some dependencies
sudo apt-get install wget ca-certificates

# add repository signing key
wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -

# update cache
sudo apt-get update

# install pgloader
sudo apt-get -t $(lsb_release -cs)-pgdg install pgloader

# migrate data (replace XXX and YYY with the correct passwords)
pgloader --type mysql --with "reset sequences" --with "data only" --set "maintenance_work_mem = '128MB'" --set "work_mem = '12MB'" --cast "type tinyint when (= precision 1) to smallint" mysql://misp:XXX@localhost/misp  postgresql://misp:YYY@localhost/misp

# afterwards, you have to change your MISP database configuration (see above)

# maybe you want to remove mysql (see command above) in the end
# if you only want to stop&disable it:
systemctl stop mysql
systemctl disable mysql

{% comment %}
{% include_relative generic/hardening.md %}
{% endcomment %}
