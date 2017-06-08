#!/bin/bash
#Autosnort script for Ubuntu 12.04+
########################################

#The script prompts for root_mysql_pass and misp_mysql_pass
#these will be the passwords you use to access mysql as root/misp
#Also asks the user if a HTTP or HTTPS web server should be set up or not.

########################################
#This line unsets some environment variables just for the shell script to run. This is done to ensure that passwords are NOT logged to your .*history files.
unset HISTFILE MYSQL_HISTFILE
########################################
# Logging setup. Ganked this entirely from stack overflow. Uses FIFO/pipe magic to log all the output of the script to a file. Also capable of accepting redirects/appends to the file for logging compiler stuff (configure, make and make install) to a log file instead of losing it on a screen buffer. This gives the user cleaner output, while logging everything in the background, for troubleshooting, analysis, or sending it to me for help.

logfile=/var/log/misp_install.log
mkfifo ${logfile}.pipe
tee < ${logfile}.pipe $logfile &
exec &> ${logfile}.pipe
rm ${logfile}.pipe

#Functions, functions everywhere.
########################################
#metasploit-like print statements. Gratuitously ganked from  Darkoperator's metasploit install script. status messages, error messages, good status returns. I added in a notification print for areas users should definitely pay attention to.

function print_status ()
{
    echo -e "\x1B[01;34m[*]\x1B[0m $1"
}

function print_good ()
{
    echo -e "\x1B[01;32m[*]\x1B[0m $1"
}

function print_error ()
{
    echo -e "\x1B[01;31m[*]\x1B[0m $1"
}

function print_notification ()
{
	echo -e "\x1B[01;33m[*]\x1B[0m $1"
}

########################################
#Script does a lot of error checking. Decided to insert an error check function. If a task performed returns a non zero status code, something very likely went wrong.

function error_check
{

if [ $? -eq 0 ]; then
	print_good "$1 successfully completed."
else
	print_error "$1 failed. Please check $logfile for more details."
exit 1
fi

}

########################################
#Package installation function.

function install_packages()
{

apt-get update &>> $logfile && apt-get install -y ${@} &>> $logfile
error_check 'Package installation'

}

########################################
#This script creates a lot of directories by default. This is a function that checks if a directory already exists and if it doesn't creates the directory (including parent dirs if they're missing).

function dir_check()
{

if [ ! -d $1 ]; then
	print_notification "$1 does not exist. Creating.."
	mkdir -p $1
else
	print_notification "$1 already exists. (No problem, We'll use it anyhow)"
fi

}

########################################
##BEGIN MAIN SCRIPT##
#Pre checks: These are a couple of basic sanity checks the script does before proceeding.

read -r -p "Please enter your mysql root password: " root_mysql_pass
size=${#root_mysql_pass}

if (( $size < 6 ));
then
		print_notification "Password is too short - $size, please consider choosing a longer password."
fi

read -r -p "Please enter your mysql MISP password: " misp_mysql_pass
read -r -p "Enable Apache HTTP to HTTPS stub? [y/N] " enableweb
read -r -p "Enable MISP HTTPS web server on port 443? [y/N] " enablessl
if [[ $enablessl =~ ^([yY][eE][sS]|[yY])$ ]];
then
    print_good "Please enter the following information for the CA certificate:"
	read -r -p "Country code: " cactry
	read -r -p "Region: " caregion
	read -r -p "City: " cacity
	read -r -p "Organization: " caorg
fi


print_status "OS Version Check.."
release=`lsb_release -r|awk '{print $2}'`
if [[ $release == "14."* ]]; then
	print_good "OS is Ubuntu 14. Good to go."
else
    print_notification "This is not Ubuntu 16.x, this autosnort script has NOT been tested on other platforms."
	print_notification "You continue at your own risk!(Please report your successes or failures!)"
fi

#root check. Lotta stuff we're doing requires root access.

print_status "Checking for root privs.."
if [ $(whoami) != "root" ]; then
	print_error "This script must be ran with sudo or root privileges."
	exit 1
else
	print_good "We are root."
fi

########################################
#this is a nice little hack I found in stack exchange to suppress messages during package installation.

export DEBIAN_FRONTEND=noninteractive

# System updates
print_status "Performing apt-get update and upgrade (May take a while if this is a fresh install).."
apt-get update &>> $logfile && apt-get -y upgrade &>> $logfile
error_check 'System updates'

########################################
#These packages are required to run MISP. I've also included a couple of basic system administration packages (ntp and ntpdate), as well as a package to help with entropy/RNG for gpg key generation

print_status "Installing: vim curl gnupg-agent git redis-server zip gcc make sudo openssl python python-dev python-pip python3-dev python3-pip libxml2-dev libxslt1-dev zlib1g-dev apache2 apache2-doc apache2-utils libapache2-mod-php5 libapache2-modsecurity php-pear php5-mysql php5-json mysql-server php-crypt-gpg .."

declare -a packages=(vim curl gnupg-agent git redis-server zip gcc make sudo openssl python python-dev python-pip python3-dev python3-pip libxml2-dev libxslt1-dev zlib1g-dev apache2 apache2-doc apache2-utils libapache2-mod-php5 libapache2-modsecurity php-pear php5-mysql php5-json mysql-server php-crypt-gpg );
install_packages ${packages[@]}


########################################
#enable apache mod_security, and mod_rewrite, disable the default sites.

a2enmod rewrite headers &>> $logfile
error_check 'Enabling of mod_rewrite'

a2dissite 000-default default-ssl &>> $logfile
error_check 'Disabling of default sites (http and ssl)'

########################################
#create and enable the misp http and https sites, then enable them
case $enableweb in
    [yY][eE][sS]|[yY])
		print_status "configuring MISP HTTP web server.."

		if [ -f /etc/apache2/sites-available/misp.conf ]; then
			print_notification "misp http to https stub site already configured."
		else
			echo "#This vhost was generated by autoMISP." > /etc/apache2/sites-available/misp.conf
			echo "<VirtualHost *:80>" >> /etc/apache2/sites-available/misp.conf
			echo "	ServerAdmin me@me.local" >> /etc/apache2/sites-available/misp.conf
			echo "	ServerName `hostname`.local" >> /etc/apache2/sites-available/misp.conf
			echo "	DocumentRoot /var/www/MISP/app/webroot" >> /etc/apache2/sites-available/misp.conf
			echo "	<Directory /var/www/MISP/app/webroot>" >> /etc/apache2/sites-available/misp.conf
			echo "		Options -Indexes" >> /etc/apache2/sites-available/misp.conf
			echo "		AllowOverride all" >> /etc/apache2/sites-available/misp.conf
			echo "		Order allow,deny" >> /etc/apache2/sites-available/misp.conf
			echo "		allow from all" >> /etc/apache2/sites-available/misp.conf
			echo "	</Directory>" >> /etc/apache2/sites-available/misp.conf
			echo "	RewriteEngine On" >> /etc/apache2/sites-available/misp.conf
			echo "	RewriteCond %{HTTPS} off" >> /etc/apache2/sites-available/misp.conf
			echo "	RewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI}" >> /etc/apache2/sites-available/misp.conf
			echo "	LogLevel warn" >> /etc/apache2/sites-available/misp.conf
			echo "	ErrorLog /var/log/apache2/misp.local_error.log" >> /etc/apache2/sites-available/misp.conf
			echo "	CustomLog /var/log/apache2/misp.local_access.log combined" >> /etc/apache2/sites-available/misp.conf


			echo "	ServerSignature Off" >> /etc/apache2/sites-available/misp.conf
			echo "</VirtualHost>" >> /etc/apache2/sites-available/misp.conf
		fi

		a2ensite misp &>> $logfile
		error_check 'Enabling of MISP HTTP site'
        ;;
        *)
esac

#misp-ssl
case $enablessl in
    [yY][eE][sS]|[yY])
		print_status "configuring MISP HTTPS web server.."

		########################################
		#We make /etc/apache2/ssl and set strict r/w/x permissions for root only in the directory.
		#Afterwards, we generate a self-signed certificate and private key, putting strict permissions on those as well.

		print_status "Generating a private key and self-signed SSL certificate for HTTPS operation.."
		dir_check /etc/apache2/ssl

		chmod 700 /etc/apache2/ssl
		cd /etc/apache2/ssl

		openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 -subj "/C=$cactry/ST=$caregion/L=$cacity/O=$caorg/CN=`hostname`" -keyout misp.key  -out misp.crt &>> $logfile
		error_check 'SSL certificate and key generation'
		print_good "SSL private key location: /etc/apache2/ssl/misp.key"
		print_good "SSL certificate location: /etc/apache2/ssl/misp.crt"

		chmod 600 /etc/apache2/ssl/misp.*

		#enable apache mod_ssl.

		a2enmod ssl &>> $logfile
		error_check 'Enabling of mod_ssl'
		########################################

		if [ -f /etc/apache2/sites-available/misp-ssl.conf ]; then
			print_notification "misp https already configured."
		else
			echo "#This vhost was generated by autoMISP." > /etc/apache2/sites-available/misp-ssl.conf
			echo "<VirtualHost *:443>" >> /etc/apache2/sites-available/misp-ssl.conf
			echo "	ServerAdmin me@me.local" >> /etc/apache2/sites-available/misp-ssl.conf
			echo "	ServerName `hostname`.local" >> /etc/apache2/sites-available/misp-ssl.conf
			echo "	DocumentRoot /var/www/MISP/app/webroot" >> /etc/apache2/sites-available/misp-ssl.conf
			echo "	<Directory /var/www/MISP/app/webroot>" >> /etc/apache2/sites-available/misp-ssl.conf
			echo "		Options -Indexes" >> /etc/apache2/sites-available/misp-ssl.conf
			echo "		AllowOverride all" >> /etc/apache2/sites-available/misp-ssl.conf
			echo "		Order allow,deny" >> /etc/apache2/sites-available/misp-ssl.conf
			echo "		allow from all" >> /etc/apache2/sites-available/misp-ssl.conf
			echo "	</Directory>" >> /etc/apache2/sites-available/misp-ssl.conf
			echo "	RewriteEngine On" >> /etc/apache2/sites-available/misp-ssl.conf
			echo "	RewriteCond %{HTTPS} off" >> /etc/apache2/sites-available/misp-ssl.conf
			echo "	RewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI}" >> /etc/apache2/sites-available/misp-ssl.conf
			echo "	SSLEngine On" >> /etc/apache2/sites-available/misp-ssl.conf
			echo "	SSLCipherSuite EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH:EECDH+ECDSA+AESGCM:EECDH+aRSA+AESGCM:EECDH+ECDSA+SHA384:EECDH+ECDSA+SHA256:EECDH+aRSA+SHA384:EECDH+aRSA+SHA256:EECDH:EDH+aRSA" >> /etc/apache2/sites-available/misp-ssl.conf
			echo "	SSLProtocol All -SSLv2 -SSLv3" >> /etc/apache2/sites-available/misp-ssl.conf
			echo "	SSLHonorCipherOrder On" >> /etc/apache2/sites-available/misp-ssl.conf
			echo "	Header always set Strict-Transport-Security \"max-age=63072000; includeSubdomains; preload\"" >> /etc/apache2/sites-available/misp-ssl.conf
			echo "	Header always set X-Frame-Options DENY" >> /etc/apache2/sites-available/misp-ssl.conf
			echo "	Header always set X-Content-Type-Options nosniff" >> /etc/apache2/sites-available/misp-ssl.conf
			echo "	SSLCompression off" >> /etc/apache2/sites-available/misp-ssl.conf
		#not yet available in the ubuntu 14.04 repo apache
		#	echo "	SSLSessionTickets Off" >> /etc/apache2/sites-available/misp-ssl.conf
			echo "	SSLUseStapling on" >> /etc/apache2/sites-available/misp-ssl.conf
		#disabled as the min mod_ssl.so required version is 1.0.2
		#	echo "	SSLOpenSSLConfCmd Curves secp384r1" >> /etc/apache2/sites-available/misp-ssl.conf
			echo "	SSLCertificateFile /etc/apache2/ssl/misp.crt" >> /etc/apache2/sites-available/misp-ssl.conf
			echo "	SSLCertificateKeyFile /etc/apache2/ssl/misp.key" >> /etc/apache2/sites-available/misp-ssl.conf
		#	echo "	SSLCertificateChainFile /etc/ssl/private/misp-chain.crt" >> /etc/apache2/sites-available/misp-ssl.conf
			echo "	LogLevel warn" >> /etc/apache2/sites-available/misp-ssl.conf
			echo "	ErrorLog /var/log/apache2/misp-ssl.local_error.log" >> /etc/apache2/sites-available/misp-ssl.conf
			echo "	CustomLog /var/log/apache2/misp-ssl.local_access.log combined" >> /etc/apache2/sites-available/misp-ssl.conf
			echo "	ServerSignature Off" >> /etc/apache2/sites-available/misp-ssl.conf
			echo "</VirtualHost>" >> /etc/apache2/sites-available/misp-ssl.conf
			echo "#This setting has to be specified outside of the VirtualHost directive" >> /etc/apache2/sites-available/misp-ssl.conf
			echo "SSLStaplingCache \"shmcb:logs/stapling-cache(150000)\"" >> /etc/apache2/sites-available/misp-ssl.conf
		fi

		a2ensite misp-ssl &>> $logfile
		error_check 'Enabling of MISP HTTPS site'
	;;
	*)
esac

#let them know that if the apache ServerName means anything to them, they may want to change it.
if [[ $enableweb =~ ^([yY][eE][sS]|[yY])$ || $enablessl =~ ^([yY][eE][sS]|[yY])$ ]]
then
    print_notification "Please note that the default ServerName is set to `hostname`.local You may need to change this."
fi

########################################
#using php pear to install GPG extentions - to allow GPG encrypted email from MISP
if [ -d /usr/share/php/data/Crypt_GPG ]; then
	print_notification "Crypt_GPG already installed."
else
	print_status "Installing Crypt_GPG.."
	pear install Crypt_GPG &>> $logfile
	error_check 'Installation of Crypt_GPG'
fi

########################################
#pull down MISP
#(nuke the directory if it exists -- failed install)

if [ -d /var/www/MISP ]; then
	rm -rf /var/www/MISP
fi

print_status "Downloading MISP to /var/www.."

cd /var/www/
git clone https://github.com/MISP/MISP.git &>> $logfile
error_check 'Download of MISP'

#git configuration changes recommend by the MISP project document

cd /var/www/MISP
git config core.filemode false &>> $logfile

########################################
#python-cybox and python-stix are installed as part of MISP

print_status "Installing cybox and stix for MISP.."

cd /var/www/MISP/app/files/scripts
git clone https://github.com/CybOXProject/python-cybox.git &>> $logfile
error_check 'Download of python-cybox'
git clone https://github.com/STIXProject/python-stix.git &>> $logfile
error_check 'Download of python-stix'

cd /var/www/MISP/app/files/scripts/python-cybox
git checkout v2.1.0.12 &>> $logfile
python setup.py install &>> $logfile
error_check "Installation of python-cybox"

cd /var/www/MISP/app/files/scripts/python-stix
git checkout v1.1.1.4 &>> $logfile
python setup.py install &>> $logfile
error_check "Installation of python-stix"

print_status "Initializing and updating MISP submodules"
cd /var/www/MISP
git submodule init &>> $logfile
git submodule update &>> $logfile
error_check "Initializing and updating MISP submodules"

########################################
#Install PHP Composer and CakePHP for MISP

print_status "Installing PHP Composer and CakePHP.."

cd /var/www/MISP/app
curl -s https://getcomposer.org/installer | php &>> $logfile
error_check 'Composer installation'
php composer.phar require kamisama/cake-resque:4.1.2 &>> $logfile
php composer.phar config vendor-dir Vendor &>> $logfile
php composer.phar install &>> $logfile
cp -fa /var/www/MISP/INSTALL/setup/config.php /var/www/MISP/app/Plugin/CakeResque/Config/config.php
print_good "Installed CakePHP"

########################################
#php.ini has to be modified to use the redis-php extension. before we make any changes, we back up the default php config. If the backup exists, we assume the php-redis extention was installed already

print_status "modifying /etc/php/apache2/php.ini to use redis.so.."
if [ -f /etc/php/apache2/php.ini.bak ]; then
	print_notification "redis.so already enabled"
else
	cp /etc/php/apache2/php.ini /etc/php/apache2/php.ini.bak
	echo "; Support for phpredis - added on `date`" >> /etc/php/apache2/php.ini
	echo "extension=redis.so" >> /etc/php/apache2/php.ini
fi

########################################
#setting up mysql user, database and table structure

print_status "Setting up mysql"
mysqladmin -uroot password $root_mysql_pass &>> $logfile
error_check 'mysql root password change'

mysql -uroot -p$root_mysql_pass -e "DELETE FROM mysql.user WHERE User=''; DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1'); DROP DATABASE IF EXISTS test; DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%'; DROP DATABASE IF EXISTS misp; CREATE DATABASE misp; GRANT ALL PRIVILEGES ON misp.* TO 'misp'@'localhost' IDENTIFIED BY '$misp_mysql_pass'; FLUSH PRIVILEGES;" &>> $logfile
error_check 'mysql_secure_installation and misp database/user creation'

cd /var/www/MISP
mysql -u misp -p$misp_mysql_pass -D misp < INSTALL/MYSQL.sql &>> $logfile
error_check 'MISP database setup'

########################################
#move the default php files for MISP and configure them

print_status "Moving and configuring MISP php config files.."

cd /var/www/MISP/app/Config
cp -a bootstrap.default.php bootstrap.php
cp -a database.default.php database.php
cp -a core.default.php core.php
cp -a config.default.php config.php
sed -i "s#db login#misp#" database.php
sed -i "s#db password#$misp_mysql_pass#" database.php
#hackish way to generate a new salt for MISP. Janky AF, but it works.
salt_seed=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
sed -i "s#Rooraenietu8Eeyo<Qu2eeNfterd-dd+#$salt_seed#" config.php

print_good "MISP php config files modified"

########################################
#This is gnupg stuff and actually requires user intervention. I'm opting not to do anything e-mail related -- the users will have to set up postfix on their own.
#I've left the commands that the MISP install docs say to use for GPG key generation, etc.

#mkdir /var/www/MISP/.gnupg
#sudo -u www-data gpg --homedir /var/www/MISP/.gnupg --gen-key
#sudo -u www-data gpg --homedir /var/www/MISP/.gnupg --export --armor YOUR-EMAIL > /var/www/MISP/app/webroot/gpg.asc

########################################
#Resetting the file permissions for the MISP webapp - to ensure www-data has proper access.

print_status "Resetting file permissions to /var/www/MISP* for www-data to be able to access properly.."

chown -R www-data:www-data /var/www/MISP
chmod -R 750 /var/www/MISP
chmod -R g+ws /var/www/MISP/app/tmp
chmod -R g+ws /var/www/MISP/app/files
chmod -R g+ws /var/www/MISP/app/files/scripts/tmp

print_good "File permissions modified"

########################################
#We have to have the worker script for MISP executable and start it with the www-data user. The workers perform all sorts of task for the MISP webapp and are kinda necessary.

print_status "Making MISP worker script executable and starting.."
chmod +x /var/www/MISP/app/Console/worker/start.sh
sudo -u www-data bash /var/www/MISP/app/Console/worker/start.sh &>> $logfile
error_check 'MISP worker script'

########################################
#support for zeromq and redis extentions

print_status "Installing pyzmq and redis via pip.."

pip install pyzmq redis &>> $logfile
error_check 'Installation of pyzmq and redis'

########################################
#Do you want extra misp modules? of course you do.
#We should misp_modules.py as the www-data user. By default, this service runs on 127.0.0.1:6666
#The python script logs both sterr and stout to /var/log/misp_mod_logs

print_status "Installing MISP extra modules.."

dir_check /opt/misp_mod
dir_check /var/log/misp_mod_logs/
chown -R www-data:www-data /var/log/misp_mod_logs
cd /opt/misp_mod
git clone https://github.com/MISP/misp-modules.git &>> $logfile
error_check "Download of MISP modules"
cd misp-modules
pip3 install -r REQUIREMENTS &>> $logfile
error_check 'MISP module requirement installation'
sudo -u www-data python3 /opt/misp_mod/misp-modules/bin/misp-modules.py &> /var/log/misp_mod_logs/misp_mod_logs-`date +%Y-%m-%d:%H:%M:%S`.log &
error_check 'MISP module script'

########################################
#Modify /etc/rc.local to add the MISP workers and module scripts to start on boot. If the file has already been modified, do nothing.

print_status "Adding persistence for MISP workers and module service via rc.local.."

if [ -f /etc/rc.local.bak ]; then
	print_notification "misp workers and extra modules already added."
else
	cp /etc/rc.local /etc/rc.local.bak
	sed -i "s#exit 0##" /etc/rc.local
	echo "sudo -u www-data bash /var/www/MISP/app/Console/worker/start.sh" >> /etc/rc.local
	echo "sudo -u www-data python3 /opt/misp_mod/misp-modules/bin/misp-modules.py &> /var/log/misp_mod_logs/misp_mod_logs-`date +%Y-%m-%d:%H:%M:%S`.log &" >> /etc/rc.local
	echo "exit 0" >> /etc/rc.local
	print_good "rc.local successfully modified"
fi

########################################
#Restart apache2

print_status "Restarting apache2.."

service apache2 restart &>> $logfile
error_check 'apache2 service restart'

########################################

print_good "script completed successfully."
print_notification "MISP installed at: /var/www/MISP"
print_notification "MISP modules installed at:/opt/misp_mod/misp-modules"
print_notification "I highly recommend accessing your MISP instance via IP address (https://x.x.x.x)"
print_notification "Important! Change the salt key in /var/www/MISP/app/Config/config.php. The salt key must be a string at least 32 bytes long."
print_notification "The admin user account will be generated on the first login, make sure that the salt is changed before you create that user!"
print_notification "Default credentials: admin@admin.test//admin"
print_notification "Obviously, you'll want to change this upon login."
print_notification "Consider deleting this script after execution!"
print_notification "Please note that if you require MISP to be able to send e-mail, Postfix and GPG configuration has been left as an exercise to the user. Commands for generating a GPG key for the MISP instance have been commented out at lines 349-351 if you wish to use them."

exit 0
