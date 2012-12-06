                                                                     
TODOs v0.2.3 to v2.0.0
-----

DB Update
- UpdateShell with in/out

Auth
- Prevent bruteforce auth attempts

Acl
- clean-up to first cut.
	- saveAcl, from GroupsController to AppController and inherit to *Controllers.

auditing/logging system
- logins
	- add source IP (headers,...);
	- failed logins.

Security
- force cookie reset after login


INSTALLATION INSTRUCTIONS
-------------------------
Install the following libraries:
apt-get install zip
apt-get install php-pear
pear install Crypt_GPG    # need version >1.3.0 
pear install Net_GeoIP
# ideally make sure geoip database is updated using crontab
#wget 'http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz'
#gunzip GeoIP.dat.gz


TODO rewrite instructions using git clones and git submodules

# Download CakePHP from github
cd /opt/
git pull https://github.com/cakephp/cakephp.git
chmod -R 755 /opt/cakephp


# Download CyDefSIG using git in the /var/www/ directory. 
cd /var/www/
git clone git@code.lab.modiss.be:cydefsig.git 


# Check if the permissions are set correctly using the following commands as root:
chown -R <user>:www-data /var/www/cydefsig
chmod -R 750 /var/www/cydefsig
chmod -R g+s /var/www/cydefsig
cd /var/www/cydefsig/app/
chmod -R g+w tmp
chmod -R g+w files

# Import the empty MySQL database in /var/www/cydefsig/app/MYSQL.txt using phpmyadmin or mysql>.

# Now configure your apache server with the DocumentRoot /var/www/cydefsig/app/webroot/


# Configure the fields in the files:
database.php : login, port, password, database
bootstrap.php: CyDefSIG.*, GnuPG.*
core.php : debug, 
webroot/index.php : CAKE_CORE_INCLUDE_PATH   (optional for multi-cydefsig installations)

# Generate a GPG encryption key.
mkdir /var/www/cydefsig/.gnupg
chown www-data:www-data /var/www/cydefsig/.gnupg
chmod 700 /var/www/cydefsig/.gnupg
sudo -u www-data gpg --homedir /var/www/cydefsig/.gnupg --gen-key

# And export the public key to the webroot
sudo -u www-data gpg --homedir .gnupg --export --armor no-reply > app/webroot/gpg.asc

# Create the Role Based Access Control (RBAC) tables and content:
cd /var/www/cydefsig/app
./Console/cake schema create DbAcl
./Console/cake acl create aco root controllers
./Console/cake AclExtras.AclExtras aco_sync
./Console/cake populate0_2_3


Now log in using the webinterface:
The default user/pass = admin@admin.test/admin 

Don't forget to change the email, password and authentication key after installation.



UPDATE INSTRUCTIONS
-------------------

To be sure, dump your database before updating.

CyDefSIG from 0.2.2 to 0.2.3 needs a database migration and population.
This is done executing /var/www/cydefsig/app/Console/shell/migrate-0.2.2-0.2.3.sh
and answer (y)es to all the questions asked
and afterward run http://<host>:<port>/events/migratemisp11to2/<your org>
with <your org> being MIL.BE or NCIRC where appropriate.

Import the regex data in /var/www/cydefsig/app/MYSQL.regex.sql using phpmyadmin or mysql>.


Recommended patches
-------------------
By default CakePHP exposes his name and version in email headers. Apply a patch to remove this behavior.

Multiple instances on a single server
-------------------------------------
If you want to install multiple instances on a single server, extract the CakePHP sources 
in a central location like /opt/cakephp.
 
Then edit /var/www/cydefsig/app/webroot/index.php and change :
	define('CAKE_CORE_INCLUDE_PATH', '/opt/cakephp/lib');

