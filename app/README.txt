                                                                     
TODOs v0.2.2 to v0.2.3
-----

Auth
- Prevent bruteforce auth attempts

Acl
- inactive buttons
	- must be non-clickable.
	- JavaScript include.
	- DOM read and disable button_offXX.
- clean-up to first cut.
	- My Profile, Group, make non-link.
	- saveAcl, from GroupsController to AppController and inherit to *Controllers.

auditing/logging system
- Action, popup.
- Change, regex remove ', revision (1) => (2) '.
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

TODO rewrite instructions using git clones and git submodules


Download CyDefSIG using git in the /var/www/ directory. 

cd /var/www/
git clone git@code.lab.modiss.be:cydefsig.git

Download and extract CakePHP 2.x to the web root directory:

cd /tmp/
wget https://nodeload.github.com/cakephp/cakephp/tarball/2.1
tar zxvf cakephp-cakephp-<version>.tar.gz
cd cakephp-cakephp-*

Now remove the app directory and move everything from CakePHP to var/www

rm -Rf app .gitignore 
mv * /var/www/cydefsig/
mv .??* /var/www/cydefsig/

TODO TODO Install the CakePHP REST Plugin in the plugins directory.
(https://github.com/kvz/cakephp-rest-plugin/tree/cake-2.0)  
using git submodule



Check if the permissions are set correctly using the following commands as root:

chown -R <user>:www-data /var/www/cydefsig
chmod -R 750 /var/www/cydefsig
chmod -R g+s /var/www/cydefsig
cd /var/www/cydefsig/app/
chmod -R g+w tmp
chmod -R g+w files

Import the empty MySQL database in /var/www/cydefsig/app/MYSQL.txt using phpmyadmin or mysql>.

Now configure your apache server with the DocumentRoot /var/www/cydefsig/app/webroot/

Configure the fields in the files:
database.php : login, port, password, database
bootstrap.php: CyDefSIG.*, GnuPG.*
core.php : debug, 

Generate a GPG encryption key.
sudo -u www-data gpg --homedir /var/www/cydefsig/.gnupg --gen-key


Now log in using the webinterface:
The default user/pass = admin@admin.test/admin 

Don't forget to change the email, password and authentication key after installation.



Recommended patches
-------------------
By default CakePHP exposes his name and version in email headers. Apply a patch to remove this behavior.
