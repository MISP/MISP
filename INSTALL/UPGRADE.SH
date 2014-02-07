printf '=========================================================\n'
printf '|                                                       |\n'
printf '|                MISP 2.1 => 2.2 upgrade                |\n'
printf '|                                                       |\n'
printf '=========================================================\n\n'
read -p 'Do you wish to your database now? [y/n] ' -n 1 -r
if [[ $REPLY =~ ^[Yy]$ ]]
then
	printf '\n\nIn order to upgrade your MISP database to version 2.2, enter your database credentials.'
	printf '\nUsername: '
	read name
	printf '\nPassword: '
	read password
	printf '\nDatabase: '
	read database
	printf '\n\n'
else
	printf '\n\nDatabase not updated. You will have to update it manually by executing\n\nmysql -u [username] -p[password] [database name] < upgrade_2.2.sql from the MISP/INSTALL directory\n\n'
fi
cd ..
git submodule init
git submodule update
cd app/Plugin/CakeResque
apt-get install redis-server
curl -s https://getcomposer.org/installer | php
php composer.phar install
cd ../../..
chown -R www-data:www-data *
chmod -R 750 *
chmod -R g+ws app/tmp
chmod -R g+ws app/files