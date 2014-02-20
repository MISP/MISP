dir=`dirname $0`
FILE_PATH=`cd  $dir;pwd`
cd ..
MISP_PATH=`pwd`
printf '========================================================\n'
printf '|                                                      |\n'
printf '|         \e[34mM\e[39malware \e[34mI\e[39mnformation \e[34mS\e[39mharing \e[34mP\e[39mlatform         |\n'
printf '|                                                      |\n'
printf '|                  2.1 => 2.2 upgrade                  |\n'
printf '|                                                      |\n'
printf '========================================================\n\n'
read -p 'Do you wish to upgrade your database now? [y/n] ' -n 1 -r
if [[ $REPLY =~ ^[Yy]$ ]]
then
	printf '\n\nIn order to upgrade your MISP database to version 2.2, enter your database credentials.'
	printf '\nUsername: '
	read name
	printf '\nPassword: '
	read password
	printf '\nDatabase: '
	read database
	cd "$FILE_PATH"
	mysql -u $name -p$password $database < upgrade_2.2.sql
	printf '\n\n'
else
	printf '\n\nDatabase not updated. You will have to update it manually by executing\n\nmysql -u [username] -p[password] [database name] < upgrade_2.2.sql from the MISP/INSTALL directory\n\n'
fi
cd "$MISP_PATH"
git submodule init
git submodule update

YUM_CMD=$(which yum)
APT_GET_CMD=$(which apt-get)
BREW_CMD=$(which brew)

if [[ ! -z $APT_GET_CMD ]] 
  then
    printf '\n\nInstalling Redis using apt-get'
    apt-get install redis-server
elif [[ ! -z $YUM_CMD ]] 
  then
    printf '\n\nNo Redis package available with yum, please install it manually.'
    yum install redis
elif [[ ! -z $OTHER_CMD ]] 
  then
    printf '\n\nInstalling Redis using brew'
    brew install redis-server
else
	echo "Error, you need either apt-get, yum or brew to install Redis using this script. Please install it manually.";
fi

cd "$MISP_PATH/app/Plugin/CakeResque"
curl -s https://getcomposer.org/installer | php
php composer.phar install
cd "$MISP_PATH"
chown -R www-data:www-data "$MISP_PATH"
chmod -R 750 "$MISP_PATH"
chmod -R g+ws "$MISP_PATH/app/tmp"
chmod -R g+ws "$MISP_PATH/app/files"
rm app/tmp/cache/*/*
cp -fa "$FILE_PATH/setup/config.php" "$MISP_PATH/app/Plugin/CakeResque/Config/config.php"
printf '\n\n=========================================================\n'
printf '|               \e[34mI\e[39mnstallation \e[34mC\e[39momplete                   |\n'
printf '=========================================================\n\n'

