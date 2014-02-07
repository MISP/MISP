clear
printf '=========================================================\n'
printf '|                                                       |\n'
printf '|         \e[34mM\e[39malware \e[34mI\e[39mnformation \e[34mS\e[39mharing \e[34mP\e[39mlatform          |\n'
printf '|                                                       |\n'
printf '|                   2.2 Installation                    |\n'
printf '|                                                       |\n'
printf '=========================================================\n\n'

YUM_CMD=$(which yum)
APT_GET_CMD=$(which apt-get)
BREW_CMD=$(which brew)
if [[ ! -z $APT_GET_CMD ]] 
  then
    printf '\n\nInstalling Redis using apt-get'
    apt-get install vim zip php-pear git redis-server
elif [[ ! -z $YUM_CMD ]] 
  then
    printf '\n\nInstalling Redis using yum'
    yum install vim zip php-pear git redis-server
elif [[ ! -z $OTHER_CMD ]] 
  then
    printf '\n\nInstalling Redis using brew'
    brew install vim zip php-pear git redis-server
else
	echo "Error, you need either apt-get, yum or brew to install zip, php-pear, git, redis using this script. Please install them manually.";
fi

pear install Crypt_GPG
pear install Net_GeoIP
git config core.filemode false
cd ..
git submodule init
git submodule update
cd app/Plugin/CakeResque
curl -s https://getcomposer.org/installer | php
php composer.phar install
cd ../../..
chown -R www-data:www-data *
chmod -R 750 *
chmod -R g+ws app/tmp
chmod -R g+ws app/files
cp -fa INSTALL/setup/config.php app/Plugin/CakeResque/Config/config.php
printf '\n\n=========================================================\n'
printf '|               \e[34mI\e[39mnstallation \e[34mC\e[39momplete                   |\n'
printf '=========================================================\n\n'