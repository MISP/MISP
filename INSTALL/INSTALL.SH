dir=`dirname $0`
FILE_PATH=`cd  $dir;pwd`
cd ..
MISP_PATH=`pwd`
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
    printf '\n\nNo redis package with yum, please download and install Redis manually.'
    yum install vim zip php-pear git
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
cd "$MISP_PATH"
git submodule init
git submodule update
cd "$MISP_PATH/app/Plugin/CakeResque"
curl -s https://getcomposer.org/installer | php
php composer.phar install
cd "$MISP_PATH"
chown -R www-data:www-data "$MISP_PATH"
chmod -R 750 "$MISP_PATH"
chmod -R g+ws "$MISP_PATH/app/tmp"
chmod -R g+ws "$MISP_PATH/app/files"
cp -fa "$FILE_PATH/setup/config.php" "$MISP_PATH/app/Plugin/CakeResque/Config/config.php"
printf '\n\n=========================================================\n'
printf '|               \e[34mI\e[39mnstallation \e[34mC\e[39momplete                   |\n'
printf '=========================================================\n\n'