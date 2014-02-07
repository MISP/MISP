cd ../app/Plugin/CakeResque
apt-get install redis-server
curl -s https://getcomposer.org/installer | php
php composer.phar install
cd ../../..
chown -R www-data:www-data ../*
chmod -R 750 ../*
chmod -R g+ws ../app/tmp
chmod -R g+ws ../app/files