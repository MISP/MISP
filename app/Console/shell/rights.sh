#!/bin/sh

USER=noud

chown -R ${USER}:www-data /var/www/cydefsig
chmod -R 750 /var/www/cydefsig
chmod -R g+s /var/www/cydefsig
cd /var/www/cydefsig/app/
chmod -R g+w tmp
chmod -R g+w files

exit 0
