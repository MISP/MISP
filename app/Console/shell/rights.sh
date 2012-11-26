#!/bin/sh

USER=noud
CY_HOME=/var/www/cydefsig
#CY_HOME=/var/www/test/nato/cydefsig
#CY_HOME=/var/www/test/bel_mod/cydefsig
#CY_HOME=/var/www/test/cert_eu/cydefsig

chown -R ${USER}:www-data ${CY_HOME}
chmod -R 750 ${CY_HOME}
chmod -R g+s ${CY_HOME}
cd ${CY_HOME}/app/
chmod -R g+w tmp
chmod -R g+w files

# GnuPG
chmod -R ug+rwx ${CY_HOME}/.gnupg

exit 0
