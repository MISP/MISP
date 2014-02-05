#!/bin/sh

USER=noud
CY_HOME=../../../../MISP

chown -R ${USER}:www-data ${CY_HOME}
chmod -R 750 ${CY_HOME}
chmod -R g+s ${CY_HOME}
cd ${CY_HOME}/app/
chmod -R g+w tmp
chmod -R g+w files

# GnuPG
chmod -R ug+rwx ${CY_HOME}/.gnupg

exit 0
