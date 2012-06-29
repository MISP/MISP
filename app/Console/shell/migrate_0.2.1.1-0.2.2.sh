#!/bin/sh

# migrate 0.2.1.1 to 0.2.2

# Servers.lastpushedid and Servers.lastpulledid

# step into project and ..
PRJCT=/var/www/cydefsig/app
cd ${PRJCT}

# update Schema, add Users.group_id
./Console/cake schema update -s 0.2.2

exit 0