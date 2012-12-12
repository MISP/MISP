#!/bin/sh

# degrate 0.2.3 to 0.2.2

# step into project and ..
PRJCT=/var/www/cydefsig/app
cd ${PRJCT}

# update Schema, remove Users.role_id
./Console/cake schema update -s 0.2.2

exit 0;