#!/bin/sh

# migrate 0.2.2 to 0.2.3

# DataBase migrate, Audit and Access Control granulation

# step into project and ..
PRJCT=../../../app
cd ${PRJCT}

# create ACL tables
./Console/cake schema create DbAcl
# populate ACL acos
./Console/cake acl create aco root controllers
./Console/cake AclExtras.AclExtras aco_sync

# create Correlation table
./Console/cake schema create DbCorrelation

# create Regexp table
./Console/cake schema create DbRegexp

# create Whitelist table
./Console/cake schema create DbWhitelist

# update Schema, add Users.role_id
./Console/cake schema update -s 0.2.2.1

# create Log table
./Console/cake schema create DbLog

# create Roles, populate ACL aros and Users.role_id
./Console/cake schema create DbRole

# populate 0.2.3
./Console/cake populate0_2_3

exit 0;