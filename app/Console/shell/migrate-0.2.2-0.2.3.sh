#!/bin/sh

# migrate 0.2.2 to 0.2.3

# DataBase migrate, Audit and Access Control granulation

# step into project and ..
PRJCT=../../app
cd ${PRJCT}

# create ACL tables
./Console/cake schema create DbAcl
# populate ACL acos
./Console/cake acl create aco root controllers
./Console/cake AclExtras.AclExtras aco_sync

# create Correlation table
./Console/cake schema create DbCorrelation

# create Regex table
./Console/cake schema create DbRegex

# create Whitelist table
./Console/cake schema create DbWhitelist

# update Schema, add Users.group_id
./Console/cake schema update -s 0.2.2.1

# create Log table
./Console/cake schema create DbLog

# create Groups, populate ACL aros and Users.group_id
./Console/cake schema create DbGroup

# populate 0.2.3
./Console/cake populate0_2_3

exit 0;