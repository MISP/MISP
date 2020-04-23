#!/bin/bash
##
## script to wipe MISP on debian/ubuntu
##
## Adapted from misp-backup by daverstephens@gmail.com
## https://github.com/daverstephens/The-SOC-Shop
## and @alexanderjaeger
## https://github.com/deralexxx/misp-backup

##
## This script can be used to reset a MISP instance
## by clearing all events, orgs and users.
## It is highy recommended to run misp-backup.sh first!
##
## Tested against MISP 2.4.96
##
## Run the script as the standard user with the command below
##
## cp misp-wipe.conf.sample misp-wipe.conf
## vi misp-wipe.conf # adjust values
## sudo bash -x misp-wipe.sh 2>&1 | tee misp-wipe.log
##
## /!\ This might fail or create a random '0' file if using ZSH... (Oh-My...Berk)
##
## Time to set some variables
##

# This makes use of the standard variables used by the installer
eval "$(curl -fsSL https://raw.githubusercontent.com/MISP/MISP/2.4/docs/generic/globalVariables.md | grep -v \`\`\`)"
MISPvars > /dev/null 2>&1

LUSER_ID="$(id -u)"

if [[ "${LUSER_ID}" > "0" ]]; then
  echo "Please run this as a privileged user"
  echo "(usually 'sudo !!' will cover you)"
  exit
fi

FILE=./misp-wipe.conf
SQL=./misp-wipe.sql

# Source configuration file
if [ -f $FILE ];
then
   echo "File $FILE exists."
   . $FILE
else
        echo "Config File $FILE does not exist. Please enter values manually"
        ## MySQL stuff
        echo 'Please enter your MySQL root account username'
        read MySQLRUser
        echo 'Please enter your MySQL root account password (will not be echoed)'
        read -s MySQLRPass
fi


# Fill in any missing values with defaults

# MISP path
PATH_TO_MISP=${PATH_TO_MISP:-$(locate MISP/app/webroot/index.php|sed 's/\/app\/webroot\/index\.php//')}
# database.php
MySQLUUser=$(grep -o -P "(?<='login' => ').*(?=')" $PATH_TO_MISP/app/Config/database.php)
MySQLUPass=$(grep -o -P "(?<='password' => ').*(?=')" $PATH_TO_MISP/app/Config/database.php)
MISPDB=$(grep -o -P "(?<='database' => ').*(?=')" $PATH_TO_MISP/app/Config/database.php)
DB_Port=$(grep -o -P "(?<='port' => ).*(?=,)" $PATH_TO_MISP/app/Config/database.php)
MISPDBHost=$(grep -o -P "(?<='host' => ').*(?=')" $PATH_TO_MISP/app/Config/database.php)

echo "Clearing data model cache files"
rm -f $PATH_TO_MISP/app/tmp/cache/models/myapp_*
rm -f $PATH_TO_MISP/app/tmp/cache/persistent/myapp_*

echo "Wiping MySQL tables"
echo "Removes all users and organizations, except default (id=1)"
echo " - Change DELETE FROM to > 0 in misp-wipe.sql to also remove default ones"
echo " - Defaults are created on first login"
MySQLRUser=${MySQLRUser:-$MySQLUUser}
MySQLRPass=${MySQLRPass:-$MySQLUPass}
mysql --host $MISPDBHost -u $MySQLRUser -p$MySQLRPass $MISPDB < $SQL

echo "Inserting default values to MySQL tables"
TMP=/tmp/misp-wipe-$$.sql
cd $PATH_TO_MISP
sed -n '/Default values for initial installation/ { s///; :a; n; p; ba; }' INSTALL/MYSQL.sql | egrep -v '(admin_settings|db_version)' > $TMP
mysql --host $MISPDBHost -u $MySQLRUser -p$MySQLRPass $MISPDB < $TMP
rm -f $TMP

echo "Wiping files"
git clean -f -x app/webroot/img/orgs
#git clean -f -x app/webroot/img/custom
git clean -f -d -x app/tmp
git clean -f -d -x app/files

echo "Updating taxonomies"
baseurl=$(grep -o -P "(?<='baseurl' => ').*(?=')" $PATH_TO_MISP/app/Config/config.php)
AuthKey=$(echo 'select authkey from users where role_id = 1 order by id limit 1;' | mysql -u $MySQLRUser -p$MySQLRPass $MISPDB 2>/dev/null | tail -1)
curl --header "Authorization: $AuthKey" --header "Accept: application/json" --header "Content-Type: application/json" -o /dev/null -s -X POST ${baseurl}/taxonomies/update

echo "Updating warninglists"
curl --header "Authorization: $AuthKey" --header "Accept: application/json" --header "Content-Type: application/json" -o /dev/null -s -X POST ${baseurl}/warninglists/update

echo "Updating noticelists"
curl --header "Authorization: $AuthKey" --header "Accept: application/json" --header "Content-Type: application/json" -o /dev/null -s -X POST ${baseurl}/noticelists/update

echo "Updating galaxies"
curl --header "Authorization: $AuthKey" --header "Accept: application/json" --header "Content-Type: application/json" -o /dev/null -s -X POST ${baseurl}/galaxies/update

echo "Updating objectTemplates"
curl --header "Authorization: $AuthKey" --header "Accept: application/json" --header "Content-Type: application/json" -o /dev/null -s -X POST ${baseurl}/objectTemplates/update

echo "Updating decayingModel"
curl --header "Authorization: $AuthKey" --header "Accept: application/json" --header "Content-Type: application/json" -o /dev/null -s -X POST ${baseurl}/decayingModel/update

if [ "$ENABLE_WARNINGLISTS" = "true" ]; then
  echo "Enabling warninglists"
  wls=$(curl --header "Authorization: $AuthKey" --header "Accept: application/json" --header "Content-Type: application/json" -s -X POST ${baseurl}/warninglists/index | jq -r '.Warninglists[] | select(.Warninglist.enabled == false) | .Warninglist.id' 2>/dev/null)
  for wl in $wls; do
    curl --header "Authorization: $AuthKey" --header "Accept: application/json" --header "Content-Type: application/json" -d "{\"id\":$wl}" -o /dev/null -s -X POST ${baseurl}/warninglists/toggleEnable
  done
fi

if [ "$ENABLE_NOTICELISTS" = "true" ]; then
  echo "Enabling noticelists"
  nls=$(curl --header "Authorization: $AuthKey" --header "Accept: application/json" --header "Content-Type: application/json" -s -X POST ${baseurl}/noticelists/index | jq -r '.[] | select(.Noticelist.enabled == false) | .Noticelist.id' 2>/dev/null)
  for nl in $nls; do
    curl --header "Authorization: $AuthKey" --header "Accept: application/json" --header "Content-Type: application/json" -d "{\"Noticelist\":{\"data\":$nl}}" -o /dev/null -s -X POST ${baseurl}/noticelists/toggleEnable
  done
fi

echo 'MISP Wipe Complete!!!'
