#@IgnoreInspection BashAddShebang
#/!bin/sh
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
## It is highy recommended ## to run misp-backup.sh first!
##
## Tested against MISP 2.4.55
##
## Run the script as the standard user with the command below
##
## cp misp-wipe.conf.sample misp-wipe.conf
## vi misp-wipe.conf # adjust values
## sudo sh -x misp-wipe.sh 2>&1 | tee misp-wipe.log
##
## Time to set some variables
##

if (( $EUID > 0 ))
  then 
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
MISPPath=${MISPPath:-$(locate MISP/app/webroot/index.php|sed 's/\/app\/webroot\/index\.php//')}
# database.php
MySQLUUser=$(grep -o -P "(?<='login' => ').*(?=')" $MISPPath/app/Config/database.php)
MySQLUPass=$(grep -o -P "(?<='password' => ').*(?=')" $MISPPath/app/Config/database.php)
MISPDB=$(grep -o -P "(?<='database' => ').*(?=')" $MISPPath/app/Config/database.php)
DB_Port=$(grep -o -P "(?<='port' => ).*(?=,)" $MISPPath/app/Config/database.php)
MISPDBHost=$(grep -o -P "(?<='host' => ').*(?=')" $MISPPath/app/Config/database.php)

echo "Clearing data model cache files"
rm -f $MISPPath/app/tmp/cache/models/myapp_*
rm -f $MISPPath/app/tmp/cache/persistent/myapp_*

echo "Wiping MySQL tables"
MySQLRUser=${MySQLRUser:-$MySQLUUser}
MySQLRPass=${MySQLRPass:-$MySQLUPass}
mysql -u $MySQLRUser -p$MySQLRPass $MISPDB < $SQL

echo "Inserting default values to MySQL tables"
TMP=/tmp/misp-wipe-$$.sql
cd $MISPPath
sed -n '/Default values for initial installation/ { s///; :a; n; p; ba; }' INSTALL/MYSQL.sql | egrep -v '(admin_settings|db_version)' > $TMP
mysql -u $MySQLRUser -p$MySQLRPass $MISPDB < $TMP
rm -f $TMP

echo "Wiping files"
git clean -f -x app/webroot/img/orgs
#git clean -f -x app/webroot/img/custom
git clean -f -x app/tmp/logs/
git clean -f -d -x app/files

echo "Updating taxonomies"
baseurl=$(grep -o -P "(?<='baseurl' => ').*(?=')" $MISPPath/app/Config/config.php)
AuthKey=$(echo 'select authkey from users where role_id = 1 order by id limit 1;' | mysql -u $MySQLRUser -p$MySQLRPass $MISPDB 2>/dev/null | tail -1)
curl --header "Authorization: $AuthKey" --header "Accept: application/json" --header "Content-Type: application/json" -o /dev/null -s -X POST ${baseurl}/taxonomies/update

echo "Updating warninglists"
curl --header "Authorization: $AuthKey" --header "Accept: application/json" --header "Content-Type: application/json" -o /dev/null -s -X POST ${baseurl}/warninglists/update

echo "Updating galaxies"
curl --header "Authorization: $AuthKey" --header "Accept: application/json" --header "Content-Type: application/json" -o /dev/null -s -X POST ${baseurl}/galaxies/update

echo "Updating objectTemplates"
curl --header "Authorization: $AuthKey" --header "Accept: application/json" --header "Content-Type: application/json" -o /dev/null -s -X POST ${baseurl}/objectTemplates/update

echo 'MISP Wipe Complete!!!'
