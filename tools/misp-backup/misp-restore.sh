#!/usr/bin/env bash
# 
# Inspired from daverstephens@gmail.com and @alexanderjaeger work on misp-backup.sh
#
# Apache, MISP and mariaDB/MySQL should be installed before running this script
#
# Only works with a database on localhost
#
# This script restores following file/DB from an archive created with misp-backup.sh:
# - app/Config PHP files
# - app/webroot/img orgs and custom files
# - app/webroot/files 
# - GPG files
# - MYSQL User used in archive or its password if exists
# - MISP database
# 
#
# This script does not restore:
# - Apache configuration files
# - SSL certificates used by the web server
#
#
# sudo sh ./misp-restore.sh  PATH_TO_ARCHIVE.tar.gz
# 

# TODO: Make script UNATTENDEDable
# TODO: Move DB, check DB?
# TODO: Check db user exists.

# This makes use of the standard variables used by the installer
eval "$(curl -fsSL https://raw.githubusercontent.com/MISP/MISP/2.4/docs/generic/globalVariables.md | awk '/^# <snippet-begin/,0' | grep -v \`\`\`)"
MISPvars > /dev/null 2>&1

# Leave empty for NO debug messages, if run with set -x or bash -x it will enable DEBUG by default
DEBUG=

case "$-" in
  *x*)  NO_PROGRESS=1; DEBUG=1 ;;
  *)    NO_PROGRESS=0 ;;
esac

## Functions

# Dynamic horizontal spacer
space () {
  if [[ "$NO_PROGRESS" == "1" ]]; then
    return
  fi
  # Check terminal width
  num=`tput cols`
  for i in `seq 1 $num`; do
    echo -n "-"
  done
  echo ""
}

# Make sure the target has enough free space
checkDiskFree () {
  if [[ ! -e $1 ]]; then
    echo "$1 does not exist, creating"
    mkdir -p $1
  fi
  threshhold=90
  free=$(df -l --sync --output=pcent $1 |tail -1|cut -f 1 -d% | tr -d \ )
  if [[ "$free" > "$threshhold" ]]; then
    space
    echo "Your destination folder is $threshhold% full."
    space
    exit 1
  fi
}

# Check if variable is empty
checkVar () {
  [[ -z $1 ]] && echo "$1 is empty, please investigate." && exit 1
}

# Small function to import SQL export
mysqlImport () {
  myDB=$(mysqlshow |grep -o $MISPDB)
  if [[ "$myDB" == "$MISPDB" ]]; then
    echo -n "$myDB detected, I can remove this if wanted. (y/n) "
    read REMOVE
    REMOVE=$(echo $REMOVE |tr [A-Z] [a-z])
    [[ "$REMOVE" == "y" ]] && mysqladmin drop $myDB
  fi

  mysql -h $MISPDBHost -u $MySQLRUser -p -Bse "CREATE DATABASE IF NOT EXISTS $MISPDB ;\
      GRANT USAGE ON *.* TO '$MySQLUUser'@'localhost' IDENTIFIED BY '$MySQLUPass';\
      GRANT ALL PRIVILEGES ON $MISPDB.* TO '$MySQLUUser'@'localhost' ; \
      FLUSH PRIVILEGES;"

  mysql -s -h $MISPDBHost -u $MySQLUUser -p$MySQLUPass $MISPDB < $BackupDir/MISPbackupfile.sql
}
echo '-- Starting MISP restore process'

FILE=./misp-backup.conf

# Extract base directory where this script is and cd into it
cd "${0%/*}"

# Set to the current webroot owner
WWW_USER=$(ls -l $0 |awk {'print $3'}|tail -1)

MySQLRUser="root"

# In most cases the owner of the cake script is also the user as which it should be executed.
if [[ "$USER" != "$WWW_USER" ]]; then
  echo "You run this script as $USER and the owner of the backup script is $WWW_USER, this should be your web server user. FYI."
fi

# Check if run as root
if [[ "$EUID" != "0" ]]; then
    echo "Please run the backup script as root"
    exit 1
fi

if [ ! -z $1 ] && [ -f $1 ]; then 
    BackupFile=$1
else
    echo 'Specify backup file by running ./misp-restore.sh  PATH_TO_ARCHIVE.tar.gz'
    exit 1
fi

# Source configuration file
if [ -f $FILE ]; then
  echo "--- File $(pwd)$FILE exists."
  . $FILE
else
  echo "--- Config File $FILE does not exist. Please enter values manually"
  echo -n '--- Where would you like to decompress backup files (Eg. /tmp)? '
  read OutputDirName
fi

checkDiskFree OutputDirName

# Decompress archive
BackupDir=$OutputDirName/$(basename -s ".tar.gz" $BackupFile)
mkdir $BackupDir
echo '--- Decompressing files'
tar zxpf $BackupFile -C $BackupDir

# Fill in any missing values with defaults
# MISP path detector
if [[ -z $UNATTENDED ]]; then
  if [[ -z $PATH_TO_MISP ]]; then
    if [[ "$(locate > /dev/null 2> /dev/null ; echo $?)" != "127" ]]; then
      if [[ "$(locate MISP/app/webroot/index.php |wc -l)" > 1 ]]; then
        echo "We located more then 1 MISP/app/webroot, reverting to manual"
        PATH_TO_MISP=${PATH_TO_MISP:-$(locate MISP/app/webroot/index.php|sed 's/\/app\/webroot\/index\.php//')}
        echo -n 'Please enter the base path of your MISP install (e.g /var/www/MISP): '
        read PATH_TO_MISP
      fi
    fi
  fi

  if [[ -d $PATH_TO_MISP ]] && [[ -f $PATH_TO_MISP/VERSION.json ]]; then
    echo "$PATH_TO_MISP exists and seems to include an existing install."
    echo "We can move it out of the way, or leave as is."
    echo -n "Move $PATH_TO_MISP to $OutputDirName/MISP-$(date +%Y%m%d)?"
    read MOVE
    MOVE=$(echo $MOVE |tr [A-Z] [a-z])
    [[ "$MOVE" == "y" ]] && mv $PATH_TO_MISP $OutputDirName/MISP-$(date +%Y%m%d) && mkdir $PATH_TO_MISP
  fi
fi

# database.php
MySQLUUser=$(grep -o -P "(?<='login' => ').*(?=')" $BackupDir/Config/database.php) ; checkVar MySQLUUser
MySQLUPass=$(grep -o -P "(?<='password' => ').*(?=')" $BackupDir/Config/database.php) ; checkVar MySQLUPass
MISPDB=$(grep -o -P "(?<='database' => ').*(?=')" $BackupDir/Config/database.php) ; checkVar MISPDB
DB_Port=$(grep -o -P "(?<='port' => ).*(?=,)" $BackupDir/Config/database.php) ; checkVar DB_Port
MISPDBHost=$(grep -o -P "(?<='host' => ').*(?=')" $BackupDir/Config/database.php) ; checkVar MISPDBHost

# config.php
Salt=$(grep -o -P "(?<='salt' => ').*(?=')" $BackupDir/Config/config.php) ; checkVar Salt
BaseURL=$(grep -o -P "(?<='baseurl' => ').*(?=')" $BackupDir/Config/config.php) # BaseURL can be empty
OrgName=$(grep -o -P "(?<='org' => ').*(?=')" $BackupDir/Config/config.php) ; checkVar OrgName
LogEmail=$(grep -o -P "(?<='email' => ').*(?=')" $BackupDir/Config/config.php|head -1) ; checkVar LogEmail
AdminEmail=$(grep -o -P "(?<='contact' => ').*(?=')" $BackupDir/Config/config.php) ; checkVar AdminEmail
GnuPGEmail=$(sed -n -e '/GnuPG/,$p' $BackupDir/Config/config.php|grep -o -P "(?<='email' => ').*(?=')") ; checkVar GnuPGEmail
GnuPGHomeDir=$(grep -o -P "(?<='homedir' => ').*(?=')" $BackupDir/Config/config.php) ; checkVar GnuPGHomeDir
GnuPGPass=$(grep -o -P "(?<='password' => ').*(?=')" $BackupDir/Config/config.php) ; checkVar GnuPGPass

if [[ -f /tmp/MISPbackupfile.sql ]]; then
  mysqlImport
  rm /tmp/MISPbackupfile.sql
  exit
fi

# Restore backup files
echo "--- Copy of GnuPG files"
mkdir -p $GnuPGHomeDir
cp $BackupDir/*.gpg $GnuPGHomeDir/
cp $BackupDir/random_seed $GnuPGHomeDir/


echo "--- Copy of org and images and files"
cp -pr $BackupDir/orgs $PATH_TO_MISP/app/webroot/img/
cp -pr $BackupDir/custom $PATH_TO_MISP/app/webroot/img/
cp -pr $BackupDir/files $PATH_TO_MISP/app/


#  Restore MISP Config files
echo "--- Copy of app/Config files"
cp -p $BackupDir/Config/bootstrap.php $PATH_TO_MISP/app/Config
cp -p $BackupDir/Config/config.php $PATH_TO_MISP/app/Config
cp -p $BackupDir/Config/core.php $PATH_TO_MISP/app/Config
cp -p $BackupDir/Config/database.php $PATH_TO_MISP/app/Config

# Permissions
echo "--- Setting persmissions"
chown -R $WWW_USER:$WWW_USER /var/www/MISP
chmod -R 750 /var/www/MISP
chmod -R g+ws /var/www/MISP/app/tmp
chmod -R g+ws /var/www/MISP/app/files
chmod -R g+ws /var/www/MISP/app/files/scripts/tmp



# Restore DB
echo "--- Starting MySQL database Restore"
echo -n '---- Please enter your MySQL root account username: '
read MySQLRUser

echo "---- Creating database and user if not exists with data found in MISP configuration files"
mysqlImport

##if [[ "$returnCode" != "0" ]]; then
##  echo "Something went wrong, MySQL returned: $returnCode"
##  echo "The MISPbackupfile.sql will be copied to: /tmp for you to handle this situation manually."
##  echo "You can also run this script again and we will retry to import the SQL."
##  cp $BackupDir/MISPbackupfile.sql /tmp > /dev/null 2> /dev/null
##  rm -rf $BackupDir
##  exit $returnCode
##fi

    
rm -rf $BackupDir

if [[ ! -z $BaseURL ]]; then
  echo "-- MISP Restore Complete! URL: $BaseURL"
else
  echo "-- MISP Restore Complete!"
fi
