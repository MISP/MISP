#!/usr/bin/env bash
## $Id: misp-backup.sh 07.04.2016 $
##
## script to backup MISP on debian/ubuntu 18.04.2
##
## Authored by daverstephens@gmail.com
## https://github.com/daverstephens/The-SOC-Shop
##
## added some more studd by @alexanderjaeger
## https://github.com/deralexxx/misp-backup
##
## more amendments by @SteveClement
##

##
## This script can be used to backup a complete MISP
## MySQL DB and config to restore onto a freshly
## built system. This is not intended as an upgrade script
## to move between MISP versions - But it might work ;).
##
## Tested against MISP 2.4.102
##
## Run the script as the standard web user with the command below
##
## cp misp-backup.conf.sample misp-backup.conf
## vi misp-backup.conf # adjust values
## sudo bash misp-backup.sh 2>&1 | tee misp-backup.log
##
## TODO: Target directory, rudimentary free space check: stat -f --format="%a" OutputDirName
## TODO: Make sure no directories are blank
## TODO: Review how much sense it makes to ask fo MySQL credentials when most of the script does auto detection anyway.
##

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

## Time to set some variables
##

FILE=./misp-backup.conf

# Extract base directory where this script is and cd into it
cd "${0%/*}"

# Set to the current webroot owner
WWW_USER=$(ls -l $0 |awk {'print $3'}|tail -1)

# In most cases the owner of the cake script is also the user as which it should be executed.
if [[ "$USER" != "$WWW_USER" ]]; then
  echo "You run this script as $USER and the owner of the backup script is $WWW_USER. FYI."
fi

# Check if run as root
if [[ "$EUID" != "0" ]]; then
    echo "Please run the backup script as root"
    exit 1
fi

# Source configuration file
if [ -f $FILE ];
then
  echo "File $(pwd)$FILE exists."
   . $FILE
else
        echo "Config File $FILE does not exist. Please enter values manually"
        space
        echo -n 'Please enter your MySQL root account username: '
        read MySQLRUser
        echo -n 'Please enter your MySQL root account password: '
        read MySQLRPass
        echo -n 'Please enter a name for the backup archive (e.g MISPBackup): '
        read OutputFileName
        echo -n 'Please enter the destination for the archive (e.g /tmp): '
        read OutputDirName
fi

# Fill in any missing values with defaults

# MISP path detector
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

# Output
OutputFileName=${OutputFileName:-MISP-Backup}
OutputDirName=${OutputDirName:-/tmp}
OutputFull="${OutputDirName}/${OutputFileName}-$(date '+%Y%m%d_%H%M%S').tar.gz"

# database.php
MySQLUUser=$(grep -o -P "(?<='login' => ').*(?=')" $PATH_TO_MISP/app/Config/database.php) ; checkVar MySQLUUser
MySQLUPass=$(grep -o -P "(?<='password' => ').*(?=')" $PATH_TO_MISP/app/Config/database.php) ; checkVar MySQLUPass
MISPDB=$(grep -o -P "(?<='database' => ').*(?=')" $PATH_TO_MISP/app/Config/database.php) ; checkVar MISPDB
DB_Port=$(grep -o -P "(?<='port' => ).*(?=,)" $PATH_TO_MISP/app/Config/database.php) ; checkVar DB_Port
MISPDBHost=$(grep -o -P "(?<='host' => ').*(?=')" $PATH_TO_MISP/app/Config/database.php) ; checkVar MISPDBHost

# config.php
Salt=$(grep -o -P "(?<='salt' => ').*(?=')" $PATH_TO_MISP/app/Config/config.php) ; checkVar Salt
BaseURL=$(grep -o -P "(?<='baseurl' => ').*(?=')" $PATH_TO_MISP/app/Config/config.php) # BaseURL can be empty
OrgName=$(grep -o -P "(?<='org' => ').*(?=')" $PATH_TO_MISP/app/Config/config.php) ; checkVar OrgName
LogEmail=$(grep -o -P "(?<='email' => ').*(?=')" $PATH_TO_MISP/app/Config/config.php|head -1) ; checkVar LogEmail
AdminEmail=$(grep -o -P "(?<='contact' => ').*(?=')" $PATH_TO_MISP/app/Config/config.php) ; checkVar AdminEmail
GnuPGEmail=$(sed -n -e '/GnuPG/,$p' $PATH_TO_MISP/app/Config/config.php|grep -o -P "(?<='email' => ').*(?=')") ; checkVar GnuPGEmail
GnuPGHomeDir=$(grep -o -P "(?<='homedir' => ').*(?=')" $PATH_TO_MISP/app/Config/config.php) ; checkVar GnuPGHomeDir
GnuPGPass=$(grep -o -P "(?<='password' => ').*(?=')" $PATH_TO_MISP/app/Config/config.php) ; checkVar GnuPGPass

checkDiskFree $OutputDirName

# Create backup files
TmpDir="$(mktemp --tmpdir=$OutputDirName -d)"
cp -rp $GnuPGHomeDir/* $TmpDir/
echo "copy of org images and other custom images"
cp -rp $PATH_TO_MISP/app/webroot/img/orgs $TmpDir/
cp -rp $PATH_TO_MISP/app/webroot/img/custom $TmpDir/
cp -rp $PATH_TO_MISP/app/files $TmpDir

#  MISP Config files
mkdir -p $TmpDir/Config
cp -p $PATH_TO_MISP/app/Config/bootstrap.php $TmpDir/Config
cp -p $PATH_TO_MISP/app/Config/config.php $TmpDir/Config
cp -p $PATH_TO_MISP/app/Config/core.php $TmpDir/Config
cp -p $PATH_TO_MISP/app/Config/database.php $TmpDir/Config

echo "MySQL Dump"
MySQLRUser=${MySQLRUser:-$MySQLUUser}
MySQLRPass=${MySQLRPass:-$MySQLUPass}
mysqldump --opt -u $MySQLRUser -p$MySQLRPass $MISPDB > $TmpDir/MISPbackupfile.sql
if [[ "$?" != "0" ]]; then
  echo "MySQLdump failed, abort." && exit 1
fi
# Create compressed archive
cd $TmpDir
tar -pzcf $OutputFull ./*
cd -
rm -rf $TmpDir
echo "MISP Backup Completed, OutputDir: ${OutputDirName}"
echo "FileName: ${OutputFileName}-$(date '+%Y%m%d_%H%M%S').tar.gz"
echo "FullName: ${OutputFull}"
