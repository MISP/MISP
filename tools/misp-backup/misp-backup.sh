#@IgnoreInspection BashAddShebang
#!/bin/sh
## $Id: misp-backup.sh 07.04.2016 $
##
## script to backup MISP on debian/ubuntu 14.04.1
##
## Authored by daverstephens@gmail.com
## https://github.com/daverstephens/The-SOC-Shop
##
## added some more studd by @alexanderjaeger
## https://github.com/deralexxx/misp-backup

##
## This script can be used to backup a complete MISP
## DB and config to restore onto a freshly
## built system. This is not intended as an upgrade script
## to move between MISP versions - But it might work ;).
##
## Tested against MISP 2.4.33
##
## Run the script as the standard user with the command below
##
## cp misp-backup.conf.sample misp-backup.conf
## vi misp-backup.conf # adjust values
## sudo sh -x misp-backup.sh 2>&1 | tee misp-backup.log
##
## Time to set some variables
##


FILE=./misp-backup.conf

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
        echo 'Please enter your MySQL root account password'
        read MySQLRPass
        echo 'What would you like to call the backup archive?'
        echo 'Eg. MISPBackup'
        read OutputFileName
        echo 'Where would you like to save the file?'
        echo 'Eg. /tmp'
        read OutputDirName
fi


# Fill in any missing values with defaults

# MISP path
MISPPath=${MISPPath:-$(locate MISP/app/webroot/index.php|sed 's/\/app\/webroot\/index\.php//')}
# Output
OutputFileName=${OutputFileName:-MISP-Backup}
OutputDirName=${OutputDirName:-/tmp}
# database.php
MySQLUUser=$(grep -o -P "(?<='login' => ').*(?=')" $MISPPath/app/Config/database.php)
MySQLUPass=$(grep -o -P "(?<='password' => ').*(?=')" $MISPPath/app/Config/database.php)
MISPDB=$(grep -o -P "(?<='database' => ').*(?=')" $MISPPath/app/Config/database.php)
DB_Port=$(grep -o -P "(?<='port' => ).*(?=,)" $MISPPath/app/Config/database.php)
MISPDBHost=$(grep -o -P "(?<='host' => ').*(?=')" $MISPPath/app/Config/database.php)
# config.php
Salt=$(grep -o -P "(?<='salt' => ').*(?=')" $MISPPath/app/Config/config.php)
BaseURL=$(grep -o -P "(?<='baseurl' => ').*(?=')" $MISPPath/app/Config/config.php)
OrgName=$(grep -o -P "(?<='org' => ').*(?=')" $MISPPath/app/Config/config.php)
LogEmail=$(grep -o -P "(?<='email' => ').*(?=')" $MISPPath/app/Config/config.php|head -1)
AdminEmail=$(grep -o -P "(?<='contact' => ').*(?=')" $MISPPath/app/Config/config.php)
GnuPGEmail=$(sed -n -e '/GnuPG/,$p' $MISPPath/app/Config/config.php|grep -o -P "(?<='email' => ').*(?=')")
GnuPGHomeDir=$(grep -o -P "(?<='homedir' => ').*(?=')" $MISPPath/app/Config/config.php)
GnuPGPass=$(grep -o -P "(?<='password' => ').*(?=')" $MISPPath/app/Config/config.php)
# Create backup files
TmpDir="$(mktemp --tmpdir=$OutputDirName -d)"
cp $GnuPGHomeDir/* $TmpDir/
echo "copy of org images and other custom images"
cp -r $MISPPath/app/webroot/img/orgs $TmpDir/
cp -r $MISPPath/app/webroot/img/custom $TmpDir/
cp -r $MISPPath/app/files $TmpDir
#  MISP Config files
mkdir -p $TmpDir/Config
cp $MISPPath/app/Config/bootstrap.php $TmpDir/Config
cp $MISPPath/app/Config/config.php $TmpDir/Config
cp $MISPPath/app/Config/core.php $TmpDir/Config
cp $MISPPath/app/Config/database.php $TmpDir/Config

echo "MySQL Dump"
MySQLRUser=${MySQLRUser:-$MySQLUUser}
MySQLRPass=${MySQLRPass:-$MySQLUPass}
mysqldump --opt -u $MySQLRUser -p$MySQLRPass $MISPDB > $TmpDir/MISPbackupfile.sql
# Create compressed archive
cd $TmpDir
tar -zcf $OutputDirName/$OutputFileName-$(date "+%Y%m%d_%H%M%S").tar.gz *
cd -
rm -rf $TmpDir
echo 'MISP Backup Complete!!!'
