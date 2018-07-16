#!/bin/sh
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
# run ./misp-restore.sh  PATH_TO_ARCHIVE.tar.gz
# 
echo '-- Starting MISP restore process'

FILE=./misp-backup.conf

if [ -f $1 ];
then 
    BackupFile=$1
else
    echo 'Specify backup file by running ./misp-restore.sh  PATH_TO_ARCHIVE.tar.gz'
exit 1
fi

# Source configuration file
if [ -f $FILE ];
then
   echo "--- File $FILE exists."
   . $FILE
else
        echo "--- Config File $FILE does not exist. Please enter values manually"
        echo '--- Where would you like to decompress backup files?'
        echo 'Eg. /tmp'
        read OutputDirName
fi

# Decompress archive
BackupDir=$OutputDirName/$(basename -s ".tar.gz" $BackupFile)
mkdir $BackupDir
echo '--- Decompressing files'
tar zxf $1 -C $BackupDir

# Fill in any missing values with defaults
# MISP path - Required : MISP should be installed
MISPPath=${MISPPath:-$(locate MISP/app/webroot/index.php|sed 's/\/app\/webroot\/index\.php//')}


# database.php
MySQLUUser=$(grep -o -P "(?<='login' => ').*(?=')" $BackupDir/Config/database.php)
MySQLUPass=$(grep -o -P "(?<='password' => ').*(?=')" $BackupDir/Config/database.php)
MISPDB=$(grep -o -P "(?<='database' => ').*(?=')" $BackupDir/Config/database.php)
DB_Port=$(grep -o -P "(?<='port' => ).*(?=,)" $BackupDir/Config/database.php)
MISPDBHost=$(grep -o -P "(?<='host' => ').*(?=')" $BackupDir/Config/database.php)

# config.php
Salt=$(grep -o -P "(?<='salt' => ').*(?=')" $BackupDir/Config/config.php)
BaseURL=$(grep -o -P "(?<='baseurl' => ').*(?=')" $BackupDir/Config/config.php)
OrgName=$(grep -o -P "(?<='org' => ').*(?=')" $BackupDir/Config/config.php)
LogEmail=$(grep -o -P "(?<='email' => ').*(?=')" $BackupDir/Config/config.php|head -1)
AdminEmail=$(grep -o -P "(?<='contact' => ').*(?=')" $BackupDir/Config/config.php)
GnuPGEmail=$(sed -n -e '/GnuPG/,$p' $BackupDir/Config/config.php|grep -o -P "(?<='email' => ').*(?=')")
GnuPGHomeDir=$(grep -o -P "(?<='homedir' => ').*(?=')" $BackupDir/Config/config.php)
GnuPGPass=$(grep -o -P "(?<='password' => ').*(?=')" $BackupDir/Config/config.php)


# Restore backup files
echo "--- Copy of GnuPG files"
mkdir -p $GnuPGHomeDir
cp $BackupDir/*.gpg $GnuPGHomeDir/
cp $BackupDir/random_seed $GnuPGHomeDir/


echo "--- Copy of org and images and files"
cp -r $BackupDir/orgs $MISPPath/app/webroot/img/
cp -r $BackupDir/custom $MISPPath/app/webroot/img/
cp -r $BackupDir/files $MISPPath/app/


#  Restore MISP Config files
echo "--- Copy of app/Config files"
cp $BackupDir/Config/bootstrap.php $MISPPath/app/Config
cp $BackupDir/Config/config.php $MISPPath/app/Config
cp $BackupDir/Config/core.php $MISPPath/app/Config
cp $BackupDir/Config/database.php $MISPPath/app/Config

# Permissions
echo "--- Setting persmissions"
chown -R www-data:www-data /var/www/MISP
chmod -R 750 /var/www/MISP
chmod -R g+ws /var/www/MISP/app/tmp
chmod -R g+ws /var/www/MISP/app/files
chmod -R g+ws /var/www/MISP/app/files/scripts/tmp



# Restore DB
echo "--- Starting MySQL database Restore"
echo '---- Please enter your MySQL root account username'
read MySQLRUser

echo "---- Creating database and user if not exists with data found in MISP configuration files"
mysql -h $MISPDBHost -u $MySQLRUser -p -Bse "CREATE DATABASE IF NOT EXISTS $MISPDB ;\
    GRANT USAGE ON *.* TO '$MySQLUUser'@'localhost' IDENTIFIED BY '$MySQLUPass';\
    GRANT ALL PRIVILEGES ON $MISPDB.* TO '$MySQLUUser'@'localhost' ; \
    FLUSH PRIVILEGES;"

mysql -s -h $MISPDBHost -u $MySQLUUser -p$MySQLUPass $MISPDB < $BackupDir/MISPbackupfile.sql
    
rm -rf $BackupDir

echo "-- MISP Restore Complete!!! URL:  $BaseURL"
