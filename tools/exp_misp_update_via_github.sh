#!/bin/bash
# Update script for MISP via GitHub

### /!\ WARNING /!\ This is WiP and not useable as of now! /!\ We have been warned.

## TODO, FIX:
# Must be launch in the parent directoy of your MISP installation

# VAR AFFECTATION
ver="1.1-20181025"
day=$(date +%Y%m%d)
root_folder="/var/www/"
misp_folder="/var/www/MISP"
backup_folder="/var/www/MISP_$day"
logfile="/var/log/git/misp_$day.log"
git_misp="https://github.com/MISP/MISP.git"
# Permissions of web user for Debian flavoured and standard Apache installs
web_perms_deb_u="www-data"
web_perms_deb_g="www-data"

# Permissions of web user for RedHat flavoured and standard Apache installs
web_perms_rh_u="root"
web_perms_rh_g="apache"

if [ ! -d /var/log/git ]; then
    mkdir -p /var/log/git/
    cd ${misp_folder}
    # The following git config is to be able to handle larger files, as per: https://stackoverflow.com/questions/2702731/git-fails-when-pushing-commit-to-github
    git config http.postBuffer 524288000
fi

if [ -e "/usr/bin/lsb_release" ]; then
    flavour="$(lsb_release -s -i)"
    if [ "${flavour}" == "Debian" || "${flavour}" == "Ubuntu" ]; then
       web_perms_u=${web_perms_deb_u}
       web_perms_g=${web_perms_deb_g}
       debian=1
    fi
fi

if [ -e "/bin/rpm" ]; then
    if [ ! -z $(rpm -qa centos-release) ]; then
        flavour=$(rpm -q centos-release)
        web_perms_u=${web_perms_rh_u}
        web_perms_g=${web_perms_rh_g}
        scl_rh="rh-php70"
        redhat=1
    elif [ ! -z $(rpm -qa redhat-release-server) ]; then
        flavour=$(rpm -q redhat-release-server)
        web_perms_u=${web_perms_rh_u}
        web_perms_g=${web_perms_rh_g}
        scl_rh="rh-php70"
        redhat=1
    else
        echo "You have neither a RedHat or CentOS flavoured OS. Set the permissions of the web user by hand."
        exit 1
    fi
fi

# DEFINE FUNCTIONS
function log_date () {
	date "+%Y-%m-%d %H:%M:%S [%z %Z]"
}

function apply_permissions () {
	chown -R ${web_perms_u}:${web_perms_g} ${misp_folder}
	find ${misp_folder} -type d -exec chmod g=rx {} \;
	chmod -R g+r,o= ${misp_folder}
	chown ${web_perms_g}:${web_perms_g} ${misp_folder}/app/Config/config.php
	chown ${web_perms_g}:${web_perms_g} ${misp_folder}/app/files
	chown ${web_perms_g}:${web_perms_g} ${misp_folder}/app/files/terms
	chown ${web_perms_g}:${web_perms_g} ${misp_folder}/app/files/scripts/tmp
	chown ${web_perms_g}:${web_perms_g} ${misp_folder}/app/Plugin/CakeResque/tmp
	chown -R ${web_perms_g}:${web_perms_g} ${misp_folder}/app/tmp
	chown -R ${web_perms_g}:${web_perms_g} ${misp_folder}/app/webroot/img/orgs
	chown -R ${web_perms_g}:${web_perms_g} ${misp_folder}/app/webroot/img/custom
	chown -R ${web_perms_g}:${web_perms_g} ${misp_folder}/.gnupg
	chmod 755 ${misp_folder}/app/Console/worker/start.sh
	chown ${web_perms_g}:${web_perms_g} ${misp_folder}/app/Console/worker/start.sh
	chcon -t httpd_sys_rw_content_t ${misp_folder}/app/Config/config.php
	chcon -t httpd_sys_rw_content_t ${misp_folder}/app/files
	chcon -t httpd_sys_rw_content_t ${misp_folder}/app/files/terms
	chcon -t httpd_sys_rw_content_t ${misp_folder}/app/files/scripts/tmp
	chcon -t httpd_sys_rw_content_t ${misp_folder}/app/Plugin/CakeResque/tmp
	chcon -R -t httpd_sys_rw_content_t ${misp_folder}/app/tmp
	chcon -R -t httpd_sys_rw_content_t ${misp_folder}/app/webroot/img/orgs
	chcon -R -t httpd_sys_rw_content_t ${misp_folder}/app/webroot/img/custom
}

# CHECKING PRIVILEGES
whoami=$(whoami)
if [[ $whoami != "root" ]]; then
	echo "[ERROR] Please be sure you have root privileges to run the script."
	exit 1
fi

# CHECKING SCRIPT INTEGRITY
md5=$(md5sum ${PWD}/$0 | grep -Eio "[a-f0-9]{32}")
sha1=$(sha1sum $PWD/$0 | grep -Eio "[a-f0-9]{40}")
echo "Script version is: $ver"
echo "Script MD5 is: $md5"
echo "Script SHA-1 is: $sha1"
echo -n "Do you want to continue [Y/n]"
read -e reply
if [[ $reply =~ ^[Nn]$ ]]; then
	echo "Exiting..."
	exit 0 
elif [[ $reply =~ ^[YyOo]$ ]]; then
        sleep 0
else
	echo "[ERROR] Unexpected answer. Exiting..."
	exit 1
fi

# STOP WORKERS
(
echo -n "Please, login to MISP interface (with admin privileges) and stop all workers (Administration / Server Settings / \"Workers\" tab then click the trash buttons): "; log_date
echo "Press a key to continue or CTRL+C to cancel..."
read -e wait

# CHECK GIT STATUS BEFORE RUNNING UPDATE
cd $misp_folder
echo -n "--> Checking for uncommited files: "; log_date
git status | grep "nothing to commit" >> /dev/null
OutStatus=$?
if [ $OutStatus == 0 ]; then
	echo -n "    Working directory is clean: "; log_date; echo -e "\r\n"
else
	echo -n "    [ERROR] It seems that your local repository isn't clean or is waiting for a commit. Try 'git status "; log_date; echo -e "\r\n"
	exit 1
fi

# BACKUP EXISTANT CONFIGURATION
echo -n "--> Backuping existent files: "; log_date
echo -ne "    Current release is: "; for verold in `cat $misp_folder/VERSION.json | grep -Po "\d{1,2},?" | sed -e 's/,/\./g'`; do echo -ne $verold; done; echo ""
echo -ne "    Current commit is: "; cat $misp_folder/.git/refs/heads/*
mkdir -p $backup_folder
cp -rf $misp_folder $backup_folder
OutBackup=$?
if [ $OutBackup == 0 ]; then
	echo -n "    [*] Backup finished successfully: "; log_date; echo -e "\r\n"
else
	echo -n "    [ERROR] An error occurred during backup: "; log_date; echo -e "\r\n"
	exit 1
fi

# PULL THE LAST COMMIT 
echo -n "--> Retrieving last MISP release: "; log_date
git pull origin 2.4
OutPull=$?
if [ $OutPull != 0 ]; then
	echo -n "    [*] An error occurred during retrieving last release: "; log_date
	echo -n "    [*] Trying to find a workaround: "; log_date
	git status | grep "both modified" >> /dev/null
	OutWorkaround=$?
	if [ $OutWorkaround == 0 ]; then
		echo -n "    A potential workaround has been found to resolve merge conflicts: "; log_date
		git add PyMISP app/webroot/css/main.css app/Lib/cakephp app/files/misp-galaxy app/files/taxonomies app/files/warninglists
		OutAdd=$?
		if [ $OutAdd != 0 ]; then
			echo -n "    [*] Workaround failed: "; log_date
			echo -n "    [*] Rollback is in progress: "; log_date
			rm -rf $misp_folder
			cp -rf $backup_folder $root_folder/MISP
			mv -f $misp_folder/MISP/* $misp_folder
			mv -f $misp_folder/MISP/.* $misp_folder
			rm -rf $misp_folder/MISP
			echo -ne "    [*] Rollback applied: "; log_date; echo -e "\r\n"
			rm -rf $backup_folder
			apply_permissions
		fi
	else
		echo -n "    [*] No workaround has been found: "; log_date
		echo -n "    [*] Rollback is in progress: "; log_date
		rm -rf $misp_folder
		cp -rf $backup_folder $root_folder/MISP
		mv -f $misp_folder/MISP/* $misp_folder
		mv -f $misp_folder/MISP/.* $misp_folder
		rm -rf $misp_folder/MISP
		echo -ne "    [*] Rollback applied: "; log_date; echo -e "\r\n"
		rm -rf $backup_folder
		apply_permissions
	fi
elif [ $OutPull == 0 ]; then
	git submodule update --init --force
	echo -ne "    Release installed: "; for vernew in `cat $misp_folder/VERSION.json | grep -Po "\d{1,2},?" | sed -e 's/,/\./g'`; do echo -ne $vernew; done; echo ""
	echo -ne "    Commit installed: "; cat $misp_folder/.git/refs/heads/*
	echo -n "    [*] Last release successfully retrieve: "; log_date
	tar -czvf /var/www/backup_MISP_$day.tar.gz $backup_folder
	apply_permissions
	cd $misp_folder/app && php composer.phar update
else
	echo -n "    [ERROR] An unexepected error occured: "; log_date
	exit 1
fi

# RESTARTING SERVICES
if [ ${redhat} == "1" ]; then 
    echo -n "--> Restarting Database server: "; log_date
    systemctl restart mariadb.service; systemctl status mariadb.service
    echo -n "--> Restarting Apache server: "; log_date
    systemctl restart httpd.service; systemctl status httpd.service
    echo -n "--> Restarting PHP service: "; log_date
    systemctl restart rh-php56-php-fpm.service; systemctl status rh-php56-php-fpm.service
    echo -n "--> Restarting MISP Workers: "; log_date
    su -s /bin/bash ${web_perms_g} -c '/usr/bin/scl enable ${rh-scl-php} ${misp_folder}/app/Console/worker/start.sh'
    echo -n "--> Restarting firewalld service: "; log_date
    systemctl restart firewalld.service; systemctl status firewalld.service
elif [ ${debian} == "1"]; then
    echo "Restart Services"
fi

# RE-APPLYING PERMISSIONS DUE TO SOME BUGS SOMETIMES
apply_permissions

) 2>&1 | tee -a $logfile
git commit -m "Update $vernew ==> OK"
#EOF
