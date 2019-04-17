#!/usr/bin/env bash

# Config section
PATH_TO_MISP='/var/www/MISP'
CAKE="$PATH_TO_MISP/app/Console/cake"
WWW_USER="www-data"
BASE_BRANCH="2.4"
BASE_REPO="github.com/MISP/MISP"
BACKUP_FILE="/tmp/MISP_pre_merge-$(date +%Y%m%d_%s).tar"
# Toggle whether a Backup should be performed. This is suggested if DB changes are made in the PR
BACKUP="0"
DATE=$(date +%Y%m%d)

re='^[0-9]+$'
if ! [[ $1 =~ $re ]]; then
  echo "PR needs to be an numerical ID, you entered: $1"
  exit 1
fi

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

# FIXME: Test Backup script
function backup() {
  sudo -H -u $WWW_USER tar cfp ${BACKUP_FILE} $PATH_TO_MISP
  cd $PATH_TO_MISP/tools/misp-backup
  sudo sh misp-backup.sh 2>&1 | tee misp-backup-${DATE}.log
  mispBackup_file=$(grep ^FullName misp-backup-${DATE}.log |cut -f2 -d:)
}

# FIXME: Test Restore script
function revert() {
  #mv $PATH_TO_MISP /tmp/
  sudo -H -u $WWW_USER rm -rf $PATH_TO_MISP
  sudo -H -u $WWW_USER tar -x -p -f ${BACKUP_FILE} -C /
  cd $PATH_TO_MISP/tools/misp-backup
  sudo sh misp-restore.sh $mispBackup_file
}

clear
if [ -w $PATH_TO_MISP ]; then
  echo "Good we can write to $PATH_TO_MISP"
else
  echo "We cannot write to $PATH_TO_MISP, make sure you can remove this directory as user: $USER"
  space
  echo "On developer install you can add the user: $USER to the $WWW_USER group. (or any other user the web server uses)"
  echo "And then simply: "
  echo "sudo find $PATH_TO_MISP -type d -exec chmod g+rwx {} \;"
  exit 1
fi

if [[ "$BACKUP" == "1" ]]; then
  backup
  if [[ "$?" != "0" ]]; then
    echo "Backup failed, please investigate manually."
    exit 1
  fi
fi

cd $PATH_TO_MISP
CURRENT_BRANCH=$(git symbolic-ref HEAD 2>/dev/null |cut -f 3 -d\/)

if [[ "$CURRENT_BRANCH" == "$BASE_BRANCH" ]]; then
  echo "Base and current branch match, continuing"
fi

CURRENT_ORIGIN=$(git remote -v |grep origin |fgrep $BASE_REPO |head -1)

if [ -z "$CURRENT_ORIGIN" ]; then
	echo "Your current origin is: $(git remote -v |head -1)"
  echo "But to test the branch you want to have an origin of: $BASE_REPO"
	exit 1
else
  echo "Performing git pull to make sure we are up to date..."
  sudo -H -u $WWW_USER git pull
  if [[ "$?" != "0" ]]; then
    echo "git pull failed, please investigate manually."
    exit 1
  fi

  sudo -H -u $WWW_USER git submodule update
  if [[ "$?" != "0" ]]; then
    echo "git submodule update failed, please investigate manually."
    exit 1
  fi
fi

sudo -H -u $WWW_USER git stash
sudo -H -u $WWW_USER git fetch origin pull/${1}/head:PR_${1}
sudo -H -u $WWW_USER git checkout PR_${1}

echo "Checked out PR #${1}"
space
echo "Press enter to see the git log of PR#${1}"
space
read
clear
sudo -H -u $WWW_USER git log --name-status HEAD^..HEAD
echo
space
echo -n "Do you want to revert to the 2.4 branch and delete the test branch (y/n) "
read REVERT

if [[ "$REVERT" == "y" ]]; then
  sudo -H -u $WWW_USER git checkout 2.4
  sudo -H -u $WWW_USER git branch -D PR_${1}
elif [[ "$BACKUP" == "1" ]]; then
  echo "Press enter to revert."
  echo "NB: You need your MYSQL Root password."
  read
  revert
  if [[ "$?" != "0" ]]; then
    echo "Backup failed, please investigate manually."
    exit 1
  fi
fi
