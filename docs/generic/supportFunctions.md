```bash
# <snippet-begin 0_support-functions.sh>
# Leave empty for NO debug messages, if run with set -x or bash -x it will enable DEBUG by default
DEBUG=

case "$-" in
  *x*)  NO_PROGRESS=1; DEBUG=1 ;;
  *)    NO_PROGRESS=0 ;;
esac

## Function Section ##

## Usage of this script
usage () {
  if [ "$0" == "bash" ]; then
    WEB_INSTALL=1
    SCRIPT_NAME="Web Installer Command"
  else
    SCRIPT_NAME=$0
  fi

  exec &> /dev/tty
  space
  echo -e "Please specify what type of ${LBLUE}MISP${NC} setup you want to install."
  space
  echo -e "${SCRIPT_NAME} -c | Install ONLY ${LBLUE}MISP${NC} Core"                   # core
  echo -e "                -M | ${LBLUE}MISP${NC} modules"        # modules
  echo -e "                -D | ${LBLUE}MISP${NC} dashboard"      # dashboard
  echo -e "                -V | Viper"                            # viper
  echo -e "                -m | Mail 2 ${LBLUE}MISP${NC}"         # mail2
  echo -e "                -S | Experimental ssdeep correlations" # ssdeep
  echo -e "                -A | Install ${YELLOW}all${NC} of the above" # all
  space
  echo -e "                -C | Only do ${YELLOW}pre-install checks and exit${NC}" # pre
  space
  echo -e "                -u | Do an unattanded Install, no questions asked"      # UNATTENDED
  echo -e "${HIDDEN}       -U | Attempt and upgrade of selected item${NC}"         # UPGRADE
  echo -e "${HIDDEN}       -N | Nuke this MISP Instance${NC}"                      # NUKE
  echo -e "${HIDDEN}       -f | Force test install on current Ubuntu LTS schim, add -B for 18.04 -> 18.10, or -BB 18.10 -> 19.10)${NC}" # FORCE
  echo -e "Options can be combined: ${SCRIPT_NAME} -c -V -D # Will install Core+Viper+Dashboard"
  space
  echo -e "Recommended is either a barebone MISP install (ideal for syncing from other instances) or"
  echo -e "MISP + modules - ${SCRIPT_NAME} -c -M"
  space
}

# Check if element is contained in array
containsElement () {
  local e match="$1"
  shift
  for e; do [[ "$e" == "$match" ]] && return 0; done
  return 1
}

checkOpt () {
  # checkOpt feature
  containsElement $1 "${options[@]}"
}

setOpt () {
  options=()
  for o in $@; do 
    case "$o" in
      ("-c") echo "core"; CORE=1 ;;
      ("-V") echo "viper"; VIPER=1 ;;
      ("-M") echo "modules"; MODULES=1 ;;
      ("-D") echo "dashboard"; DASHBOARD=1 ;;
      ("-m") echo "mail2"; MAIL2=1 ;;
      ("-S") echo "ssdeep"; SSDEEP=1 ;;
      ("-A") echo "all"; ALL=1 ;;
      ("-C") echo "pre"; PRE=1 ;;
      ("-U") echo "upgrade"; UPGRADE=1 ;;
      ("-N") echo "nuke"; NUKE=1 ;;
      ("-u") echo "unattended"; UNATTENDED=1 ;;
      ("-f") echo "force"; FORCE=1 ;;
      (*) echo "$o is not a valid argument"; exit 1 ;;
    esac
  done
}

# Extract debian flavour
checkFlavour () {
  if [ -z $(which lsb_release) ]; then
    checkAptLock
    sudo apt install lsb-release dialog -y
  fi

  FLAVOUR=$(lsb_release -s -i |tr [A-Z] [a-z])
  if [ FLAVOUR == "ubuntu" ]; then
    RELEASE=$(lsb_release -s -r)
    debug "We detected the following Linux flavour: ${YELLOW}$(tr '[:lower:]' '[:upper:]' <<< ${FLAVOUR:0:1})${FLAVOUR:1} ${RELEASE}${NC}"
  else
    debug "We detected the following Linux flavour: ${YELLOW}$(tr '[:lower:]' '[:upper:]' <<< ${FLAVOUR:0:1})${FLAVOUR:1}${NC}"
  fi
}

# Extract manufacturer
checkManufacturer () {
  if [ -z $(which dmidecode) ]; then
    checkAptLock
    sudo apt install dmidecode -qy
  fi
  MANUFACTURER=$(sudo dmidecode -s system-manufacturer)
  echo $MANUFACTURER
}

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

# Spinner so the user knows something is happening
spin()
{
  if [[ "$NO_PROGRESS" == "1" ]]; then
    return
  fi
  spinner="/|\\-/|\\-"
  while :
  do
    for i in `seq 0 7`
    do
      echo -n "${spinner:$i:1}"
      echo -en "\010"
      sleep 0.$i
    done
  done
}

# Progress bar
progress () {
  if [[ "$NO_PROGRESS" == "1" ]]; then
    return
  fi
  bar="#"
  if [[ $progress -ge 100 ]]; then
    echo -ne "#####################################################################################################  (100%)\r"
    return
  fi
  progress=$[$progress+$1]
  for p in $(seq 1 $progress); do
    bar+="#"
    echo -ne "$bar  ($p%)\r"
  done
  echo -ne '\n'
}

# Check locale
checkLocale () {
  debug "Checking Locale"
  # If locale is missing, generate and install a common UTF-8
  if [[ ! -f /etc/default/locale || $(wc -l /etc/default/locale| cut -f 1 -d\ ) == "1" ]]; then
    checkAptLock
    sudo DEBIAN_FRONTEND=noninteractive apt install locales -qy
    sudo sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/g' /etc/locale.gen
    sudo locale-gen en_US.UTF-8
    sudo update-locale LC_ALL=en_US.UTF-8 LANG=en_US.UTF-8
  fi
}

# Simple function to check command exit code
checkFail () {
  if [[ $2 -ne 0 ]]; then
    echo "iAmError: $1"
    echo "The last command exited with error code: $2"
    exit $2
  fi
}

# Check if misp user is present and if run as root
checkID () {
  debug "Checking if run as root and $MISP_USER is present"
  if [[ $EUID == 0 ]]; then
    echo "This script cannot be run as a root"
    exit 1
  elif [[ $(id $MISP_USER >/dev/null; echo $?) -ne 0 ]]; then
    if [[ "$UNATTENDED" != "1" ]]; then 
      echo "There is NO user called '$MISP_USER' create a user '$MISP_USER' (y) or continue as $USER (n)? (y/n) "
      read ANSWER
      ANSWER=$(echo $ANSWER |tr [A-Z] [a-z])
    else
      ANSWER="y"
    fi

    if [[ $ANSWER == "y" ]]; then
      sudo useradd -s /bin/bash -m -G adm,cdrom,sudo,dip,plugdev,www-data,staff $MISP_USER
      echo $MISP_USER:$MISP_PASSWORD | sudo chpasswd
      echo "User $MISP_USER added, password is: $MISP_PASSWORD"
    elif [[ $ANSWER == "n" ]]; then
      echo "Using $USER as install user, hope that is what you want."
      echo -e "${RED}Adding $USER to groups www-data and staff${NC}"
      MISP_USER=$USER
      sudo adduser $MISP_USER staff
      sudo adduser $MISP_USER www-data
    else
      echo "yes or no was asked, try again."
      sudo adduser $MISP_USER staff
      sudo adduser $MISP_USER www-data
      exit 1
    fi
  else
    echo "User ${MISP_USER} exists, skipping creation"
    echo -e "${RED}Adding $MISP_USER to groups www-data and staff${NC}"
    sudo adduser $MISP_USER staff
    sudo adduser $MISP_USER www-data
  fi
}

# pre-install check to make sure what we will be installing on, is ready and not a half installed system
preInstall () {
# preInstall needs to be able to be called before ANY action. Install/Upgrade/AddTool
# Pre install wants to be the place too where the following is checked and set via ENV_VAR:
# Check if composer is installed and functioning
# Check if misp db is installed (API call would confirm that the DB indeed works)
# Check apache config (Maybe try to talk to the server via api, this would confirm quite a lot)
# Check if workers are running/installed, maybe kick them if they are not
# /var/www/MISP/app/Config/[bootstrap,databases,core,config].php exists
# /var/www/MISP perms are correct (for $SUDO_WWW useage)
#

  # Check if $PATH_TO_MISP exists and is writable by $WWW_USER
  [[ -d "$PATH_TO_MISP" ]] && PATH_TO_MISP_EXISTS=1 && echo "$PATH_TO_MISP exists"

  # .git exists and git is working for $WWW_USER
  [[ -d "$PATH_TO_MISP/.git" ]] && PATH_TO_GIT_EXISTS=1 && echo "$PATH_TO_MISP/.git exists" && cd $PATH_TO_MISP && $SUDO_WWW git status

  # .gnupg exists and working correctly
  [[ -d "$PATH_TO_MISP/.gnupg" ]] && PATH_TO_GNUPG_EXISTS=1 && echo "$PATH_TO_MISP/.gnupg exists"


  # Extract username, password and dbname
  ##cat database.php |grep -v // |grep -e database -e login -e password |tr -d \' |tr -d \ |tr -d , |tr -d \>
  DBPASSWORD_MISP=$(cat database.php |grep -v // |grep -e password |tr -d \' |tr -d \ |tr -d , |tr -d \> |cut -f 2 -d=)
  DBUSER_MISP=$(cat database.php |grep -v // |grep -e login |tr -d \' |tr -d \ |tr -d , |tr -d \> |cut -f 2 -d=)
  DBNAME=$(cat database.php |grep -v // |grep -e database |tr -d \' |tr -d \ |tr -d , |tr -d \> |cut -f 2 -d=)
  AUTH_KEY=$(mysql --disable-column-names -B  -u $DBUSER_MISP -p"$DBPASSWORD_MISP" $DBNAME -e 'SELECT authkey FROM users WHERE role_id=1 LIMIT 1')

  # Check if db exists
  [[ -d "/var/lib/mysql/$DBNAME" ]] && MISP_DB_DIR_EXISTS=1 && echo "/var/lib/mysql/$DBNAME exists"

  echo -e "${RED}Place-holder, not implemented yet.${NC}"
  exit
}

# Upgrade function
upgrade () {
  headerJSON="application/json"
  Acc="Accept:"
  Autho="Authorization:"
  CT="Content-Type:"
  MISP_BASEURL="https://127.0.0.1"
  cd $PATH_TO_MISP/app ; $SUDO_WWW php composer.phar update $SUDO_WWW php composer.phar self-update

  for URN in $(echo "galaxies warninglists noticelists objectTemplates taxonomies"); do
    curl --header "$Autho $AUTH_KEY" --header "$Acc $headerJSON" --header "$CT $headerJSON" -k -X POST $MISP_BASEURL/$URN/update
  done

  echo -e "${RED}Place-holder, not implemented yet.${NC}"
  exit
}

# check is /usr/local/src is RW by misp user
checkUsrLocalSrc () {
  echo ""
  if [[ -e /usr/local/src ]]; then
    WRITEABLE=$(sudo -H -u $MISP_USER touch /usr/local/src 2> /dev/null ; echo $?)
    if [[ "$WRITEABLE" == "0" ]]; then
      echo "Good, /usr/local/src exists and is writeable as $MISP_USER"
    else
      # TODO: The below might be shorter, more elegant and more modern
      #[[ -n $KALI ]] || [[ -n $UNATTENDED ]] && echo "Just do it" 
      if [ "$KALI" == "1" -o "$UNATTENDED" == "1" ]; then
        ANSWER="y"
      else
        space
        echo "/usr/local/src need to be writeable by $MISP_USER for misp-modules, viper etc."
        echo -n "Permission to fix? (y/n) "
        read ANSWER
        ANSWER=$(echo $ANSWER |tr [A-Z] [a-z])
        space
      fi
      if [ "$ANSWER" == "y" ]; then
        sudo chmod 2775 /usr/local/src
        sudo chown root:staff /usr/local/src
      fi
    fi
  else
    echo "/usr/local/src does not exist, creating."
    mkdir /usr/local/src
    sudo chmod 2775 /usr/local/src
    sudo chown root:staff /usr/local/src
  fi
}

kaliSpaceSaver () {
  # Future function in case Kali overlay on LiveCD is full
  echo "${RED}Not implement${NC}"
}

# Because Kali is l33t we make sure we run as root
kaliOnRootR0ckz () {
  if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
  elif [[ $(id $MISP_USER >/dev/null; echo $?) -ne 0 ]]; then
    useradd -s /bin/bash -m -G adm,cdrom,sudo,dip,plugdev,www-data,staff $MISP_USER
    echo $MISP_USER:$MISP_PASSWORD | chpasswd
  else
    # TODO: Make sure we consider this further down the road
    echo "User ${MISP_USER} exists, skipping creation"
  fi
}

setBaseURL () {
  debug "Setting Base URL"
  CONN=$(ip -br -o -4 a |grep UP |head -1 |tr -d "UP")
  IFACE=`echo $CONN |awk {'print $1'}`
  IP=`echo $CONN |awk {'print $2'}| cut -f1 -d/`
  if [[ $(checkManufacturer) != "innotek GmbH" ]]; then
    debug "We guess that this is a physical machine and cannot possibly guess what the MISP_BASEURL might be."
    if [[ "$UNATTENDED" != "1" ]]; then 
      echo "You can now enter your own MISP_BASEURL, if you wish to NOT do that, the MISP_BASEURL will be empty, which will work, but ideally you configure it afterwards."
      echo "Do you want to change it now? (y/n) "
      read ANSWER
      ANSWER=$(echo $ANSWER |tr [A-Z] [a-z])
      if [[ "$ANSWER" == "y" ]]; then
        if [[ ! -z $IP ]]; then
          echo "It seems you have an interface called $IFACE UP with the following IP: $IP - FYI"
          echo "Thus your Base URL could be: https://$IP"
        fi
        echo "Please enter the Base URL, e.g: 'https://example.org'"
        echo ""
        echo -n "Enter Base URL: "
        read MISP_BASEURL
      else
        MISP_BASEURL='""'
      fi
    else
        MISP_BASEURL="https://misp.local"
        # Webserver configuration
        FQDN='misp.local'
    fi
  elif [[ $KALI == "1" ]]; then
    MISP_BASEURL="https://misp.local"
    # Webserver configuration
    FQDN='misp.local'
  else
    MISP_BASEURL='https://localhost:8443'
    # Webserver configuration
    FQDN='localhost.localdomain'
  fi
}

# Test and install software RNG
installRNG () {
  sudo modprobe tpm-rng 2> /dev/null
  if [ "$?" -eq "0" ]; then 
    echo tpm-rng | sudo tee -a /etc/modules
  fi
  checkAptLock
  sudo apt install -qy rng-tools # This might fail on TPM grounds, enable the security chip in your BIOS
  sudo service rng-tools start

  if [ "$?" -eq "1" ]; then 
    sudo apt purge -qy rng-tools
    sudo apt install -qy haveged
    sudo /etc/init.d/haveged start
  fi
}

# Kali upgrade
kaliUpgrade () {
  debug "Running various Kali upgrade tasks"
  sudo apt update
  checkAptLock
  sudo DEBIAN_FRONTEND=noninteractive apt install --only-upgrade bash libc6 -y
  sudo DEBIAN_FRONTEND=noninteractive apt autoremove -y
}

# Disables sleep
disableSleep () {
  debug "Disabling sleep etc if run from a Laptop as the install might take some time…" > /dev/tty
  gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-ac-timeout 0 2> /dev/null
  gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-battery-timeout 0 2> /dev/null
  gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-battery-type nothing 2> /dev/null
  gsettings set org.gnome.desktop.screensaver lock-enabled false 2> /dev/null
  gsettings set org.gnome.desktop.screensaver idle-activation-enabled false 2> /dev/null

  setterm -blank 0 -powersave off -powerdown 0
  xset s 0 0 2> /dev/null
  xset dpms 0 0 2> /dev/null
  xset dpms force off
  xset s off 2> /dev/null
  service sleepd stop
  kill $(lsof | grep 'sleepd' | awk '{print $2}')
  checkAptLock
}

# Remove alias if present
if [[ $(type -t checkAptLock) == "alias" ]]; then unalias checkAptLock; fi
# Simple function to make sure APT is not locked
checkAptLock () {
  SLEEP=3
  while [ "$DONE" != "0" ]; do
    sudo apt-get check 2> /dev/null > /dev/null && DONE=0
    echo -e "${LBLUE}apt${NC} is maybe ${RED}locked${NC}, waiting ${RED}$SLEEP${NC} seconds." > /dev/tty
    sleep $SLEEP
    SLEEP=$[$SLEEP+3]
  done
  unset DONE
}

# <snippet-begin 0_installDepsPhp70.sh>
# Install Php 7.0 dependencies
installDepsPhp70 () {
  debug "Installing PHP 7.0 dependencies"
  PHP_ETC_BASE=/etc/php/7.0
  PHP_INI=${PHP_ETC_BASE}/apache2/php.ini
  sudo apt update
  sudo apt install -qy \
  libapache2-mod-php \
  php php-cli \
  php-dev \
  php-json php-xml php-mysql php-opcache php-readline php-mbstring \
  php-pear \
  php-redis php-gnupg

  for key in upload_max_filesize post_max_size max_execution_time max_input_time memory_limit
  do
      sudo sed -i "s/^\($key\).*/\1 = $(eval echo \${$key})/" $PHP_INI
  done
}
# <snippet-end 0_installDepsPhp70.sh>

# <snippet-begin 0_installDepsPhp73.sh>
# Install Php 7.3 deps
installDepsPhp73 () {
  debug "Installing PHP 7.3 dependencies"
  PHP_ETC_BASE=/etc/php/7.3
  PHP_INI=${PHP_ETC_BASE}/apache2/php.ini
  sudo apt update
  checkAptLock
  sudo apt install -qy \
  libapache2-mod-php7.3 \
  php7.3 php7.3-cli \
  php7.3-dev \
  php7.3-json php7.3-xml php7.3-mysql php7.3-opcache php7.3-readline php7.3-mbstring \
  php-pear \
  php-redis php-gnupg
}
# <snippet-end 0_installDepsPhp73.sh>

# Installing core dependencies
installDeps () {
  debug "Installing core dependencies"
  checkAptLock
  sudo apt update
  sudo apt install -qy etckeeper
  # Skip dist-upgrade for now, pulls in 500+ updated packages
  #sudo apt -y dist-upgrade
  gitMail=$(git config --global --get user.email ; echo $?)
  if [ "$?" -eq "1" ]; then 
    git config --global user.email "root@kali.lan"
  fi
  gitUser=$(git config --global --get user.name ; echo $?)
  if [ "$?" -eq "1" ]; then 
    git config --global user.name "Root User"
  fi

  [[ -n $KALI ]] || [[ -n $UNATTENDED ]] && sudo DEBIAN_FRONTEND=noninteractive apt install -qy postfix || sudo apt install -qy postfix

  sudo apt install -qy \
  curl gcc git gnupg-agent make openssl redis-server neovim unzip zip libyara-dev python3-yara python3-redis python3-zmq sqlite3 \
  mariadb-client \
  mariadb-server \
  apache2 apache2-doc apache2-utils \
  python3-dev python3-pip libpq5 libjpeg-dev libfuzzy-dev ruby asciidoctor \
  libxml2-dev libxslt1-dev zlib1g-dev python3-setuptools expect

  installRNG
}

# On Kali, the redis start-up script is broken. This tries to fix it.
fixRedis () {
  # As of 20190124 redis-server init.d scripts are broken and need to be replaced
  sudo mv /etc/init.d/redis-server /etc/init.d/redis-server_`date +%Y%m%d`

  echo '#! /bin/sh
### BEGIN INIT INFO
# Provides:		redis-server
# Required-Start:	$syslog
# Required-Stop:	$syslog
# Should-Start:		$local_fs
# Should-Stop:		$local_fs
# Default-Start:	2 3 4 5
# Default-Stop:		0 1 6
# Short-Description:	redis-server - Persistent key-value db
# Description:		redis-server - Persistent key-value db
### END INIT INFO

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
DAEMON=/usr/bin/redis-server
DAEMON_ARGS=/etc/redis/redis.conf
NAME=redis-server
DESC=redis-server
PIDFILE=/var/run/redis.pid

test -x $DAEMON || exit 0
test -x $DAEMONBOOTSTRAP || exit 0

set -e

case "$1" in
  start)
	echo -n "Starting $DESC: "
	touch $PIDFILE
	chown redis:redis $PIDFILE
	if start-stop-daemon --start --quiet --umask 007 --pidfile $PIDFILE --chuid redis:redis --exec $DAEMON -- $DAEMON_ARGS
	then
		echo "$NAME."
	else
		echo "failed"
	fi
	;;
  stop)
	echo -n "Stopping $DESC: "
	if start-stop-daemon --stop --retry 10 --quiet --oknodo --pidfile $PIDFILE --exec $DAEMON
	then
		echo "$NAME."
	else
		echo "failed"
	fi
	rm -f $PIDFILE
	;;

  restart|force-reload)
	${0} stop
	${0} start
	;;
  *)
	echo "Usage: /etc/init.d/$NAME {start|stop|restart|force-reload}" >&2
	exit 1
	;;
esac

exit 0' | sudo tee /etc/init.d/redis-server
  sudo chmod 755 /etc/init.d/redis-server
  sudo /etc/init.d/redis-server start
}

# generate MISP apache conf
genApacheConf () {
  echo "<VirtualHost _default_:80>
          ServerAdmin admin@localhost.lu
          ServerName misp.local

          Redirect permanent / https://misp.local

          LogLevel warn
          ErrorLog /var/log/apache2/misp.local_error.log
          CustomLog /var/log/apache2/misp.local_access.log combined
          ServerSignature Off
  </VirtualHost>

  <VirtualHost _default_:443>
          ServerAdmin admin@localhost.lu
          ServerName misp.local
          DocumentRoot $PATH_TO_MISP/app/webroot

          <Directory $PATH_TO_MISP/app/webroot>
                  Options -Indexes
                  AllowOverride all
  		            Require all granted
                  Order allow,deny
                  allow from all
          </Directory>

          SSLEngine On
          SSLCertificateFile /etc/ssl/private/misp.local.crt
          SSLCertificateKeyFile /etc/ssl/private/misp.local.key
  #        SSLCertificateChainFile /etc/ssl/private/misp-chain.crt

          LogLevel warn
          ErrorLog /var/log/apache2/misp.local_error.log
          CustomLog /var/log/apache2/misp.local_access.log combined
          ServerSignature Off
          Header set X-Content-Type-Options nosniff
          Header set X-Frame-Options DENY
  </VirtualHost>" | tee /etc/apache2/sites-available/misp-ssl.conf
}

# Add git pull update mechanism to rc.local - TODO: Make this better
gitPullAllRCLOCAL () {
  sed -i -e '$i \git_dirs="/usr/local/src/misp-modules/ /var/www/misp-dashboard /usr/local/src/faup /usr/local/src/mail_to_misp /usr/local/src/misp-modules /usr/local/src/viper /var/www/misp-dashboard"\n' /etc/rc.local
  sed -i -e '$i \for d in $git_dirs; do\n' /etc/rc.local
  sed -i -e '$i \    echo "Updating ${d}"\n' /etc/rc.local
  sed -i -e '$i \    cd $d && sudo git pull &\n' /etc/rc.local
  sed -i -e '$i \done\n' /etc/rc.local
}

# Composer on php 7.0 does not need any special treatment the provided phar works well
alias composer70='composer72'

# Composer on php 7.2 does not need any special treatment the provided phar works well
composer72 () {
  cd $PATH_TO_MISP/app
  mkdir /var/www/.composer ; chown www-data:www-data /var/www/.composer
  $SUDO_WWW php composer.phar require kamisama/cake-resque:4.1.2
  $SUDO_WWW php composer.phar config vendor-dir Vendor
  $SUDO_WWW php composer.phar install
}

# Composer on php 7.3 needs a recent version of composer.phar
composer73 () {
  cd $PATH_TO_MISP/app
  mkdir /var/www/.composer ; chown www-data:www-data /var/www/.composer
  # Update composer.phar
  # If hash changes, check here: https://getcomposer.org/download/ and replace with the correct one
  # Current Sum for: v1.8.3
  SHA384_SUM='48e3236262b34d30969dca3c37281b3b4bbe3221bda826ac6a9a62d6444cdb0dcd0615698a5cbe587c3f0fe57a54d8f5'
  sudo -H -u www-data php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
  sudo -H -u www-data php -r "if (hash_file('SHA384', 'composer-setup.php') === '$SHA384_SUM') { echo 'Installer verified'; } else { echo 'Installer corrupt'; unlink('composer-setup.php'); exit(137); } echo PHP_EOL;"
  checkFail "composer.phar checksum failed, please investigate manually. " $?
  sudo -H -u www-data php composer-setup.php
  sudo -H -u www-data php -r "unlink('composer-setup.php');"
  $SUDO_WWW php composer.phar require kamisama/cake-resque:4.1.2
  $SUDO_WWW php composer.phar config vendor-dir Vendor
  $SUDO_WWW php composer.phar install
}

# Enable various core services
enableServices () {
    update-rc.d mysql enable
    update-rc.d apache2 enable
    update-rc.d redis-server enable
}

# Generate rc.local
genRCLOCAL () {
  if [ ! -e /etc/rc.local ]; then
      echo '#!/bin/sh -e' | tee -a /etc/rc.local
      echo 'exit 0' | tee -a /etc/rc.local
      chmod u+x /etc/rc.local
  fi

  sed -i -e '$i \echo never > /sys/kernel/mm/transparent_hugepage/enabled\n' /etc/rc.local
  sed -i -e '$i \echo 1024 > /proc/sys/net/core/somaxconn\n' /etc/rc.local
  sed -i -e '$i \sysctl vm.overcommit_memory=1\n' /etc/rc.local
}

# Run PyMISP tests
runTests () {
  sudo sed -i -E "s~url\ =\ (.*)~url\ =\ '${MISP_BASEURL}'~g" $PATH_TO_MISP/PyMISP/tests/testlive_comprehensive.py
  sudo sed -i -E "s/key\ =\ (.*)/key\ =\ '${AUTH_KEY}'/g" $PATH_TO_MISP/PyMISP/tests/testlive_comprehensive.py
  sudo chown -R $WWW_USER:$WWW_USER $PATH_TO_MISP/PyMISP/

  sudo -H -u $WWW_USER sh -c "cd $PATH_TO_MISP/PyMISP && git submodule foreach git pull origin master"
  sudo -H -u $WWW_USER ${PATH_TO_MISP}/venv/bin/pip install -e $PATH_TO_MISP/PyMISP/.[fileobjects,neo,openioc,virustotal,pdfexport]
  sudo -H -u $WWW_USER git clone https://github.com/viper-framework/viper-test-files.git $PATH_TO_MISP/PyMISP/tests/viper-test-files
  sudo -H -u $WWW_USER sh -c "cd $PATH_TO_MISP/PyMISP && ${PATH_TO_MISP}/venv/bin/python tests/testlive_comprehensive.py"
}

# Nuke the install, meaning remove all MISP data but no packages, this makes testing the installer faster
nuke () {
  echo -e "${RED}YOU ARE ABOUT TO DELETE ALL MISP DATA! Sleeping 10, 9, 8...${NC}"
  sleep 10
  sudo rm -rvf /usr/local/src/{misp-modules,viper,mail_to_misp,LIEF,faup}
  sudo rm -rvf /var/www/MISP
  sudo mysqladmin drop misp
  sudo mysql -e "DROP USER misp@localhost"
}

# Final function to let the user know what happened
theEnd () {
  space
  echo "Admin (root) DB Password: $DBPASSWORD_ADMIN" |$SUDO_USER tee /home/${MISP_USER}/mysql.txt
  echo "User  (misp) DB Password: $DBPASSWORD_MISP"  |$SUDO_USER tee -a /home/${MISP_USER}/mysql.txt
  echo "Authkey: $AUTH_KEY" |$SUDO_USER tee -a /home/${MISP_USER}/MISP-authkey.txt

  clear
  space
  echo -e "${LBLUE}MISP${NC} Installed, access here: ${MISP_BASEURL}"
  echo
  echo "User: admin@admin.test"
  echo "Password: admin"
  space
  [[ -n $KALI ]] || [[ -n $DASHBOARD ]] || [[ -n $ALL ]] && echo -e "${LBLUE}MISP${NC} Dashboard, access here: ${MISP_BASEURL}:8001"
  [[ -n $KALI ]] || [[ -n $DASHBOARD ]] || [[ -n $ALL ]] && space
  [[ -n $KALI ]] || [[ -n $VIPER ]] || [[ -n $ALL ]] && echo -e "viper-web installed, access here: ${MISP_BASEURL}:8888"
  [[ -n $KALI ]] || [[ -n $VIPER ]] || [[ -n $ALL ]] && echo -e "viper-cli configured with your ${LBLUE}MISP${NC} ${RED}Site Admin Auth Key${NC}"
  [[ -n $KALI ]] || [[ -n $VIPER ]] || [[ -n $ALL ]] && echo
  [[ -n $KALI ]] || [[ -n $VIPER ]] || [[ -n $ALL ]] && echo "User: admin"
  [[ -n $KALI ]] || [[ -n $VIPER ]] || [[ -n $ALL ]] && echo "Password: Password1234"
  [[ -n $KALI ]] || [[ -n $VIPER ]] || [[ -n $ALL ]] && space
  echo -e "The following files were created and need either ${RED}protection or removal${NC} (${YELLOW}shred${NC} on the CLI)"
  echo "/home/${MISP_USER}/mysql.txt"
  echo -e "${RED}Contents:${NC}"
  cat /home/${MISP_USER}/mysql.txt
  echo "/home/${MISP_USER}/MISP-authkey.txt"
  echo -e "${RED}Contents:${NC}"
  cat /home/${MISP_USER}/MISP-authkey.txt
  space
  echo -e "The ${RED}LOCAL${NC} system credentials:"
  echo "User: ${MISP_USER}"
  echo "Password: ${MISP_PASSWORD} # Or the password you used of your custom user"
  space
  echo "To enable outgoing mails via postfix set a permissive SMTP server for the domains you want to contact:"
  echo
  echo "sudo postconf -e 'relayhost = example.com'"
  echo "sudo postfix reload"
  space
  echo -e "Enjoy using ${LBLUE}MISP${NC}. For any issues see here: https://github.com/MISP/MISP/issues"
  space
  if [[ "$UNATTENDED" == "1" ]]; then
    echo -e "${RED}Unattended install!${NC}"
    echo -e "This means we guessed the Base URL, it might be wrong, please double check."
    space
  fi

  if [[ "$USER" != "$MISP_USER" ]]; then
    sudo su - ${MISP_USER}
  fi
}
## End Function Section Nothing allowed in .md after this line ##
# <snippet-end 0_support-functions.sh>
```
