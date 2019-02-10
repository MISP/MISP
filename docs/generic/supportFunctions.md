```bash
# <snippet-begin 0_support-functions.sh>
# Leave empty for NO debug messages, if run with set -x or bash -x it will enable DEBUG by default
DEBUG=
case "$-" in
  *x*)  NO_PROGRESS=1; DEBUG=1 ;;
  *)    NO_PROGRESS=0 ;;
esac
# Some colors for easier debug
RED='\033[0;31m'
GREEN='\033[0;32m'
LBLUE='\033[1;34m'
NC='\033[0m'


# Function Section

## Usage of this script
usage () {
  echo "Please specify what type of MISP if you want to install."
  space
  echo "${0} -c | Install ONLY MISP Core"                   # core
  echo "                    -V | Core + Viper"              # viper
  echo "                    -M | Core + MISP modules"       # modules
  echo "                    -D | Core + MISP dashboard"     # dashboard
  echo "                    -m | Core + Mail 2 MISP"        # mail2
  echo "                    -A | Install all of the above"  # all
  space
  echo "                    -C | Only do pre-install checks and exit" # pre
  space
  echo "                    -U | Do an unattanded Install, no questions asked" # UNATTENDED
  space
  echo "Options can be combined: ${0} -V -D # Will install Core+Viper+Dashboard"
  space
}

checkOpt () {
  # checkOpt feature
  containsElement $1 "${options[@]}"
}

setOpt () {
  options=()
  for o in $@; do 
    option=$(
    case "$o" in
      ("-c") echo "core"; CORE=1 ;;
      ("-V") echo "viper"; VIPER=1 ;;
      ("-M") echo "modules"; MODULES=1 ;;
      ("-D") echo "dashboard"; DASHBOARD=1 ;;
      ("-m") echo "mail2"; MAIL2=1 ;;
      ("-A") echo "all"; ALL=1 ;;
      ("-C") echo "pre"; PRE=1 ;;
      ("-U") echo "unattended"; UNATTENDED=1 ;;
      #(*) echo "$o is not a valid argument" ;;
    esac)
    options+=($option)
  done
}

# Extract debian flavour
checkFlavour () {
  if [ ! -f $(which lsb_release) ]; then
    sudo apt install lsb-release -y
  fi

  FLAVOUR=$(lsb_release -s -i |tr [A-Z] [a-z])
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

# Check if element is contained in array
containsElement () {
  local e match="$1"
  shift
  for e; do [[ "$e" == "$match" ]] && return 0; done
  return 1
}

# Check locale
checkLocale () {
  # If locale is missing, generate and install a common UTF-8
  if [ ! -f /etc/default/locale ]; then
    sudo apt install locales -y
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
  if [[ $EUID == 0 ]]; then
   echo "This script cannot be run as a root"
   exit 1
  elif [[ $(id $MISP_USER >/dev/null; echo $?) -ne 0 ]]; then
    echo "There is NO user called '$MISP_USER' create a user '$MISP_USER' or continue as $USER? (y/n) "
    read ANSWER
    ANSWER=$(echo $ANSWER |tr [A-Z] [a-z])
    if [[ $ANSWER == "y" ]]; then
      sudo useradd -s /bin/bash -m -G adm,cdrom,sudo,dip,plugdev,www-data,staff $MISP_USER
      echo $MISP_USER:$MISP_PASSWORD | sudo chpasswd
      echo "User $MISP_USER added, password is: $MISP_PASSWORD"
    elif [[ $ANSWER == "n" ]]; then
      echo "Using $USER as install user, hope that is what you want."
      echo "${RED}Adding $USER to groups www-data and staff${NC}"
      MISP_USER=$USER
      sudo adduser $MISP_USER staff
      sudo adduser $MISP_USER www-data
    else
      echo "yes or no was asked, try again."
      exit 1
    fi
  else
    echo "User ${MISP_USER} exists, skipping creation"
    echo "${RED}Adding $MISP_USER to groups www-data and staff${NC}"
    sudo adduser $MISP_USER staff
    sudo adduser $MISP_USER www-data
  fi
}

# check is /usr/local/src is RW by misp user
checkUsrLocalSrc () {
if [[ -e /usr/local/src ]]; then
  if [[ -w /usr/local/src ]]; then
    echo "Good, /usr/local/src exists and is writeable as $MISP_USER"
  else
    # TODO: The below might be shorter, more elegant and more modern
    #[[ -n $KALI ]] || [[ -n $UNATTENDED ]] && echo "Just do it" 
    if [ "$KALI" == "1" -o "$UNATTENDED" == "1" ]; then
      ANSWER="y"
    else
      echo -n "/usr/local/src need to be writeable by $MISP_USER, permission to fix? (y/n)"
      read ANSWER
      ANSWER=$(echo $ANSWER |tr [A-Z] [a-z])
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

# Test and install software RNG
installRNG () {
  modprobe tpm-rng 2> /dev/null
  if [ "$?" -eq "0" ]; then 
    echo tpm-rng >> /etc/modules
  fi
  apt install -qy rng-tools # This might fail on TPM grounds, enable the security chip in your BIOS
  service rng-tools start

  if [ "$?" -eq "1" ]; then 
    apt purge -qy rng-tools
    apt install -qy haveged
    /etc/init.d/haveged start
  fi
}

# Kali upgrade
kaliUpgrade () {
  SLEEP=3
  sudo apt update
  while [ "$DONE" != "0" ]; do
    sudo DEBIAN_FRONTEND=noninteractive apt install --only-upgrade bash libc6 -y && DONE=0
    echo -e "${LBLUE}apt${NC} is maybe ${RED}locked${NC}, waiting ${RED}$SLEEP${NC} seconds."
    sleep $SLEEP
    SLEEP=$[$SLEEP+3]
  done
  unset DONE
}

# Disables sleep
disableSleep () {
  debug "Disabling sleep etc if run from a Laptop as the install might take some time…"
  gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-ac-timeout 0 2> /dev/null
  gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-battery-timeout 0 2> /dev/null
  gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-battery-type 'nothing' 2> /dev/null
  xset s 0 0 2> /dev/null
  xset dpms 0 0 2> /dev/null
  xset s off 2> /dev/null
}

# <snippet-begin 0_installDepsPhp73.sh>
# Install Php 7.3 deps
installDepsPhp73 () {
  PHP_ETC_BASE=/etc/php/7.3
  PHP_INI=${PHP_ETC_BASE}/apache2/php.ini
  SLEEP=3
  sudo apt update
  while [ "$DONE" != "0" ]; do
    sudo apt install -qy \
    libapache2-mod-php7.3 \
    php7.3 php7.3-cli \
    php7.3-dev \
    php7.3-json php7.3-xml php7.3-mysql php7.3-opcache php7.3-readline php7.3-mbstring \
    php-pear \
    php-redis php-gnupg 2> /dev/null > /dev/null && DONE=0
    echo -e "${LBLUE}apt${NC} is maybe ${RED}locked${NC}, waiting ${RED}$SLEEP${NC} seconds."
    sleep $SLEEP
    SLEEP=$[$SLEEP+3]
  done
  unset DONE
}
# <snippet-end 0_installDepsPhp73.sh>

# Installing core dependencies
installDeps () {
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
  curl gcc git gnupg-agent make openssl redis-server neovim zip libyara-dev python3-yara python3-redis python3-zmq \
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
  sed -i -e '$i \sudo -u www-data bash /var/www/MISP/app/Console/worker/start.sh\n' /etc/rc.local
}

# Final function to let the user know what happened
theEnd () {
  space
  echo "Admin (root) DB Password: $DBPASSWORD_ADMIN" > /home/${MISP_USER}/mysql.txt
  echo "User  (misp) DB Password: $DBPASSWORD_MISP" >> /home/${MISP_USER}/mysql.txt
  echo "Authkey: $AUTH_KEY" > /home/${MISP_USER}/MISP-authkey.txt

  clear
  space
  echo "MISP Installed, access here: https://misp.local"
  echo "User: admin@admin.test"
  echo "Password: admin"
  echo "MISP Dashboard, access here: http://misp.local:8001"
  space
  echo "The following files were created and need either protection or removal (shred on the CLI)"
  echo "/home/${MISP_USER}/mysql.txt"
  echo "/home/${MISP_USER}/MISP-authkey.txt"
  cat /home/${MISP_USER}/mysql.txt
  cat /home/${MISP_USER}/MISP-authkey.txt
  space
  echo "The LOCAL system credentials:"
  echo "User: ${MISP_USER}"
  echo "Password: ${MISP_PASSWORD}"
  space
  echo "viper-web installed, access here: http://misp.local:8888"
  echo "viper-cli configured with your MISP Site Admin Auth Key"
  echo "User: admin"
  echo "Password: Password1234"
  space
  echo "To enable outgoing mails via postfix set a permissive SMTP server for the domains you want to contact:"
  space
  echo "sudo postconf -e 'relayhost = example.com'"
  echo "sudo postfix reload"
  space
  echo "Enjoy using MISP. For any issues see here: https://github.com/MISP/MISP/issues"
  su - ${MISP_USER}
}
# <snippet-end 0_support-functions.sh>
```
