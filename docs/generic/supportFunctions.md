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
  ## FIXME: The current state of misp-dashboard is broken, disabling any use.
  ##echo -e "                -D | ${LBLUE}MISP${NC} dashboard"      # dashboard
  ## FIXME: The current state of Viper is broken, disabling any use.
  ##echo -e "                -V | Viper"                            # viper
  echo -e "                -m | Mail 2 ${LBLUE}MISP${NC}"         # mail2
  echo -e "                -S | Experimental ssdeep correlations" # ssdeep
  echo -e "                -A | Install ${YELLOW}all${NC} of the above" # all
  space
  echo -e "                -C | Only do ${YELLOW}pre-install checks and exit${NC}" # pre
  space
  echo -e "                -u | Do an unattended Install, no questions asked"      # UNATTENDED
  echo -e "${HIDDEN}       -U | Attempt and upgrade of selected item${NC}"         # UPGRADE
  echo -e "${HIDDEN}       -N | Nuke this MISP Instance${NC}"                      # NUKE
  echo -e "${HIDDEN}       -f | Force test install on current Ubuntu LTS schim, add -B for 18.04 -> 18.10, or -BB 18.10 -> 19.10)${NC}" # FORCE
  echo -e "Options can be combined: ${SCRIPT_NAME} -c -D # Will install Core+Dashboard"
  space
  echo -e "Recommended is either a barebone MISP install (ideal for syncing from other instances) or"
  echo -e "MISP + modules - ${SCRIPT_NAME} -c -M"
  echo -e ""
  echo -e ""
  echo -e "Interesting environment variables that get considered are:"
  echo -e ""
  echo -e "MISP_USER/MISP_PASSWORD # Local username on machine, default: misp/opensslGeneratedPassword"
  echo -e ""
  echo -e "PATH_TO_MISP # Where MISP will be installed, default: /var/www/MISP (recommended)"
  echo -e ""
  echo -e "DBHOST/DBNAME # database hostname, MISP database name, default: localhost/misp"
  echo -e "DBUSER_ADMIN/DBPASSWORD_ADMIN # MySQL admin user, default: root/opensslGeneratedPassword"
  echo -e "DBUSER_MISP/DBPASSWORD_MISP # MISP database user, default: misp/opensslGeneratedPassword"
  echo -e ""
  echo -e "You need to export the variable(s) to be taken into account. (or specified in-line when invoking INSTALL.sh)"
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
      ("-ni") echo "noninteractive"; NONINTERACTIVE=1 ;;
      ("-f") echo "force"; FORCE=1 ;;
      (*) echo "$o is not a valid argument"; exit 1 ;;
    esac
  done
}

# check if command_exists
command_exists () {
  command -v "$@" > /dev/null 2>&1
}

# TODO: fix os detection mess
# Try to detect what we are running on
checkCoreOS () {
  # lsb_release can exist on any platform. RedHat package: redhat-lsb
  LSB_RELEASE=$(which lsb_release > /dev/null ; echo $?)
  APT=$(which apt > /dev/null 2>&1; echo -n $?)
  APT_GET=$(which apt-get > /dev/null 2>&1; echo $?)

  # debian specific
  # /etc/debian_version
  ## os-release #generic
  # /etc/os-release

  # Redhat checks
  if [[ -f "/etc/redhat-release" ]]; then
    echo "This is some redhat flavour"
    REDHAT=1
    RHfla=$(cat /etc/redhat-release | cut -f 1 -d\ | tr '[:upper:]' '[:lower:]')
  fi
}

# Extract debian flavour
checkFlavour () {
  FLAVOUR=""
  # Every system that we officially support has /etc/os-release
  if [ -r /etc/os-release ]; then
    FLAVOUR="$(. /etc/os-release && echo "$ID"| tr '[:upper:]' '[:lower:]')"
  fi

  case "${FLAVOUR}" in
    ubuntu)
      if command_exists lsb_release; then
        dist_version="$(lsb_release --codename | cut -f2)"
      fi
      if [ -z "$dist_version" ] && [ -r /etc/lsb-release ]; then
        dist_version="$(. /etc/lsb-release && echo "$DISTRIB_CODENAME")"
      fi
    ;;
    debian|raspbian)
      dist_version="$(sed 's/\/.*//' /etc/debian_version | sed 's/\..*//')"
      case "$dist_version" in
        10)
          dist_version="buster"
        ;;
        9)
          dist_version="stretch"
        ;;
      esac
    ;;
    centos)
      if [ -z "$dist_version" ] && [ -r /etc/os-release ]; then
        dist_version="$(. /etc/os-release && echo "$VERSION_ID")"
        dist_version=${dist_version:0:1}
      fi
      echo "${FLAVOUR} support is experimental at the moment"
    ;;
    rhel|ol|sles|fedora)
      if [ -z "$dist_version" ] && [ -r /etc/os-release ]; then
        # FIXME: On fedora the trimming fails
        dist_version="$(. /etc/os-release && echo "$VERSION_ID")"
        dist_version=${dist_version:0:1}  # Only interested about major version
      fi
      # FIXME: Only tested for RHEL 7 so far 
      echo "${FLAVOUR} support is experimental at the moment"
    ;;
    *)
      if command_exists lsb_release; then
        dist_version="$(lsb_release --release | cut -f2)"
      fi
      if [ -z "$dist_version" ] && [ -r /etc/os-release ]; then
        dist_version="$(. /etc/os-release && echo "$VERSION_ID")"
      fi
    ;;
  esac

  # FIXME: The below want to be refactored
  if [ "${FLAVOUR}" == "ubuntu" ]; then
    RELEASE=$(lsb_release -s -r)
    debug "We detected the following Linux flavour: ${YELLOW}$(tr '[:lower:]' '[:upper:]' <<< ${FLAVOUR:0:1})${FLAVOUR:1} ${RELEASE}${NC}"
  else
    debug "We detected the following Linux flavour: ${YELLOW}$(tr '[:lower:]' '[:upper:]' <<< ${FLAVOUR:0:1})${FLAVOUR:1}${NC}"
  fi
}


# Check if this is a forked Linux distro
check_forked () {
  # Check for lsb_release command existence, it usually exists in forked distros
  if command_exists lsb_release; then
    # Check if the `-u` option is supported
    set +e
    lsb_release -a -u > /dev/null 2>&1
    lsb_release_exit_code=$?
    set -e

    # Check if the command has exited successfully, it means we're in a forked distro
    if [ "$lsb_release_exit_code" = "0" ]; then
      # Print info about current distro
      cat <<-EOF
      You're using '${FLAVOUR}' version '${dist_version}'.
EOF
      # Get the upstream release info
      FLAVOUR=$(lsb_release -a -u 2>&1 | tr '[:upper:]' '[:lower:]' | grep -E 'id' | cut -d ':' -f 2 | tr -d '[:space:]')
      dist_version=$(lsb_release -a -u 2>&1 | tr '[:upper:]' '[:lower:]' | grep -E 'codename' | cut -d ':' -f 2 | tr -d '[:space:]')

      # Print info about upstream distro
      cat <<-EOF
      Upstream release is '${FLAVOUR}' version '$dist_version'.
EOF
    else
      if [[ -r /etc/debian_version ]] && [[ "${FLAVOUR}" != "ubuntu" ]] && [[ "${FLAVOUR}" != "raspbian" ]]; then
        # We're Debian and don't even know it!
        FLAVOUR=debian
        dist_version="$(sed 's/\/.*//' /etc/debian_version | sed 's/\..*//')"
        case "$dist_version" in
          10)
            dist_version="buster"
          ;;
          9)
            dist_version="stretch"
          ;;
          8|'Kali Linux 2')
            dist_version="jessie"
          ;;
        esac
      fi
    fi
  fi
}

checkInstaller () {
  # Workaround: shasum is not available on RHEL, only checking sha512
  if [[ "${FLAVOUR}" == "rhel" ]] || [[ "${FLAVOUR}" == "centos" ]] || [[ "${FLAVOUR}" == "fedora" ]]; then
  INSTsum=$(sha512sum ${0} | cut -f1 -d\ )
  /usr/bin/wget --no-cache -q -O /tmp/INSTALL.sh.sha512 https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.sh.sha512
        chsum=$(cat /tmp/INSTALL.sh.sha512)
  if [[ "${chsum}" == "${INSTsum}" ]]; then
    echo "SHA512 matches"
  else
    echo "SHA512: ${chsum} does not match the installer sum of: ${INSTsum}"
    # exit 1 # uncomment when/if PR is merged
  fi
  else
    # TODO: Implement $FLAVOUR checks and install depending on the platform we are on
    if [[ $(which shasum > /dev/null 2>&1 ; echo $?) -ne 0 ]]; then
      checkAptLock
      sudo apt install libdigest-sha-perl -qyy
    fi
    # SHAsums to be computed, not the -- notatiation is for ease of use with rhash
    SHA_SUMS="--sha1 --sha256 --sha384 --sha512"
    for sum in $(echo ${SHA_SUMS} |sed 's/--sha//g'); do
      /usr/bin/wget --no-cache -q -O /tmp/INSTALL.sh.sha${sum} https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.sh.sha${sum}
      INSTsum=$(shasum -a ${sum} ${0} | cut -f1 -d\ )
      chsum=$(cat /tmp/INSTALL.sh.sha${sum} | cut -f1 -d\ )

      if [[ "${chsum}" == "${INSTsum}" ]]; then
        echo "sha${sum} matches"
      else
        echo "sha${sum}: ${chsum} does not match the installer sum of: ${INSTsum}"
        echo "Delete installer, re-download and please run again."
        exit 1
      fi
    done
  fi
}

# Extract manufacturer
checkManufacturer () {
  if [[ -z $(which dmidecode) ]]; then
    checkAptLock
    sudo apt install dmidecode -qy
  fi
  MANUFACTURER=$(sudo dmidecode -s system-manufacturer)
  debug ${MANUFACTURER}
}

# Dynamic horizontal spacer if needed, for autonomeous an no progress bar install, we are static.
space () {
  if [[ "$NO_PROGRESS" == "1" ]] || [[ "$PACKER" == "1" ]]; then
    echo "--------------------------------------------------------------------------------"
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
  progress=$[$progress+$1]
  if [[ "$NO_PROGRESS" == "1" ]] || [[ "$PACKER" == "1" ]]; then
    echo "progress=${progress}" > /tmp/INSTALL.stat
    return
  fi
  bar="#"

  # Prevent progress of overflowing
  if [[ $progress -ge 100 ]]; then
    echo -ne "#####################################################################################################  (100%)\r"
    return
  fi
  # Display progress
  for p in $(seq 1 $progress); do
    bar+="#"
    echo -ne "$bar  ($p%)\r"
  done
  echo -ne '\n'
  echo "progress=${progress}" > /tmp/INSTALL.stat
}

# Check locale
checkLocale () {
  debug "Checking Locale"
  # If locale is missing, generate and install a common UTF-8
  if [[ ! -f /etc/default/locale || $(wc -l /etc/default/locale| cut -f 1 -d\ ) -eq "1" ]]; then
    checkAptLock
    sudo DEBIAN_FRONTEND=noninteractive apt install locales -qy
    sudo sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/g' /etc/locale.gen
    sudo locale-gen en_US.UTF-8
    sudo update-locale LC_ALL=en_US.UTF-8 LANG=en_US.UTF-8
  fi
}

# Simple function to check command exit code
checkFail () {
  # '-ne' checks for numerical differences, '==' used for strings
  if [[ $2 -ne 0 ]]; then
    echo "iAmError: $1"
    echo "The last command exited with error code: $2"
    exit $2
  fi
}

ask_o () {

  ANSWER=""

  if [ -z "${1}" ]; then
    echo "This function needs at least 1 parameter."
    exit 1
  fi

  [ -z "${2}" ] && OPT1="y" || OPT1="${2}"
  [ -z "${3}" ] && OPT2="n" || OPT2="${3}"

  while true; do
    case "${ANSWER}" in "${OPT1}" | "${OPT2}") break ;; esac
    echo -e -n "${1} (${OPT1}/${OPT2}) "
    read ANSWER
    ANSWER=$(echo "${ANSWER}" |  tr '[:upper:]' '[:lower:]')
  done

}

clean () {
  rm /tmp/INSTALL.stat
  rm /tmp/INSTALL.sh.*
}

# Check if misp user is present and if run as root
checkID () {
  debug "Checking if run as root and $MISP_USER is present"
  if [[ $EUID -eq 0 ]]; then
    echo "This script cannot be run as a root"
    clean > /dev/null 2>&1
    exit 1
  elif [[ $(id $MISP_USER >/dev/null; echo $?) -ne 0 ]]; then
    if [[ "$UNATTENDED" != "1" ]]; then
      echo "There is NO user called '$MISP_USER' create a user '$MISP_USER' (y) or continue as $USER (n)? (y/n) "
      read ANSWER
      ANSWER=$(echo $ANSWER |tr '[:upper:]' '[:lower:]')
      INSTALL_USER=${USER}
    else
      ANSWER="y"
    fi

    if [[ $ANSWER == "y" ]]; then
      sudo useradd -s /bin/bash -m -G adm,cdrom,sudo,dip,plugdev,www-data,staff $MISP_USER
      echo $MISP_USER:$MISP_PASSWORD | sudo chpasswd
      echo "User $MISP_USER added, password is: $MISP_PASSWORD"
    elif [[ $ANSWER == "n" ]]; then
      echo "Using $USER as install user, hope that is what you want."
      echo -e "${RED}Adding $USER to groups $WWW_USER and staff${NC}"
      MISP_USER=$USER
      sudo adduser $MISP_USER staff
      sudo adduser $MISP_USER $WWW_USER
    else
      echo "yes or no was asked, try again."
      sudo adduser $MISP_USER staff
      sudo adduser $MISP_USER $WWW_USER
      exit 1
    fi
  else
    echo "User ${MISP_USER} exists, skipping creation"
    echo -e "${RED}Adding $MISP_USER to groups $WWW_USER and staff${NC}"
    sudo adduser $MISP_USER staff
    sudo adduser $MISP_USER $WWW_USER
  fi

  # FIXME: the below SUDO_CMD check is a duplicate from global variables, try to have just one check
  # sudo config to run $LUSER commands
  if [[ "$(groups ${MISP_USER} |grep -o 'staff')" == "staff" ]]; then
    SUDO_CMD="sudo -H -u ${MISP_USER} -g staff"
  else
    SUDO_CMD="sudo -H -u ${MISP_USER}"
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
# /var/www/MISP perms are correct (for $SUDO_WWW usage)
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
  AUTH_KEY=$(mysql -h $DBHOST --disable-column-names -B  -u $DBUSER_MISP -p"$DBPASSWORD_MISP" $DBNAME -e 'SELECT authkey FROM users WHERE role_id=1 LIMIT 1')

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
  ${SUDO_WWW} sh -c "cd ${PATH_TO_MISP}/app ; php composer.phar update ; php composer.phar self-update"

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
      sudo chmod 2775 /usr/local/src
      sudo chown root:staff /usr/local/src
    fi
  else
    echo "/usr/local/src does not exist, creating."
    mkdir -p /usr/local/src
    sudo chmod 2775 /usr/local/src
    # TODO: Better handling /usr/local/src permissions
    if [[ "$(cat /etc/group |grep staff > /dev/null 2>&1)" == "0" ]]; then
      sudo chown root:staff /usr/local/src
    fi
  fi
}

kaliSpaceSaver () {
  # Future function in case Kali overlay on LiveCD is full
  echo "${RED}Not implement${NC}"
}

# FIXME: Kali now uses kali/kali instead of root/toor
# Because Kali is l33t we make sure we DO NOT run as root
kaliOnTheR0ckz () {
  totalRoot=$(df -k | grep /$ |awk '{ print $2 }')
  totalMem=$(cat /proc/meminfo|grep MemTotal |grep -Eo '[0-9]{1,}')
  overlay=$(df -kh |grep overlay; echo $?) # if 1 overlay NOT present

  if [[ ${totalRoot} -lt 3059034 ]]; then
    echo "(If?) You run Kali in LiveCD mode, you need more overlay disk space."
    echo "This is defined by the total memory setting in you VM config."
    echo "You currently have: ${totalMem}kB which is not enough."
    echo "6-8Gb should be fine. (need >3Gb overlayFS)"
    exit 1
  fi

  if [[ ${EUID} -eq 0 ]]; then
    echo "This script must NOT be run as root"
    exit 1
  elif [[ $(id ${MISP_USER} >/dev/null; echo $?) -ne 0 ]]; then
    sudo useradd -s /bin/bash -m -G adm,cdrom,sudo,dip,plugdev,www-data,staff ${MISP_USER}
    echo ${MISP_USER}:${MISP_PASSWORD} | sudo chpasswd
  else
    # TODO: Make sure we consider this further down the road
    echo "User ${MISP_USER} exists, skipping creation"
  fi
}

setBaseURL () {
  debug "Setting Base URL"

  CONN=$(ip -br -o -4 a |grep UP |head -1 |tr -d "UP")
  IFACE=$(echo $CONN |awk {'print $1'})
  IP=$(echo $CONN |awk {'print $2'}| cut -f1 -d/)

  [[ -n ${MANUFACTURER} ]] || checkManufacturer

  if [[ "${MANUFACTURER}" != "innotek GmbH" ]] && [[ "$MANUFACTURER" != "VMware, Inc." ]] && [[ "$MANUFACTURER" != "QEMU" ]]; then
    debug "We guess that this is a physical machine and cannot reliably guess what the MISP_BASEURL might be."

    if [[ "${UNATTENDED}" != "1" ]]; then 
      echo "You can now enter your own MISP_BASEURL, if you wish to NOT do that, the MISP_BASEURL will be empty, which will work, but ideally you configure it afterwards."
      echo "Do you want to change it now? (y/n) "
      read ANSWER
      ANSWER=$(echo ${ANSWER} |tr '[:upper:]' '[:lower:]')
      if [[ "${ANSWER}" == "y" ]]; then
        if [[ ! -z ${IP} ]]; then
          echo "It seems you have an interface called ${IFACE} UP with the following IP: ${IP} - FYI"
          echo "Thus your Base URL could be: https://${IP}"
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
  elif [[ "${KALI}" == "1" ]]; then
    MISP_BASEURL="https://misp.local"
    # Webserver configuration
    FQDN='misp.local'
  elif [[ "${MANUFACTURER}" == "innotek GmbH" ]]; then
    MISP_BASEURL='https://localhost:8443'
    IP=$(ip addr show | awk '$1 == "inet" {gsub(/\/.*$/, "", $2); print $2}' |grep -v "127.0.0.1" |tail -1)
    sudo iptables -t nat -A OUTPUT -p tcp --dport 8443 -j DNAT --to ${IP}:443
    # Webserver configuration
    FQDN='localhost.localdomain'
  elif [[ "${MANUFACTURER}" == "VMware, Inc." ]]; then
    MISP_BASEURL='""'
    # Webserver configuration
    FQDN='misp.local'
  else
    MISP_BASEURL='""'
    # Webserver configuration
    FQDN='misp.local'
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
  checkAptLock
  # Fix Missing keys early
  sudo wget -O /etc/apt/trusted.gpg.d/php.gpg https://packages.sury.org/php/apt.gpg
  # /!\ The following is a very ugly dependency hack to make php7.4 work on Kali
  wget http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2_amd64.deb
  sudo dpkg -i libssl1.1_1.1.1f-1ubuntu2_amd64.deb
  wget http://ftp.debian.org/debian/pool/main/i/icu/libicu67_67.1-7_amd64.deb
  sudo dpkg -i libicu67_67.1-7_amd64.deb
  # EOH End-Of-Hack
  sudo DEBIAN_FRONTEND=noninteractive apt update
  sudo DEBIAN_FRONTEND=noninteractive apt install --only-upgrade bash libc6 -y
  sudo DEBIAN_FRONTEND=noninteractive apt autoremove -y
}

# Kali 2022.x has only php81
installDepsKaliPhp74 () {
    sudo apt -y install lsb-release apt-transport-https ca-certificates 
    sudo wget -O /etc/apt/trusted.gpg.d/php.gpg https://packages.sury.org/php/apt.gpg
    echo "deb https://packages.sury.org/php/ bullseye main" | sudo tee /etc/apt/sources.list.d/php.list
    sudo apt update
    wget http://ftp.us.debian.org/debian/pool/main/libf/libffi/libffi7_3.3-6_amd64.deb
    sudo dpkg -i libffi7_3.3-6_amd64.deb
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
  if [[ -n ${APT_UPDATED} ]]; then
    sudo apt update && APT_UPDATED=1
  fi
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
  checkAptLock
  sudo apt install -qy \
  libapache2-mod-php \
  php php-cli \
  php-dev \
  php-json php-xml php-mysql php-opcache php-readline php-mbstring php-zip \
  php-redis php-gnupg \
  php-gd

  for key in upload_max_filesize post_max_size max_execution_time max_input_time memory_limit
  do
      sudo sed -i "s/^\($key\).*/\1 = $(eval echo \${$key})/" $PHP_INI
  done
  sudo sed -i "s/^\(session.sid_length\).*/\1 = $(eval echo \${session0sid_length})/" $PHP_INI
  sudo sed -i "s/^\(session.use_strict_mode\).*/\1 = $(eval echo \${session0use_strict_mode})/" $PHP_INI
}
# <snippet-end 0_installDepsPhp70.sh>

# <snippet-begin 0_installDepsPhp73.sh>
# Install Php 7.3 deps
installDepsPhp73 () {
  debug "Installing PHP 7.3 dependencies"
  PHP_ETC_BASE=/etc/php/7.3
  PHP_INI=${PHP_ETC_BASE}/apache2/php.ini
  checkAptLock
  if [[ ! -n ${KALI} ]]; then
    sudo apt install -qy \
      libapache2-mod-php7.3 \
      php7.3 php7.3-cli \
      php7.3-dev \
      php7.3-json php7.3-xml php7.3-mysql php7.3-opcache php7.3-readline php7.3-mbstring \
      php-redis php-gnupg \
      php-gd
  else
      sudo apt install -qy \
        libapache2-mod-php7.3 \
        libgpgme-dev \
        php7.3 php7.3-cli \
        php7.3-dev \
        php7.3-json php7.3-xml php7.3-mysql php7.3-opcache php7.3-readline php7.3-mbstring \
        php7.3-gd
      sudo pecl channel-update pecl.php.net
      #sudo pear config-set php_ini ${PHP_INI}
      echo "" |sudo pecl install redis
      sudo pecl install gnupg
      echo extension=gnupg.so | sudo tee ${PHP_ETC_BASE}/mods-available/gnupg.ini
      echo extension=redis.so | sudo tee ${PHP_ETC_BASE}/mods-available/redis.ini
  fi
}
# <snippet-end 0_installDepsPhp73.sh>

# Installing core dependencies
installDeps () {
  debug "Installing core dependencies"
  checkAptLock
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
  curl gcc git gnupg-agent make openssl redis-server neovim unzip zip libyara-dev python3-yara python3-redis python3-zmq sqlite3 python3-virtualenv \
  mariadb-client \
  mariadb-server \
  apache2 apache2-doc apache2-utils \
  python3-dev python3-pip libpq5 libjpeg-dev libfuzzy-dev ruby asciidoctor \
  libxml2-dev libxslt1-dev zlib1g-dev python3-setuptools

  installRNG
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
  </VirtualHost>" | sudo tee /etc/apache2/sites-available/misp-ssl.conf
}

# Add git pull update mechanism to rc.local - TODO: Make this better
gitPullAllRCLOCAL () {
  sudo sed -i -e '$i \git_dirs="/usr/local/src/misp-modules /var/www/misp-dashboard /usr/local/src/faup /usr/local/src/mail_to_misp /usr/local/src/misp-modules /usr/local/src/viper /var/www/misp-dashboard"\n' /etc/rc.local
  sudo sed -i -e '$i \for d in $git_dirs; do\n' /etc/rc.local
  sudo sed -i -e '$i \    echo "Updating ${d}"\n' /etc/rc.local
  sudo sed -i -e '$i \    cd $d && sudo git pull &\n' /etc/rc.local
  sudo sed -i -e '$i \done\n' /etc/rc.local
}


# Main composer function
composer () {
  sudo mkdir -p /var/www/.composer ; sudo chown ${WWW_USER}:${WWW_USER} /var/www/.composer
  ${SUDO_WWW} sh -c "cd ${PATH_TO_MISP}/app ; php composer.phar install --no-dev"
}

# Legacy composer function
composer74 () {
  sudo mkdir -p /var/www/.composer ; sudo chown ${WWW_USER}:${WWW_USER} /var/www/.composer
  ${SUDO_WWW} sh -c "cd ${PATH_TO_MISP}/app ; php7.4 composer.phar install --no-dev"
}

# TODO: FIX somehow the alias of the function does not work
# Composer on php 7.0 does not need any special treatment the provided phar works well
alias composer70=composer
# Composer on php 7.2 does not need any special treatment the provided phar works well
alias composer72=composer
# Composer on php 7.3 does not need any special treatment the provided phar works well
alias composer73=composer

# TODO: this is probably a useless function
# Enable various core services
enableServices () {
    sudo systemctl daemon-reload
    sudo systemctl enable --now  mysql
    sudo systemctl enable --now  apache2
    sudo systemctl enable --now  redis-server
}

# TODO: check if this makes sense
# Generate rc.local
genRCLOCAL () {
  if [[ ! -e /etc/rc.local ]]; then
      echo '#!/bin/sh -e' | tee -a /etc/rc.local
      echo 'exit 0' | sudo tee -a /etc/rc.local
      chmod u+x /etc/rc.local
  fi

  sudo sed -i -e '$i \echo never > /sys/kernel/mm/transparent_hugepage/enabled\n' /etc/rc.local
  sudo sed -i -e '$i \echo 1024 > /proc/sys/net/core/somaxconn\n' /etc/rc.local
  sudo sed -i -e '$i \sysctl vm.overcommit_memory=1\n' /etc/rc.local
  sudo sed -i -e '$i \[ -f /etc/init.d/firstBoot ] && bash /etc/init.d/firstBoot\n' /etc/rc.local
}

# Run PyMISP tests
runTests () {
  echo "url = \"${MISP_BASEURL}\"
key = \"${AUTH_KEY}\"" |sudo tee ${PATH_TO_MISP}/PyMISP/tests/keys.py
  sudo chown -R $WWW_USER:$WWW_USER $PATH_TO_MISP/PyMISP/

  ${SUDO_WWW} sh -c "cd $PATH_TO_MISP/PyMISP && git submodule foreach git pull origin main"
  ${SUDO_WWW} ${PATH_TO_MISP}/venv/bin/pip install -e $PATH_TO_MISP/PyMISP/.[fileobjects,neo,openioc,virustotal,pdfexport]
  ${SUDO_WWW} sh -c "cd $PATH_TO_MISP/PyMISP && ${PATH_TO_MISP}/venv/bin/python tests/testlive_comprehensive.py"
}

# Nuke the install, meaning remove all MISP data but no packages, this makes testing the installer faster
nuke () {
  echo -e "${RED}YOU ARE ABOUT TO DELETE ALL MISP DATA! Sleeping 10, 9, 8...${NC}"
  sleep 10
  sudo rm -rvf /usr/local/src/{misp-modules,viper,mail_to_misp,LIEF,faup}
  sudo rm -rvf /var/www/MISP
  sudo mysqladmin -h $DBHOST drop misp
  sudo mysql -h $DBHOST -e "DROP USER misp@localhost"
}

# Final function to let the user know what happened
theEnd () {
  space
  echo "Admin (root) DB Password: $DBPASSWORD_ADMIN" |$SUDO_CMD tee /home/${MISP_USER}/mysql.txt
  echo "User  (misp) DB Password: $DBPASSWORD_MISP"  |$SUDO_CMD tee -a /home/${MISP_USER}/mysql.txt
  echo "Authkey: $AUTH_KEY" |$SUDO_CMD tee -a /home/${MISP_USER}/MISP-authkey.txt

  # Commenting out, see: https://github.com/MISP/MISP/issues/5368
  # clear -x
  space
  echo -e "${LBLUE}MISP${NC} Installed, access here: ${MISP_BASEURL}"
  echo
  echo "User: admin@admin.test"
  echo "Password: admin"
  space
  ##[[ -n $KALI ]] || [[ -n $DASHBOARD ]] || [[ -n $ALL ]] && echo -e "${LBLUE}MISP${NC} Dashboard, access here: ${MISP_BASEURL}:8001"
  ##[[ -n $KALI ]] || [[ -n $DASHBOARD ]] || [[ -n $ALL ]] && space
  ##[[ -n $KALI ]] || [[ -n $VIPER ]] || [[ -n $ALL ]] && echo -e "viper-web installed, access here: ${MISP_BASEURL}:8888"
  ##[[ -n $KALI ]] || [[ -n $VIPER ]] || [[ -n $ALL ]] && echo -e "viper-cli configured with your ${LBLUE}MISP${NC} ${RED}Site Admin Auth Key${NC}"
  ##[[ -n $KALI ]] || [[ -n $VIPER ]] || [[ -n $ALL ]] && echo
  ##[[ -n $KALI ]] || [[ -n $VIPER ]] || [[ -n $ALL ]] && echo "User: admin"
  ##[[ -n $KALI ]] || [[ -n $VIPER ]] || [[ -n $ALL ]] && echo "Password: Password1234"
  ##[[ -n $KALI ]] || [[ -n $VIPER ]] || [[ -n $ALL ]] && space
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
  echo "GnuPG Passphrase is: ${GPG_PASSPHRASE}"
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

  if [[ "$PACKER" == "1" ]]; then
    echo -e "${RED}This was an Automated Packer install!${NC}"
    echo -e "This means we forced an unattended install."
    space
  fi

  if [[ "$USER" != "$MISP_USER" && "$UNATTENDED" != "1" ]]; then
    sudo su - ${MISP_USER}
  fi
}
# <snippet-end 0_support-functions.sh>
# <snippet-begin 0_installDepsPhp72.sh>
# Install Php 7.2 dependencies
installDepsPhp72 () {
  debug "Installing PHP 7.2 dependencies"
  PHP_ETC_BASE=/etc/php/7.2
  PHP_INI=${PHP_ETC_BASE}/apache2/php.ini
  checkAptLock
  sudo apt install -qy \
  libapache2-mod-php \
  php php-cli \
  php-dev \
  php-json php-xml php-mysql php7.2-opcache php-readline php-mbstring php-zip \
  php-redis php-gnupg \
  php-intl php-bcmath \
  php-gd

  for key in upload_max_filesize post_max_size max_execution_time max_input_time memory_limit
  do
      sudo sed -i "s/^\($key\).*/\1 = $(eval echo \${$key})/" $PHP_INI
  done
  sudo sed -i "s/^\(session.sid_length\).*/\1 = $(eval echo \${session0sid_length})/" $PHP_INI
  sudo sed -i "s/^\(session.use_strict_mode\).*/\1 = $(eval echo \${session0use_strict_mode})/" $PHP_INI
}
## End Function Section Nothing allowed in .md after this line ##
# <snippet-end 0_installDepsPhp72.sh>
```
