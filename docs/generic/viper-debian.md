#### Install viper framework (with a virtualenv)
-----------------------

```bash
# <snippet-begin 6_viper.sh>
# Main Viper install function
viper () {
  debug "Installing Viper dependencies"
  cd /usr/local/src/
  sudo apt-get install \
    libssl-dev swig python3-ssdeep p7zip-full unrar-free sqlite python3-pyclamd exiftool radare2 \
    python3-magic python3-sqlalchemy python3-prettytable libffi-dev libfreetype6-dev libpng-dev -qy
  echo "Cloning Viper"
  $SUDO_USER git clone https://github.com/viper-framework/viper.git
  sudo chown -R $MISP_USER:$MISP_USER viper
  cd viper
  echo "Creating virtualenv"
  $SUDO_USER virtualenv -p python3 venv
  echo "Submodule update"
  # TODO: Check for current user install permissions
  $SUDO_USER git submodule update --init --recursive
  ##$SUDO git submodule update --init --recursive
  echo "Pip install deps"
  $SUDO_USER ./venv/bin/pip install SQLAlchemy PrettyTable python-magic
  echo "pip install scrapy"
  $SUDO_USER ./venv/bin/pip install scrapy
  echo "install lief"
  $SUDO_USER ./venv/bin/pip install https://github.com/lief-project/packages/raw/lief-master-latest/pylief-0.9.0.dev.zip
  echo "pip install reqs"
  $SUDO_USER ./venv/bin/pip install -r requirements.txt
  $SUDO_USER sed -i '1 s/^.*$/\#!\/usr\/local\/src\/viper\/venv\/bin\/python/' viper-cli
  $SUDO_USER sed -i '1 s/^.*$/\#!\/usr\/local\/src\/viper\/venv\/bin\/python/' viper-web
  echo "Launching viper-cli"
  $SUDO_USER /usr/local/src/viper/viper-cli -h > /dev/null
  echo "Launching viper-web"
  $SUDO_USER /usr/local/src/viper/viper-web -p 8888 -H 0.0.0.0 &
  echo 'PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/usr/local/src/viper:/var/www/MISP/app/Console"' |sudo tee /etc/environment
  echo ". /etc/environment" >> /home/${MISP_USER}/.profile

  # TODO: Perms, MISP_USER_HOME, nasty hack cuz Kali on R00t
  if [ -f /home/${MISP_USER}/.viper/viper.conf ]; then
    VIPER_HOME="/home/${MISP_USER}/.viper"
  else
    VIPER_HOME="${HOME}/.viper"
  fi

  echo "Setting misp_url/misp_key"
  $SUDO_USER sed -i "s/^misp_url\ =/misp_url\ =\ http:\/\/localhost/g" ${VIPER_HOME}/viper.conf
  $SUDO_USER sed -i "s/^misp_key\ =/misp_key\ =\ $AUTH_KEY/g" ${VIPER_HOME}/viper.conf
  # Reset admin password to: admin/Password1234
  echo "Fixing admin.db with default password"
  VIPER_COUNT=0
  while [ "$(sudo sqlite3 ${VIPER_HOME}/admin.db 'UPDATE auth_user SET password="pbkdf2_sha256$100000$iXgEJh8hz7Cf$vfdDAwLX8tko1t0M1TLTtGlxERkNnltUnMhbv56wK/U="'; echo $?)" -ne "0" ]; do
    # FIXME This might lead to a race condition, the while loop is sub-par
    sudo chown $MISP_USER:$MISP_USER ${VIPER_HOME}/admin.db
    echo "Updating viper-web admin password, giving process time to start-up, sleeping 5, 4, 3,…"
    sleep 6
    VIPER_COUNT=$[$VIPER_COUNT+1]
    if [[ "$VIPER_COUNT" > '10' ]]; then
      echo "Something is wrong with updating viper. Continuing without db update."
      break
    fi
  done

  # Add viper-web to rc.local to be started on boot
  sudo sed -i -e '$i \sudo -u misp /usr/local/src/viper/viper-web -p 8888 -H 0.0.0.0 > /tmp/viper-web_rc.local.log &\n' /etc/rc.local
}
# <snippet-end 6_viper.sh>
```
