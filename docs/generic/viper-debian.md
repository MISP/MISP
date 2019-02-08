#### Install viper framework (with a virtualenv)
-----------------------

!!! warning
    Viper has **lief** as a dependency, lief only has an .egg for Python3.6 NOT Python3.7<br />
    If you have python3.7 installed make sure **virtualenv** uses **python3.6**<br />
    ```bash
    virtualenv -p python3.6 venv
    ```

```bash
# <snippet-begin viper.sh>
# Main Viper install function
viper () {
  cd /usr/local/src/
  debug "Installing Viper dependencies"
  sudo apt-get install \ 
    libssl-dev swig python3-ssdeep p7zip-full unrar-free sqlite python3-pyclamd exiftool radare2 \ 
    python3-magic python3-sqlalchemy python3-prettytable libffi-dev -y
  debug "Cloning Viper"
  git clone https://github.com/viper-framework/viper.git
  chown -R $MISP_USER:$MISP_USER viper
  cd viper
  debug "virtualenv -p python3.6 venv"
  debug "Submodule update"
  # TODO: Check for current user install permissions
  git submodule update --init --recursive
  ##$SUDO git submodule update --init --recursive
  debug "Pip install deps"
  ./venv/bin/pip install SQLAlchemy PrettyTable python-magic
  debug "pip install scrapy"
  debug "./venv/bin/pip install scrapy"
  debug "pip install reqs"
  ./venv/bin/pip install -r requirements.txt
  sed -i '1 s/^.*$/\#!\/usr\/local\/src\/viper\/venv\/bin\/python/' viper-cli
  sed -i '1 s/^.*$/\#!\/usr\/local\/src\/viper\/venv\/bin\/python/' viper-web
  debug "pip uninstall yara"
  ./venv/bin/pip uninstall yara -y
  debug "Launching viper-cli"
  # TODO: Perms
  #$SUDO /usr/local/src/viper/viper-cli -h > /dev/null
  /usr/local/src/viper/viper-cli -h > /dev/null
  debug "Launching viper-web"
  # TODO: Perms
  /usr/local/src/viper/viper-web -p 8888 -H 0.0.0.0 &
  #$SUDO /usr/local/src/viper/viper-web -p 8888 -H 0.0.0.0 &
  echo 'PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/usr/local/src/viper:/var/www/MISP/app/Console"' |sudo tee /etc/environment
  echo ". /etc/environment" >> /home/${MISP_USER}/.profile
  debug "Setting misp_url/misp_key"
  # TODO: Perms, MISP_USER_HOME
  sed -i "s/^misp_url\ =/misp_url\ =\ http:\/\/localhost/g" /home/${MISP_USER}/.viper/viper.conf
  sed -i "s/^misp_key\ =/misp_key\ =\ $AUTH_KEY/g" /home/${MISP_USER}/.viper/viper.conf

  # Reset admin password to: admin/Password1234
  debug "Fixing admin.db with default password"
  while [ "$(sqlite3 /home/${MISP_USER}/.viper/admin.db 'UPDATE auth_user SET password="pbkdf2_sha256$100000$iXgEJh8hz7Cf$vfdDAwLX8tko1t0M1TLTtGlxERkNnltUnMhbv56wK/U="'; echo $?)" -ne "0" ]; do
    # FIXME This might lead to a race condition, the while loop is sub-par
    chown $MISP_USER:$MISP_USER /home/${MISP_USER}/.viper/admin.db
    echo "Updating viper-web admin password, giving process time to start-up, sleeping 5, 4, 3,…"
    sleep 6
  done

  # Add viper-web to rc.local to be started on boot
  sudo sed -i -e '$i \sudo -u misp /usr/local/src/viper/viper-web -p 8888 -H 0.0.0.0 > /tmp/viper-web_rc.local.log &\n' /etc/rc.local
}
# <snippet-end viper.sh>
```
