#### Experimental ssdeep correlations
##### installing ssdeep
```bash
# <snippet-begin 6_ssdeep.sh>
ssdeep () {
  debug "Install ssdeep 2.14.1"
  cd /usr/local/src
  $SUDO_CMD wget https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/ssdeep-2.14.1.tar.gz
  $SUDO_CMD tar zxvf ssdeep-2.14.1.tar.gz
  cd ssdeep-2.14.1
  $SUDO_CMD ./configure --datadir=/usr --prefix=/usr --localstatedir=/var --sysconfdir=/etc
  $SUDO_CMD make
  sudo make install

  #installing ssdeep_php
  sudo pecl channel-update pecl.php.net
  sudo pecl install ssdeep

  # You should add "extension=ssdeep.so" to mods-available - Check /etc/php for your current version
  echo "extension=ssdeep.so" | sudo tee ${PHP_ETC_BASE}/mods-available/ssdeep.ini
  sudo phpenmod ssdeep
  sudo service apache2 restart
}
# <snippet-end 6_ssdeep.sh>
```
