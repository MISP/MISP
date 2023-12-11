#### MISP Dashboard
--------------

!!! warning
    A valid MaxMind DB key is required.

```bash
# <snippet-begin 4_misp-dashboard.sh>
# Main MISP Dashboard install function
mispDashboard () {
  debug "Install misp-dashboard"
  # Install pyzmq to main MISP venv
  debug "Installing PyZMQ"
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install pyzmq
  cd /var/www
  sudo mkdir misp-dashboard
  sudo chown $WWW_USER:$WWW_USER misp-dashboard

  false; while [[ $? -ne 0 ]]; do $SUDO_WWW git clone https://github.com/MISP/misp-dashboard.git; done
  cd misp-dashboard
  sudo -H /var/www/misp-dashboard/install_dependencies.sh
  sudo sed -i "s/^host\ =\ localhost/host\ =\ 0.0.0.0/g" /var/www/misp-dashboard/config/config.cfg
  sudo sed -i '/Listen 80/a Listen 0.0.0.0:8001' /etc/apache2/ports.conf
  sudo apt install libapache2-mod-wsgi-py3 net-tools -y
  echo "<VirtualHost *:8001>
      ServerAdmin admin@misp.local
      ServerName misp.local

      DocumentRoot /var/www/misp-dashboard

      WSGIDaemonProcess misp-dashboard \
         user=misp group=misp \
         python-home=/var/www/misp-dashboard/DASHENV \
         processes=1 \
         threads=15 \
         maximum-requests=5000 \
         listen-backlog=100 \
         queue-timeout=45 \
         socket-timeout=60 \
         connect-timeout=15 \
         request-timeout=60 \
         inactivity-timeout=0 \
         deadlock-timeout=60 \
         graceful-timeout=15 \
         eviction-timeout=0 \
         shutdown-timeout=5 \
         send-buffer-size=0 \
         receive-buffer-size=0 \
         header-buffer-size=0 \
         response-buffer-size=0 \
         server-metrics=Off

      WSGIScriptAlias / /var/www/misp-dashboard/misp-dashboard.wsgi

      <Directory /var/www/misp-dashboard>
          WSGIProcessGroup misp-dashboard
          WSGIApplicationGroup %{GLOBAL}
          Require all granted
      </Directory>

      LogLevel info
      ErrorLog /var/log/apache2/misp-dashboard.local_error.log
      CustomLog /var/log/apache2/misp-dashboard.local_access.log combined
      ServerSignature Off
  </VirtualHost>" | sudo tee /etc/apache2/sites-available/misp-dashboard.conf

  # Enable misp-dashboard in apache and reload
  sudo a2ensite misp-dashboard
  sudo systemctl restart apache2

  # Needs to be started after apache2 is reloaded so the port status check works
  $SUDO_WWW bash /var/www/misp-dashboard/start_all.sh

  # Add misp-dashboard to rc.local to start on boot.
  sudo sed -i -e '$i \sudo -u www-data bash /var/www/misp-dashboard/start_all.sh > /tmp/misp-dashboard_rc.local.log\n' /etc/rc.local
}
# <snippet-end 4_misp-dashboard.sh>
