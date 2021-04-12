#### MISP Dashboard on CentOS
--------------

!!! warning
    A valid MaxMind DB key is required.

!!! warning
    Does not work fully on RHEL 8

```bash
# <snippet-begin 4_misp-dashboardRHEL.sh>
# Main MISP Dashboard install function
mispDashboard () {
  sudo dnf install wget screen -y
  sudo mkdir /var/www/misp-dashboard
  sudo chown ${WWW_USER}:${WWW_USER} /var/www/misp-dashboard
  false; while [[ $? -ne 0 ]]; do ${SUDO_WWW} git clone https://github.com/MISP/misp-dashboard.git /var/www/misp-dashboard; done
  cd /var/www/misp-dashboard
  sudo sed -i -E 's/sudo apt/#sudo apt/' install_dependencies.sh
  sudo -H /var/www/misp-dashboard/install_dependencies.sh
  sudo sed -i "s/^host\ =\ localhost/host\ =\ 0.0.0.0/g" /var/www/misp-dashboard/config/config.cfg
  sudo sed -i '/Listen 80/a Listen 0.0.0.0:8001' /etc/httpd/conf/httpd.conf
  # TODO: Check if this works on 7.x
  [[ "${DIST_VER}" =~ ^[7].* ]] && sudo dnf install rh-python36-mod_wsgi -y
  [[ "${DIST_VER}" =~ ^[7].* ]] && sudo cp /opt/rh/httpd24/root/usr/lib64/httpd/modules/mod_rh-python36-wsgi.so /etc/httpd/modules/
  [[ "${DIST_VER}" =~ ^[7].* ]] && sudo cp /opt/rh/httpd24/root/etc/httpd/conf.modules.d/10-rh-python36-wsgi.conf /etc/httpd/conf.modules.d/
  ([[ "${DISTRI}" == "fedora33" ]] || [[ "${DIST_VER}" =~ ^[8].* ]]) && sudo dnf install python3-mod_wsgi -y

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
      ErrorLog /var/log/httpd/misp-dashboard.local_error.log
      CustomLog /var/log/httpd/misp-dashboard.local_access.log combined
      ServerSignature Off
  </VirtualHost>" | sudo tee /etc/httpd/conf.d/misp-dashboard.conf

  sudo semanage port -a -t http_port_t -p tcp 8001
  sudo systemctl restart httpd.service

  # Add misp-dashboard to rc.local to start on boot.
  sudo sed -i -e '$i \sudo -u apache bash /var/www/misp-dashboard/start_all.sh > /tmp/misp-dashboard_rc.local.log\n' /etc/rc.local
}
# <snippet-end 4_misp-dashboardRHEL.sh>
```
