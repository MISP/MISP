#### MISP Dashboard on CentOS
--------------

!!! warning
    Currently defunct due to upstream dependency changes

!!! warning
    Does not work on RHEL 8

```bash
# <snippet-begin 4_misp-dashboardRHEL.sh>
# Main MISP Dashboard install function
mispDashboard () {
  sudo yum install wget screen -y
  sudo mkdir /var/www/misp-dashboard
  sudo chown $WWW_USER:$WWW_USER /var/www/misp-dashboard
  false; while [[ $? -ne 0 ]]; do $SUDO_WWW git clone https://github.com/MISP/misp-dashboard.git /var/www/misp-dashboard; done
  cd /var/www/misp-dashboard
  sudo sed -i -E 's/sudo apt/#sudo apt/' install_dependencies.sh
  sudo sed -i -E 's/virtualenv -p python3 DASHENV/\/usr\/bin\/scl enable rh-python36 \"virtualenv -p python3 DASHENV\"/' install_dependencies.sh
  sudo -H /var/www/misp-dashboard/install_dependencies.sh
  sudo sed -i "s/^host\ =\ localhost/host\ =\ 0.0.0.0/g" /var/www/misp-dashboard/config/config.cfg
  sudo sed -i '/Listen 80/a Listen 0.0.0.0:8001' /etc/httpd/conf/httpd.conf
  sudo yum install rh-python36-mod_wsgi -y
  sudo cp /opt/rh/httpd24/root/usr/lib64/httpd/modules/mod_rh-python36-wsgi.so /etc/httpd/modules/
  sudo cp /opt/rh/httpd24/root/etc/httpd/conf.modules.d/10-rh-python36-wsgi.conf /etc/httpd/conf.modules.d/

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

  # Enable ZeroMQ for misp-dashboard
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.ZeroMQ_enable" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.ZeroMQ_event_notifications_enable" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.ZeroMQ_object_notifications_enable" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.ZeroMQ_object_reference_notifications_enable" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.ZeroMQ_attribute_notifications_enable" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.ZeroMQ_sighting_notifications_enable" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.ZeroMQ_user_notifications_enable" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.ZeroMQ_organisation_notifications_enable" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.ZeroMQ_port" 50000
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.ZeroMQ_redis_host" "localhost"
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.ZeroMQ_redis_port" 6379
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.ZeroMQ_redis_database" 1
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.ZeroMQ_redis_namespace" "mispq"
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.ZeroMQ_include_attachments" false
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.ZeroMQ_tag_notifications_enable" false
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.ZeroMQ_audit_notifications_enable" false
}
# <snippet-end 4_misp-dashboardRHEL.sh>
```
