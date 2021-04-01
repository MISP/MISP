```bash
# <snippet-begin 4_misp-dashboard-cake.sh>
dashboardCAKE () {
  # Enable ZeroMQ for misp-dashboard
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_enable" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_host" "127.0.0.1"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_port" 50000
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_redis_host" "localhost"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_redis_port" 6379
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_redis_database" 1
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_redis_namespace" "mispq"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_include_attachments" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_event_notifications_enable" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_object_notifications_enable" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_object_reference_notifications_enable" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_attribute_notifications_enable" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_tag_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_sighting_notifications_enable" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_user_notifications_enable" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_organisation_notifications_enable" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_audit_notifications_enable" false
}
# <snippet-end 4_misp-dashboard-cake.sh>
```
