#### Make some misp-modules available

```bash
sudo -H -u www-data $CAKE Admin setSetting "Plugin.Enrichment_asn_history_enabled" true
sudo -H -u www-data $CAKE Admin setSetting "Plugin.Enrichment_cve_enabled" true
sudo -H -u www-data $CAKE Admin setSetting "Plugin.Enrichment_dns_enabled" true
```

