<?php
class ConfigLoadTask extends Shell
{
    public function execute()
    {
        if (Configure::read('MISP.system_setting_db')) {
            App::uses('SystemSetting', 'Model');
            SystemSetting::setGlobalSetting();
        }
        // Environment variables are the highest priority source, so they are
        // applied last to override both the config file and the database.
        App::uses('EnvSetting', 'Tools');
        EnvSetting::setGlobalSetting();
    }
}
