<?php
class ConfigLoadTask extends Shell
{
    public function execute()
    {
        if (Configure::read('MISP.system_setting_db')) {
            App::uses('SystemSetting', 'Model');
            SystemSetting::setGlobalSetting();
        }
    }
}
