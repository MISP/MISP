<?php
class ConfigLoadTask extends Shell
{
    public function execute()
    {
        Configure::load('config');

        if (Configure::read('MISP.system_setting_db')) {
            App::uses('SystemSetting', 'Model');
            SystemSetting::setGlobalSetting();
        }
    }
}
