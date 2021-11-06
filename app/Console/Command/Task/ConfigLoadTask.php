<?php
class ConfigLoadTask extends Shell
{
    public function execute()
    {
        Configure::load('config');

        if (Configure::read('MISP.system_setting_db')) {
            $this->loadModel('SystemSetting');
            $settings = $this->SystemSetting->getSettings();
            Configure::write($settings);
        }
    }
}
