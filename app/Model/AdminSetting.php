<?php
App::uses('AppModel', 'Model');

class AdminSetting extends AppModel
{
    public $useTable = 'admin_settings';

    public $actsAs = array(
        'SysLogLogable.SysLogLogable' => array(
            'userModel' => 'User',
            'userKey' => 'user_id',
            'change' => 'full'
        ),
        'Containable'
    );

    public $validate = array('setting' => 'isUnique');

    public function changeSetting($setting, $value = false)
    {
        $existing = $this->find('first', array(
            'conditions' => array('setting' => $setting),
            'fields' => ['id'],
        ));
        if ($existing) {
            if ($this->save([
                'id' => $existing['AdminSetting']['id'],
                'value' => $value,
            ])) {
                return true;
            } else {
                return $this->validationErrors;
            }
        } else {
            $this->create();
            $existing['AdminSetting'] = array('setting' => $setting, 'value' => $value);
            if ($this->save($existing)) {
                return true;
            } else {
                return $this->validationErrors;
            }
        }
    }

    public function getSetting($setting)
    {
        $setting_object = $this->find('first', array(
            'conditions' => array('setting' => $setting),
            'fields' => ['value'],
        ));
        if (!empty($setting_object)) {
            return $setting_object['AdminSetting']['value'];
        } else {
            return false;
        }
    }

    public function updatesDone($blocking = false)
    {
        if ($blocking) {
            $continue = false;
            while ($continue == false) {
                $db_version = $this->find('first', array('conditions' => array('setting' => 'db_version')));
                $continue = empty($this->findUpgrades($db_version['AdminSetting']['value']));
            }
            return true;
        } else {
            $db_version = $this->find('first', array('conditions' => array('setting' => 'db_version')));
            return empty($this->findUpgrades($db_version['AdminSetting']['value']));
        }
    }
}
