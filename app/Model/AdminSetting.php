<?php
App::uses('AppModel', 'Model');

class AdminSetting extends AppModel {

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

	public function changeSetting($setting, $value = false) {
		$setting_object = $this->find('first', array(
			'conditions' => array('setting' => $setting)
		));
		if (!empty($setting_object)) {
			$setting_object['AdminSetting']['value'] = $value;
		} else {
			$this->create();
			$setting_object['AdminSetting'] = array('setting' => $setting, 'value' => $value);
		}
		if ($this->save($setting_object)) {
			return true;
		} else {
			return $this->validationErrors;
		}
	}

	public function getSetting($setting) {
		$setting_object = $this->find('first', array(
				'conditions' => array('setting' => $setting)
		));
		if (!empty($setting_object)) {
			return $setting_object['AdminSetting']['value'];
		} else {
			return false;
		}
	}
}
