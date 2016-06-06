<?php
App::uses('AppModel', 'Model');

class AdminSetting extends AppModel {
	public $actsAs = array('Containable');
	public $validate = array('setting' => 'isUnique');
}
