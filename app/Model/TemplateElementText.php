<?php

App::uses('AppModel', 'Model');

class TemplateElementText extends AppModel {
	public $actsAs = array('Containable');
	public $belongsTo = array('TemplateElement');

	public $validate = array(
			'name' => array(
					'rule' => array('valueNotEmpty'),
					'message' => 'Please enter a Name',
			),
			'text' => array(
					'rule' => array('valueNotEmpty'),
					'message' => 'Please fill out the text field',
			),
	);
}
