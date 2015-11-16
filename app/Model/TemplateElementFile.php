<?php

App::uses('AppModel', 'Model');

/**
 * TemplateElementAttribute Model
 *
*/
class TemplateElementFile extends AppModel {
	public $actsAs = array('Containable');
	public $belongsTo = array('TemplateElement');
	
	public $validate = array(
			'name' => array(
				'rule' => 'valueNotEmpty',
				'message' => 'Please enter a Name',
			),
			'description' => array(
				'rule' => 'valueNotEmpty',
				'message' => 'Please enter a Description',
			),
			'category' => array(
				'notDefault' => array(
					'rule'    => array('comparison', '!=', 'Select Category'),
					'message' => 'Please choose a category.'
				),
				'valueNotEmpty' => array(
					'rule' => 'valueNotEmpty',
					'message' => 'Please choose a category.'
				)
			),
	);
	public function beforeValidate($options = array()) {
		parent::beforeValidate();
	}
}
