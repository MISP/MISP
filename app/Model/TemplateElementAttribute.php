<?php

App::uses('AppModel', 'Model');

/**
 * TemplateElementAttribute Model
 *
*/
class TemplateElementAttribute extends AppModel {
	public $actsAs = array('Containable');
	public $hasMany = array('TemplateElementType');
	public $belongsTo = array('TemplateElement');
}
