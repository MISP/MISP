<?php

App::uses('AppModel', 'Model');

/**
 * TemplateElementText Model
 *
*/
class TemplateElementText extends AppModel {
	public $actsAs = array('Containable');
	public $belongsTo = array('TemplateElement');
}
