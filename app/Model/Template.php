<?php

App::uses('AppModel', 'Model');

/**
 * Template Model
 *
*/
class Template extends AppModel {
	public $actsAs = array('Containable');
	public $hasMany = array('TemplateElement', 'TemplateTag');
}
