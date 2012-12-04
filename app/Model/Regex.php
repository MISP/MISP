<?php
App::uses('AppModel', 'Model');
/**
 * Log Model
 *
 */
class Regex extends AppModel {

/**
 * Use table
 *
 * @var mixed False or table name
 */
	public $useTable = 'regex';

	public $actsAs = array('Regex' => array('fields' => array('info', 'value')));

	public function getAll() {
		return $this->find('all');
	}
}