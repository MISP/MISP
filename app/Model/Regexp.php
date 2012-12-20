<?php

App::uses('AppModel', 'Model');

/**
 * Regexp Model
 *
 */
class Regexp extends AppModel {

/**
 * Use table
 *
 * @var mixed False or table name
 */
	public $useTable = 'regexp';

	public function getAll() {
		return $this->find('all');
	}
}