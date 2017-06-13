<?php

App::uses('AppModel', 'Model');

class Object extends AppModel {
	public $actsAs = array(
			'Containable',
			'SysLogLogable.SysLogLogable' => array(	// TODO Audit, logable
					'roleModel' => 'Object',
					'roleKey' => 'object_id',
					'change' => 'full'
			),
	);

	public $belongsTo = array(
	);

	public $validate = array(
	);

}
