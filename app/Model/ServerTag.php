<?php
App::uses('AppModel', 'Model');

class ServerTag extends AppModel {

	public $actsAs = array('Containable');

	public $validate = array(
		'server_id' => array(
			'valueNotEmpty' => array(
				'rule' => array('valueNotEmpty'),
			),
		),
		'tag_id' => array(
			'valueNotEmpty' => array(
				'rule' => array('valueNotEmpty'),
			),
		),
	);

	public $belongsTo = array(
		'Server',
		'Tag'
	);

	public function attachTagToServer($server_id, $tag_id) {
		$existingAssociation = $this->find('first', array(
			'recursive' => -1,
			'conditions' => array(
				'tag_id' => $tag_id,
				'server_id' => $server_id
			)
		));
		if (empty($existingAssociation)) {
			$this->create();
			if (!$this->save(array('server_id' => $server_id, 'tag_id' => $tag_id))) return false;
		}
		return true;
	}
}
