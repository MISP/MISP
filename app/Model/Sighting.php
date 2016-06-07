<?php
App::uses('AppModel', 'Model');
class Sighting extends AppModel{
	public $useTable = 'sightings';
	public $recursive = -1;
	public $actsAs = array(
			'Containable',
	);

	public $validate = array(
		'event_id' => 'numeric',
		'attribute_id' => 'numeric',
		'org_id' => 'numeric',
		'date_sighting' => 'numeric'
	);

	public $belongsTo = array(
			'Attribute' => array(
					'className' => 'Attribute',
			),
			'Event' => array(
					'className' => 'Event',
			),
			'Organisation' => array(
					'className' => 'Organisation',
					'foreignKey' => 'org_id'
			),
	);

	public function beforeValidate($options = array()) {
		parent::beforeValidate();
		$date = date('Y-m-d H:i:s');
		if (empty($this->data['Sighting']['id']) && empty($this->data['Sighting']['date_sighting'])) {
			$this->data['Sighting']['date_sighting'] = $date;
		}
		return true;
	}

	public function attachToEvent(&$event, &$user, $eventOnly = false) {
		$ownEvent = false;
		if ($user['Role']['perm_site_admin'] || $event['Event']['org_id'] == $user['org_id']) $ownEvent = true;
		$conditions = array('Sighting.event_id' => $event['Event']['id']);
		if (!$ownEvent && (!Configure::read('Plugin.Sightings_policy') || Configure::read('Plugin.Sightings_policy') == 0)) {
			$conditions['Sighting.org_id'] = $user['org_id'];
		}
		$contain = array();
		if (Configure::read('MISP.showorg')) {
			$contain['Organisation'] = array('fields' => array('Organisation.id', 'Organisation.uuid', 'Organisation.name'));
		}

		// Sighting reporters setting
		// If the event has any sightings for the user's org, then the user is a sighting reporter for the event too.
		// This means that he /she has access to the sightings data contained within
		if (!$ownEvent && Configure::read('Plugin.Sightings_policy') == 1) {
			$temp = $this->find('first', array('recursive' => -1, 'conditions' => array('Sighting.event_id' => $event['Event']['id'], 'Sighting.org_id' => $user['org_id'])));
			if (empty($temp)) return array();
		}

		$sightings = $this->find('all', array(
				'conditions' => $conditions,
				'recursive' => -1,
				'contain' => $contain,
		));
		if (empty($sightings)) return array();
		$anonymise = Configure::read('Plugin.Sightings_anonymise');

		foreach ($sightings as $k => &$sighting) {
			if ($anonymise && !$user['Role']['perm_site_admin']) {
				if ($sighting['Sighting']['org_id'] != $user['org_id']) {
					unset($sightings[$k]['Sighting']['org_id']);
					unset($sightings[$k]['Organisation']);
				}
			}
			// rearrange it to match the event format of fetchevent
			if (isset($sightings[$k]['Organisation'])) {
				$sightings[$k]['Sighting']['Organisation'] = $sightings[$k]['Organisation'];
			}
			$sightings[$k] = $sightings[$k]['Sighting'] ;
		}
		return $sightings;
	}

	public function saveSightings($id, $values, $timestamp, $user) {
		$conditions = array();
		if ($id && $id !== 'stix') {
			if (strlen($id) == 36) $conditions = array('Attribute.uuid' => $id);
			else $conditions = array('Attribute.id' => $id);
		} else {
			if (!$values) return 0;
			foreach ($values as &$value) {
				foreach (array('value1', 'value2') as $field) {
					$conditions['OR'][] = array(
						'LOWER(Attribute.' . $field . ') LIKE' => strtolower($value)
					);
				}
			}
		}
		$attributes = $this->Attribute->fetchAttributes($user, array('conditions' => $conditions));
		if (empty($attributes)) return 0;
		$sightingsAdded = 0;
		foreach ($attributes as &$attribute) {
			$this->create();
			$sighting = array(
					'attribute_id' => $attribute['Attribute']['id'],
					'event_id' => $attribute['Attribute']['event_id'],
					'org_id' => $user['org_id'],
					'date_sighting' => $timestamp,
			);
			$sightingsAdded += $this->save($sighting) ? 1 : 0;
		}
		return $sightingsAdded;
	}

	public function handleStixSighting($data) {
		$randomFileName = $this->generateRandomFileName();
		$tempFile = new File(APP . "files" . DS . "scripts" . DS . "tmp" . DS . $randomFileName, true, 0644);

		// save the json_encoded event(s) to the temporary file
		if (!$tempFile->write($data)) return array('success' => 0, 'message' => 'Could not write the Sightings file to disk.');
		$tempFile->close();
		$scriptFile = APP . "files" . DS . "scripts" . DS . "stixsighting2misp.py";
		// Execute the python script and point it to the temporary filename
		$result = shell_exec('python ' . $scriptFile . ' ' . $randomFileName);
		// The result of the script will be a returned JSON object with 2 variables: success (boolean) and message
		// If success = 1 then the temporary output file was successfully written, otherwise an error message is passed along
		$result = json_decode($result, true);

		if ($result['success'] == 1) {
			$file = new File(APP . "files" . DS . "scripts" . DS . "tmp" . DS . $randomFileName . ".out");
			$result['data'] = $file->read();
			$file->close();
			$file->delete();
		}
		$tempFile->delete();
		return $result;
	}

	public function generateRandomFileName() {
		$length = 12;
		$characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
		$charLen = strlen($characters) - 1;
		$fn = '';
		for ($p = 0; $p < $length; $p++) {
			$fn .= $characters[rand(0, $charLen)];
		}
		return $fn;
	}
}
