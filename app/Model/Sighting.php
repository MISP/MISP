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
		'date_sighting' => 'datetime'
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
	
	public function attachToEvent(&$event, &$user, $eventOnly=false) {
		$ownEvent = false;
		if ($user['Role']['perm_site_admin'] || $event['Event']['org_id'] == $user['org_id']) $ownEvent = true;
		$conditions = array('Sighting.event_id' => $event['Event']['id']);
		if (!$ownEvent && (!Configure::read('Plugin.Sightings_policy') || Configure::read('Plugin.Sightings_policy') == 0)) $conditions['Sighting.org_id'] = $user['org_id'];
		$contain = array();
		if (Configure::read('MISP.showorg')) $contain['Organisation'] = array('fields' => array('Organisation.id', 'Organisation.uuid', 'Organisation.name'));
		
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
			//rearrange it to match the event format of fetchevent
			if (isset($sightings[$k]['Organisation'])) $sightings[$k]['Sighting']['Organisation'] = $sightings[$k]['Organisation'];
			$sightings[$k] = $sightings[$k]['Sighting'] ;
		}
		return $sightings; 
	}
}