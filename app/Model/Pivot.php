<?php
App::uses('AppModel', 'Model');

/**
 * Pivot Model
 *
 */
class Pivot extends AppModel {
	/**
	 * hasOne associations
	 *
	 * @var array
	 */
	public $hasOne = array(
			'User' => array(
					'className' => 'User',
					'foreignKey' => 'user_id',
			),
			'Event' => array(
					'className' => 'Event',
					'foreignKey' => 'event_id',
			),
			'Parent' => array(
					'className' => 'Pivot',
					'foreignKey' => 'pivot_id',
			)
	);
	
	public function startPivoting($userID, $eventID, $eventInfo, $eventDate) {
		$this->deleteAll(array('Pivot.user_id' => $userID), false);
		$this->create();
		$this->save(array(
				'event_id' => $eventID,
				'user_id' => $userID,
				'event_info' => $eventInfo,
				'event_date' => $eventDate,
				'pivot_id' => 0));	
		return $this->getPivots($userID);	
	}
	
	public function continuePivoting($userID, $eventID, $eventInfo, $eventDate) {
		$this->recursive = -1;
		$lastPivot = $this->find(
				'first', 
				array(
						'fields' => array('MAX(Pivot.id) as last_id'),
						'conditions' => array('Pivot.user_id' => $userID),
			));
		$this->save(array(
				'event_id' => $eventID,
				'user_id' => $userID,
				'pivot_id' => $lastPivot[0]['last_id']));
		return $this->getPivots($userID);
	}
	
	public function getPivots($userID) {
		$this->recursive = -1;
		$allPivots = $this->find(
				'all',
				array(
						'fields' => array('Pivot.event_id', 'Pivot.event_info', 'Pivot.event_date'),
						'conditions' => array('Pivot.user_id' => $userID),
		));
		return $allPivots;
	}
}
?>