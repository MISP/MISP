<?php
App::uses('AppController', 'Controller');

class SightingsController extends AppController {
	public $components = array('Session', 'RequestHandler');

	public function beforeFilter() {
		parent::beforeFilter();
		if (!Configure::read('Plugin.Sightings_enable')) throw new MethodNotAllowedException('This feature is not enabled on this instance.');
	}

	public $paginate = array(
			'limit' => 60,
			'maxLimit' => 9999,	// LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
			'order' => array('Sighting.date_sighting' => 'DESC'),
	);

	// takes an attribute ID or UUID
	public function add($id) {
		if (!$this->userRole['perm_add']) throw new MethodNotAllowedException('You are not authorised to add sightings data as you don\'t have write access.');
		if (!$this->request->is('post')) throw new MethodNotAllowedException('This action can only be accessed via a post request.');
		if (strlen($id) == 36) $conditions = array('Attribute.uuid' => $id);
		else $conditions = array('Attribute.id' => $id);
		$attribute = $this->Sighting->Attribute->fetchAttributes($this->Auth->user(), array('conditions' => $conditions));
		if (empty($attribute)) throw new NotFoundException('Could not add sighting information, invalid attribute.');
		// normalise the request data if it exists
		if (isset($this->request->data['request'])) $this->request->data = $this->request->data['request'];
		if (isset($this->request->data['Sighting'])) $this->request->data = $this->request->data['Sighting'];
		$attribute = $attribute[0];
		$this->Sighting->create();
		$date = date('Y-m-d H:i:s');
		$sighting = array(
			'attribute_id' => $attribute['Attribute']['id'],
			'event_id' => $attribute['Attribute']['event_id'],
			'org_id' => $this->Auth->user('org_id'),
			'date_sighting' => isset($this->request->data['date_sighting']) ? $this->request->data['date_sighting'] : $date,
		);
		$result = $this->Sighting->save($sighting);
		if ($this->request->is('ajax')) {
			if (!$result) {
				$error_message = 'Could not add the Sighting. Reason: ' . json_encode($this->Sighting->validationErrors);
				return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => $error_message)), 'status' => 200));
			} else {
				return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Sighting added.')), 'status' => 200));
			}
		} else {
			if (!$result) {
				$this->set('errors', json_encode($this->Sighting->validatidationErrors));
				$this->set('name', 'Failed');
				$this->set('message', 'Could not add the Sighting.');
				$this->set('_serialize', array('name', 'message', 'errors'));
			} else {
				$this->set('name', 'Success');
				$this->set('message', 'Sighting successfuly added.');
				$this->set('url', '/sightings/add/' . $id);
				$this->set('id', $this->Sighting->id);
				$this->set('_serialize', array('name', 'message', 'url', 'id'));
			}
		}
	}

	// takes a sighting ID
	public function delete($id) {
		if (!$this->userRole['perm_modify_org']) throw new MethodNotAllowedException('You are not authorised to remove sightings data as you don\'t have permission to modify your organisation\'s data.');
		if (!$this->request->is('post')) throw new MethodNotAllowedException('This action can only be accessed via a post request.');
		$sighting = $this->Sighting->find('first', array('conditions' => array('Sighting.id' => $id), 'recursive' => -1));
		if (empty($sighting)) throw new NotFoundException('Invalid sighting.');
		if (!$this->_isSiteAdmin()) {
			if ($sighting['Sighting']['org_id'] != $this->Auth->user('org_id')) throw new NotFoundException('Invalid sighting.');
		}
		$result = $this->Sighting->delete($sighting['Sighting']['id']);
		if (!$result) {
			$this->set('errors', '');
			$this->set('name', 'Failed');
			$this->set('message', 'Could not delete the Sighting.');
			$this->set('_serialize', array('name', 'message', 'errors'));
		} else {
			$this->set('name', 'Success');
			$this->set('message', 'Sighting successfuly deleted.');
			$this->set('url', '/sightings/delete/' . $id);
			$this->set('_serialize', array('name', 'message', 'url'));
		}
	}
}
