<?php
App::uses('AppController', 'Controller');

class SightingsController extends AppController {
	public $components = array('Session', 'RequestHandler');

	public function beforeFilter() {
		parent::beforeFilter();
	}

	public $paginate = array(
			'limit' => 60,
			'maxLimit' => 9999,	// LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
			'order' => array(
					'Sighting.created' => 'DESC'
			),
	);

	public function index() {
	}

	public function add() {
	}
	
	public function edit($id) {
	}

	public function delete($id) {

	}	
}
