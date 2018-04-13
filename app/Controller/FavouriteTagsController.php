<?php
App::uses('AppController', 'Controller');

class FavouriteTagsController extends AppController {
	public $components = array('Session', 'RequestHandler');

	public $paginate = array(
			'limit' => 60,
			'maxLimit' => 9999,	// LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
			'order' => array(
					'FavouriteTag.id' => 'DESC'
			),
	);

	public function toggle() {
		if (!$this->request->is('post')) throw new MethodNotAllowedException('This action is only available via POST requests.');
		if (!is_numeric($this->request->data['FavouriteTag']['data'])) throw new MethodNotAllowedException('Invalid tag ID.');
		$this->FavouriteTag->Tag->id = $this->request->data['FavouriteTag']['data'];
		if (!$this->FavouriteTag->Tag->exists()) throw new MethodNotAllowedException('Invalid tag ID.');
		$data = array('tag_id' => $this->request->data['FavouriteTag']['data'], 'user_id' => $this->Auth->user('id'));
		$existingFavourite = $this->FavouriteTag->find('first', array('conditions' => $data, 'recursive' => -1));
		$success = false;
		if (empty($existingFavourite)) {
			$message = 'Adding the tag to your favourites';
			$this->FavouriteTag->create();
			if ($this->FavouriteTag->save($data)) $success = true;
		} else {
			$message = 'Removing the tag from your favourites';
			if ($this->FavouriteTag->deleteAll($data, false)) $success = true;
		}
		if ($success) {
			return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => $message . ' was successful.')), 'status'=>200, 'type' => 'json'));
		} else {
			return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'fails' => $message . ' has failed.')), 'status'=>200, 'type' => 'json'));
		}
	}

	public function getToggleField() {
		if (!$this->request->is('ajax')) throw new MethodNotAllowedException('This action is available via AJAX only.');
		$this->layout = 'ajax';
		$this->render('ajax/getToggleField');
	}
}
