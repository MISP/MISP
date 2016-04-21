<?php
App::uses('AppController', 'Controller');

class WarninglistsController extends AppController {
	public $components = array('Session', 'RequestHandler');

	public function beforeFilter() {
		parent::beforeFilter();
	}

	public $paginate = array(
			'limit' => 60,
			'maxLimit' => 9999,	// LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
			'contain' => array(
				'WarninglistType'
			),
			'order' => array(
				'Warninglist.id' => 'DESC'
			),
	);

	public function index() {
		$this->paginate['recursive'] = -1;
		$warninglists = $this->paginate();
		foreach ($warninglists as &$warninglist) {
			$warninglist['Warninglist']['valid_attributes'] = array();
			foreach ($warninglist['WarninglistType'] as $type) $warninglist['Warninglist']['valid_attributes'][] = $type['type'];
			$warninglist['Warninglist']['valid_attributes'] = implode(', ', $warninglist['Warninglist']['valid_attributes']);
			unset($warninglist['WarninglistType']);
		}
		$this->set('warninglists', $warninglists);
	}
	
	public function update() {
		$result = $this->Warninglist->update();
		$this->Log = ClassRegistry::init('Log');
		$fails = 0;
		$successes = 0;
		if (!empty($result)) {
			if (isset($result['success'])) {
				foreach ($result['success'] as $id => &$success) {
					if (isset($success['old'])) $change = $success['name'] . ': updated from v' . $success['old'] . ' to v' . $success['new'];
					else $change = $success['name'] . ' v' . $success['new'] . ' installed';
					$this->Log->create();
					$this->Log->save(array(
							'org' => $this->Auth->user('Organisation')['name'],
							'model' => 'Warninglist',
							'model_id' => $id,
							'email' => $this->Auth->user('email'),
							'action' => 'update',
							'user_id' => $this->Auth->user('id'),
							'title' => 'Warning list updated',
							'change' => $change,
					));
					$successes++;
				}
			}
			if (isset($result['fails'])) {
				foreach ($result['fails'] as $id => &$fail) {
					$this->Log->create();
					$this->Log->save(array(
							'org' => $this->Auth->user('Organisation')['name'],
							'model' => 'Warninglist',
							'model_id' => $id,
							'email' => $this->Auth->user('email'),
							'action' => 'update',
							'user_id' => $this->Auth->user('id'),
							'title' => 'Warning list failed to update',
							'change' => $fail['name'] . ' could not be installed/updated. Error: ' . $fail['fail'],
					));
					$fails++;
				}
			}
		} else {
			$this->Log->create();
			$this->Log->save(array(
					'org' => $this->Auth->user('Organisation')['name'],
					'model' => 'Warninglist',
					'model_id' => 0,
					'email' => $this->Auth->user('email'),
					'action' => 'update',
					'user_id' => $this->Auth->user('id'),
					'title' => 'Warninglist update (nothing to update)',
					'change' => 'Executed an update of the warning lists, but there was nothing to update.',
			));
		}
		if ($successes == 0 && $fails == 0) $this->Session->setFlash('All warninglists are up to date already.');
		else if ($successes == 0) $this->Session->setFlash('Could not update any of the warning lists');
		else {
			$message = 'Successfully updated ' . $successes . ' warninglists.';
			if ($fails != 0) $message . ' However, could not update ' . $fails . ' warning list.';
			$this->Session->setFlash($message);
		}
		$this->redirect(array('controller' => 'warninglists', 'action' => 'index'));
	}
	
	public function toggleEnable($id) {
		$currentState = $this->Warninglist->find('first', array('conditions' => array('id' => $id), 'recursive' => -1));
		if (empty($currentState)) return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Warninglist not found.')), 'status' => 200));
		if ($currentState['Warninglist']['enabled']) {
			$currentState['Warninglist']['enabled'] = false;
			$message = 'disabled';
		} else {
			$currentState['Warninglist']['enabled'] = true;
			$message = 'enabled';
		}
		if ($this->Warninglist->save($currentState)) {
			return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Warninglist ' . $message)), 'status' => 200));
		} else {
			return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Warninglist could not be enabled.')), 'status' => 200));
		}
	}
	
	public function getToggleField($id) {
		if (!$this->request->is('ajax')) throw new MethodNotAllowedException('This action is available via AJAX only.');
		$this->layout = 'ajax';
		$currentState = $this->Warninglist->find('first', array('conditions' => array('id' => $id), 'recursive' => -1, 'fields' => array('id', 'enabled')));
		$this->set('item', $currentState);
		$this->render('ajax/getToggleField');
	}
}