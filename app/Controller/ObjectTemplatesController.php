<?php

App::uses('AppController', 'Controller');

class ObjectsController extends AppController {
	public $components = array('Security' ,'RequestHandler', 'Session');

	public $paginate = array(
			'limit' => 20,
			'order' => array(
					'Object.id' => 'desc'
			),
	);

  public function add($eventId) {

  }

  public function edit($id) {

  }

  public function delete($id) {

  }

  public function view($id) {

  }

	public function update() {
		$result = $this->ObjectTemplate->update();
		$this->Log = ClassRegistry::init('Log');
		$fails = 0;
		$successes = 0;
		if (!empty($result)) {
			if (isset($result['success'])) {
				foreach ($result['success'] as $id => $success) {
					if (isset($success['old'])) $change = $success['name'] . ': updated from v' . $success['old'] . ' to v' . $success['new'];
					else $change = $success['name'] . ' v' . $success['new'] . ' installed';
					$this->Log->create();
					$this->Log->save(array(
							'org' => $this->Auth->user('Organisation')['name'],
							'model' => 'ObjectTemplate',
							'model_id' => $id,
							'email' => $this->Auth->user('email'),
							'action' => 'update',
							'user_id' => $this->Auth->user('id'),
							'title' => 'Object template updated',
							'change' => $change,
					));
					$successes++;
				}
			}
			if (isset($result['fails'])) {
				foreach ($result['fails'] as $id => $fail) {
					$this->Log->create();
					$this->Log->save(array(
							'org' => $this->Auth->user('Organisation')['name'],
							'model' => 'ObjectTemplate',
							'model_id' => $id,
							'email' => $this->Auth->user('email'),
							'action' => 'update',
							'user_id' => $this->Auth->user('id'),
							'title' => 'Object template failed to update',
							'change' => $fail['name'] . ' could not be installed/updated. Error: ' . $fail['fail'],
					));
					$fails++;
				}
			}
		} else {
			$this->Log->create();
			$this->Log->save(array(
					'org' => $this->Auth->user('Organisation')['name'],
					'model' => 'ObjectTemplate',
					'model_id' => 0,
					'email' => $this->Auth->user('email'),
					'action' => 'update',
					'user_id' => $this->Auth->user('id'),
					'title' => 'Object template update (nothing to update)',
					'change' => 'Executed an update of the Object Template library, but there was nothing to update.',
			));
		}
		if ($successes == 0 && $fails == 0) $this->Session->setFlash('All object templates are up to date already.');
		else if ($successes == 0) $this->Session->setFlash('Could not update any of the object templates');
		else {
			$message = 'Successfully updated ' . $successes . ' object templates.';
			if ($fails != 0) $message .= ' However, could not update ' . $fails . ' object templates.';
			$this->Session->setFlash($message);
		}
		$this->redirect(array('controller' => 'ObjectTemplates', 'action' => 'index'));

	}
}
