<?php
App::uses('AppController', 'Controller');

class TaxonomiesController extends AppController {
	public $components = array('Session', 'RequestHandler');

	public function beforeFilter() {
		parent::beforeFilter();
	}

	public $paginate = array(
			'limit' => 60,
			'maxLimit' => 9999,	// LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
			'order' => array(
					'Taxonomy.id' => 'DESC'
			),
	);

	public function index() {
		$taxonomies = $this->Taxonomy->listTaxonomies();
		$this->paginate['recursive'] = -1;
		$this->set('taxonomies', $this->paginate());
	}
	
	public function view($id) {
		if (isset($this->passedArgs['pages'])) $currentPage = $this->passedArgs['pages'];
		else $currentPage = 1;
		$urlparams = '';
		$passedArgs = array();
		App::uses('CustomPaginationTool', 'Tools');
		$customPagination = new CustomPaginationTool();
		$params = $customPagination->createPaginationRules($events, $this->passedArgs, $this->alias);
		$this->params->params['paging'] = array($this->modelClass => $params);
		$taxonomy = $this->Taxonomy->getTaxonomy($id, array('full' => true));
		$customPagination->truncateByPagination($taxonomy['entries'], $params);
		$this->set('entries', $taxonomy['entries']);
		$this->set('taxonomy', $taxonomy['Taxonomy']);
	}
	
	public function enable($id) {
		if (!$this->_isSiteAdmin() || !$this->request->is('Post')) throw new MethodNotAllowedException('You don\'t have permission to do that.');
		$taxonomy = $this->Taxonomy->find('first', array(
			'recursive' => -1,
			'conditions' => array('Taxonomy.id' => $id),
		));
		$taxonomy['Taxonomy']['enabled'] = true;
		$this->Taxonomy->save($taxonomy);
		$this->Log = ClassRegistry::init('Log');
		$this->Log->create();
		$this->Log->save(array(
				'org' => $this->Auth->user('Organisation')['name'],
				'model' => 'Taxonomy',
				'model_id' => $id,
				'email' => $this->Auth->user('email'),
				'action' => 'enable',
				'user_id' => $this->Auth->user('id'),
				'title' => 'Taxonomy enabled',
				'change' => $taxonomy['Taxonomy']['namespace'] . ' - enabled',
		));
		$this->Session->setFlash('Taxonomy enabled.');
		$this->redirect($this->referer());
	}
	
	public function disable($id) {
		if (!$this->_isSiteAdmin() || !$this->request->is('Post')) throw new MethodNotAllowedException('You don\'t have permission to do that.');
		$taxonomy = $this->Taxonomy->find('first', array(
				'recursive' => -1,
				'conditions' => array('Taxonomy.id' => $id),
		));
		$taxonomy['Taxonomy']['enabled'] = false;
		$this->Taxonomy->save($taxonomy);
		$this->Log = ClassRegistry::init('Log');
		$this->Log->create();
		$this->Log->save(array(
				'org' => $this->Auth->user('Organisation')['name'],
				'model' => 'Taxonomy',
				'model_id' => $id,
				'email' => $this->Auth->user('email'),
				'action' => 'disable',
				'user_id' => $this->Auth->user('id'),
				'title' => 'Taxonomy disabled',
				'change' => $taxonomy['Taxonomy']['namespace'] . ' - disabled',
		));
		$this->Session->setFlash('Taxonomy disabled.');
		$this->redirect($this->referer());
	}
	
	public function update() {
		if (!$this->_isSiteAdmin()) throw new MethodNotAllowedException('You don\'t have permission to do that.');
		$result = $this->Taxonomy->update();
		$this->Log = ClassRegistry::init('Log');
		$fails = 0;
		$successes = 0;
		if (!empty($result)) {
			if (isset($result['success'])) {
				foreach ($result['success'] as $id => &$success) {
					if (isset($success['old'])) $change = $success['namespace'] . ': updated from v' . $success['old'] . ' to v' . $success['new'];
					else $change = $success['namespace'] . ' v' . $success['new'] . ' installed';
					$this->Log->create();
					$this->Log->save(array(
							'org' => $this->Auth->user('Organisation')['name'],
							'model' => 'Taxonomy',
							'model_id' => $id,
							'email' => $this->Auth->user('email'),
							'action' => 'update',
							'user_id' => $this->Auth->user('id'),
							'title' => 'Taxonomy updated',
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
							'model' => 'Taxonomy',
							'model_id' => $id,
							'email' => $this->Auth->user('email'),
							'action' => 'update',
							'user_id' => $this->Auth->user('id'),
							'title' => 'Taxonomy failed to update',
							'change' => $fail['namespace'] . ' could not be installed/updated. Error: ' . $fail['fail'],
					));
					$fails++;
				}
			}
		} else {
			$this->Log->create();
			$this->Log->save(array(
					'org' => $this->Auth->user('Organisation')['name'],
					'model' => 'Taxonomy',
					'model_id' => 0,
					'email' => $this->Auth->user('email'),
					'action' => 'update',
					'user_id' => $this->Auth->user('id'),
					'title' => 'Taxonomy update (nothing to update)',
					'change' => 'Executed an update of the taxonomy library, but there was nothing to update.',
			));
		}
		if ($successes == 0 && $fails == 0) $this->Session->setFlash('All taxonomy libraries are up to date already.');
		else if ($successes == 0) $this->Session->setFlash('Could not update any of the taxonomy libraries');
		else {
			$message = 'Successfully updated ' . $successes . ' taxonomy libraries.';
			if ($fails != 0) $message . ' However, could not update ' . $fails . ' taxonomy libraries.';
			$this->Session->setFlash($message);
		}
		$this->redirect(array('controller' => 'taxonomies', 'action' => 'index'));
		/*debug($this->Taxonomy->getTaxonomy('1'));
		debug($this->Taxonomy->listTaxonomies());
		debug($this->Taxonomy->getTaxonomy('1', array('full' => true)));
		debug($this->Taxonomy->listTaxonomies(array('full' => true)));*/
	}
}
