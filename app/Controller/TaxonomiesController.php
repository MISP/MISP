<?php
App::uses('AppController', 'Controller');

class TaxonomiesController extends AppController {
	public $components = array('Session', 'RequestHandler');

	public $paginate = array(
			'limit' => 60,
			'maxLimit' => 9999,	// LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
			'contain' => array(
				'TaxonomyPredicate' => array(
					'fields' => array('TaxonomyPredicate.id'),
					'TaxonomyEntry' => array('fields' => array('TaxonomyEntry.id'))
				)
			),
			'order' => array(
					'Taxonomy.id' => 'DESC'
			),
	);

	public function index() {
		$this->paginate['recursive'] = -1;
		$taxonomies = $this->paginate();
		$this->loadModel('Tag');
		foreach ($taxonomies as $key => $taxonomy) {
			$total = 0;
			foreach ($taxonomy['TaxonomyPredicate'] as $predicate) {
				$total += empty($predicate['TaxonomyEntry']) ? 1 : count($predicate['TaxonomyEntry']);
			}
			$taxonomies[$key]['total_count'] = $total;
			$taxonomies[$key]['current_count'] = $this->Tag->find('count', array('conditions' => array('lower(Tag.name) LIKE ' => strtolower($taxonomy['Taxonomy']['namespace']) . ':%', 'hide_tag' => 0)));
			unset($taxonomies[$key]['TaxonomyPredicate']);
		}
		if ($this->_isRest()) {
			return $this->RestResponse->viewData($taxonomies, $this->response->type());
		} else {
			$this->set('taxonomies', $taxonomies);
		}
	}

	public function view($id) {
		if (isset($this->passedArgs['pages'])) {
			$currentPage = $this->passedArgs['pages'];
		} else {
			$currentPage = 1;
		}
		$this->set('page', $currentPage);
		$urlparams = '';
		$passedArgs = array();
		App::uses('CustomPaginationTool', 'Tools');
		$filter = isset($this->passedArgs['filter']) ? $this->passedArgs['filter'] : false;
		$taxonomy = $this->Taxonomy->getTaxonomy($id, array('full' => true, 'filter' => $filter));
		if (empty($taxonomy)) throw new NotFoundException('Taxonomy not found.');
		foreach ($taxonomy['entries'] as $key => $value) {
			$taxonomy['entries'][$key]['events'] = count($value['existing_tag']['EventTag']);
		}
		$this->set('filter', $filter);
		$customPagination = new CustomPaginationTool();
		$params = $customPagination->createPaginationRules($taxonomy['entries'], $this->passedArgs, 'TaxonomyEntry');
		if ($params['sort'] == 'id') $params['sort'] = 'tag';
		$this->params->params['paging'] = array($this->modelClass => $params);
		$params = $customPagination->applyRulesOnArray($taxonomy['entries'], $params, 'taxonomies');
		if ($this->_isRest()) {
			return $this->RestResponse->viewData($taxonomy, $this->response->type());
		} else {
			$this->set('entries', $taxonomy['entries']);
			$this->set('urlparams', $urlparams);
			$this->set('passedArgs', json_encode($passedArgs));
			$this->set('passedArgsArray', $passedArgs);
			$this->set('taxonomy', $taxonomy['Taxonomy']);
			$this->set('id', $id);
		}
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
		if ($this->_isRest()) {
			return $this->RestResponse->saveSuccessResponse('Taxonomy', 'enable', $id, $this->response->type());
		} else {
			$this->Session->setFlash('Taxonomy enabled.');
			$this->redirect($this->referer());
		}
	}

	public function disable($id) {
		if (!$this->_isSiteAdmin() || !$this->request->is('Post')) throw new MethodNotAllowedException('You don\'t have permission to do that.');
		$taxonomy = $this->Taxonomy->find('first', array(
				'recursive' => -1,
				'conditions' => array('Taxonomy.id' => $id),
		));
		$taxonomy['Taxonomy']['enabled'] = 0;
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
		if ($this->_isRest()) {
			return $this->RestResponse->saveSuccessResponse('Taxonomy', 'disable', $id, $this->response->type());
		} else {
			$this->Session->setFlash('Taxonomy disabled.');
			$this->redirect($this->referer());
		}
	}

	public function update() {
		if (!$this->_isSiteAdmin()) throw new MethodNotAllowedException('You don\'t have permission to do that.');
		$result = $this->Taxonomy->update();
		$this->Log = ClassRegistry::init('Log');
		$fails = 0;
		$successes = 0;
		if (!empty($result)) {
			if (isset($result['success'])) {
				foreach ($result['success'] as $id => $success) {
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
				foreach ($result['fails'] as $id => $fail) {
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
		$message = '';
		if ($successes == 0 && $fails == 0) $message = 'All taxonomy libraries are up to date already.';
		else if ($successes == 0) $message = 'Could not update any of the taxonomy libraries';
		else {
			$message = 'Successfully updated ' . $successes . ' taxonomy libraries.';
			if ($fails != 0) $message .= ' However, could not update ' . $fails . ' taxonomy libraries.';
		}
		if ($this->_isRest()) {
			return $this->RestResponse->saveSuccessResponse('Taxonomy', 'update', false, $this->response->type(), $message);
		} else {
			$this->Session->setFlash($message);
			$this->redirect(array('controller' => 'taxonomies', 'action' => 'index'));
		}
	}

	public function addTag($taxonomy_id = false) {
		if ((!$this->_isSiteAdmin() && !$this->userRole['perm_tagger']) || !$this->request->is('post')) throw new NotFoundException('You don\'t have permission to do that.');
		if ($taxonomy_id) {
			$result = $this->Taxonomy->addTags($taxonomy_id);
		} else {
			if (isset($this->request->data['Taxonomy'])) {
				$this->request->data['Tag'] = $this->request->data['Taxonomy'];
				unset($this->request->data['Taxonomy']);
			}
			if (isset($this->request->data['Tag']['request'])) $this->request->data['Tag'] = $this->request->data['Tag']['request'];
			if (!isset($this->request->data['Tag']['nameList'])) $this->request->data['Tag']['nameList'] = array($this->request->data['Tag']['name']);
			else $this->request->data['Tag']['nameList'] = json_decode($this->request->data['Tag']['nameList'], true);
			$result = $this->Taxonomy->addTags($this->request->data['Tag']['taxonomy_id'], $this->request->data['Tag']['nameList']);
		}
		if ($result) {
			$this->Session->setFlash('The tag(s) has been saved.');
		} else {
			$this->Session->setFlash('The tag(s) could not be saved. Please, try again.');
		}
		$this->redirect($this->referer());
	}

	public function disableTag($taxonomy_id = false) {
		if ((!$this->_isSiteAdmin() && !$this->userRole['perm_tagger']) || !$this->request->is('post')) throw new NotFoundException('You don\'t have permission to do that.');
		if ($taxonomy_id) {
			$result = $this->Taxonomy->disableTags($taxonomy_id);
		} else {
			if (isset($this->request->data['Taxonomy'])) {
				$this->request->data['Tag'] = $this->request->data['Taxonomy'];
				unset($this->request->data['Taxonomy']);
			}
			if (isset($this->request->data['Tag']['request'])) $this->request->data['Tag'] = $this->request->data['Tag']['request'];
			if (!isset($this->request->data['Tag']['nameList'])) $this->request->data['Tag']['nameList'] = array($this->request->data['Tag']['name']);
			else $this->request->data['Tag']['nameList'] = json_decode($this->request->data['Tag']['nameList'], true);
			$result = $this->Taxonomy->disableTags($this->request->data['Tag']['taxonomy_id'], $this->request->data['Tag']['nameList']);
		}
		$this->Session->setFlash($result ? 'The tag(s) has been hidden.' : 'The tag(s) could not be hidden. Please, try again.');
		$this->redirect($this->referer());
	}

	public function taxonomyMassConfirmation($id) {
		if (!$this->_isSiteAdmin() && !$this->userRole['perm_tagger']) throw new NotFoundException('You don\'t have permission to do that.');
		$this->set('id', $id);
		$this->render('ajax/taxonomy_mass_confirmation');
	}

	public function delete($id) {
		if ($this->request->is('post')) {
			$result = $this->Taxonomy->delete($id, true);
			if ($result) {
				$this->Session->setFlash('Taxonomy successfuly deleted.');
				$this->redirect(array('controller' => 'taxonomies', 'action' => 'index'));
			} else {
				$this->Session->setFlash('Taxonomy could not be deleted.');
				$this->redirect(array('controller' => 'taxonomies', 'action' => 'index'));
			}
		} else {
			if ($this->request->is('ajax')) {
				$this->set('id', $id);
				$this->render('ajax/taxonomy_delete_confirmation');
			} else {
				throw new MethodNotAllowedException('This function can only be reached via AJAX.');
			}
		}
	}
}
