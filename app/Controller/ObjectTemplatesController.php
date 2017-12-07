<?php

App::uses('AppController', 'Controller');

class ObjectTemplatesController extends AppController {
	public $components = array('Security' ,'RequestHandler', 'Session');

	public $paginate = array(
			'limit' => 60,
			'order' => array(
					'Object.id' => 'desc'
			),
			'contain' => array(
				'Organisation' => array('fields' => array('Organisation.id', 'Organisation.name', 'Organisation.uuid'))
			),
			'recursive' => -1
	);

	public function objectChoice($event_id) {
		$this->ObjectTemplate->populateIfEmpty($this->Auth->user());
		$templates_raw = $this->ObjectTemplate->find('all', array(
			'recursive' => -1,
			'conditions' => array('ObjectTemplate.active' => 1),
			'fields' => array('id', 'meta-category', 'name', 'description', 'org_id'),
			'contain' => array('Organisation.name'),
			'sort' => array('ObjectTemplate.name asc')
		));
		$templates = array('all' => array());
		foreach ($templates_raw as $k => $template) {
			unset($template['ObjectTemplate']['meta-category']);
			$template['ObjectTemplate']['org_name'] = $template['Organisation']['name'];
			$templates[$templates_raw[$k]['ObjectTemplate']['meta-category']][] = $template['ObjectTemplate'];
			$templates['all'][] = $template['ObjectTemplate'];
		}
		foreach ($templates as $category => $template_list) {
			$templates[$category] = Hash::sort($templates[$category], '{n}.name');
		}
		$template_categories = array_keys($templates);
		$this->layout = false;
		$this->set('template_categories', $template_categories);
		$this->set('eventId', $event_id);
		$this->set('templates', $templates);
		$this->render('ajax/object_choice');
	}

  public function view($id) {
		$params = array(
			'recursive' => -1,
			'contain' => array(
				'Organisation' => array('fields' => array('Organisation.id', 'Organisation.name', 'Organisation.uuid'))
			),
			'conditions' => array('ObjectTemplate.id' => $id)
		);
		if ($this->_isRest()) {
			$params['contain'][] = 'ObjectTemplateElement';
		}
		if ($this->_isSiteAdmin()) {
				$params['contain']['User']= array('fields' => array('User.id', 'User.email'));
		}
		$objectTemplate = $this->ObjectTemplate->find('first', $params);
		if (empty($objectTemplate)) {
			throw new NotFoundException('Invalid object template');
		}
		if ($this->_isRest()) {
			return $this->RestResponse->viewData($objectTemplate, $this->response->type());
		} else {
			$this->set('id', $id);
			$this->set('template', $objectTemplate);
		}
  }

	public function delete($id) {
		if (!$this->request->is('post') && !$this->request->is('put') && !$this->request->is('delete')) {
			throw new MethodNotAllowedException();
		}
		$this->ObjectTemplate->id = $id;
		if (!$this->ObjectTemplate->exists()) {
			throw new NotFoundException('Invalid ObjectTemplate');
		}
		if ($this->ObjectTemplate->delete()) {
			if ($this->_isRest()) {
				return $this->RestResponse->saveSuccessResponse('ObjectTemplates', 'admin_delete', $id, $this->response->type());
			} else {
				$this->Session->setFlash(__('ObjectTemplate deleted'));
			}
		}
		if ($this->_isRest()) {
			return $this->RestResponse->saveFailResponse('ObjectTemplates', 'admin_delete', $id, $this->ObjectTemplate->validationErrors, $this->response->type());
		} else {
			$this->Session->setFlash('ObjectTemplate could not be deleted');
		}
		$this->redirect($this->referer());
	}

	public function viewElements($id, $context = 'all') {
		$elements = $this->ObjectTemplate->ObjectTemplateElement->find('all', array(
			'conditions' => array('ObjectTemplateElement.object_template_id' => $id)
		));
		$this->set('list', $elements);
		$this->layout = 'ajax';
		$this->render('ajax/view_elements');
	}

	public function index($all = false) {
		if (!$all || !$this->_isSiteAdmin()) {
			$this->paginate['conditions'][] = array('ObjectTemplate.active' => 1);
			$this->set('all', false);
		} else {
			$this->set('all', true);
		}
		if ($this->_isRest()) {
			$rules = $this->paginate;
			unset($rules['limit']);
			unset($rules['order']);
			$objectTemplates = $this->ObjectTemplate->find('all', $rules);
			return $this->RestResponse->viewData($objectTemplates, $this->response->type());
		} else {
			$this->paginate['order'] = array('ObjectTemplate.name' => 'ASC');
			$objectTemplates = $this->paginate();
			$this->set('list', $objectTemplates);
		}
	}

	public function update($type = false, $force = false) {
		if (!empty($this->params['named']['type'])) {
			$type = $this->params['named']['type'];
		}
		if (!empty($this->params['named']['force'])) {
			$force = $this->params['named']['force'];
		}
		$result = $this->ObjectTemplate->update($this->Auth->user(), $type, $force);
		$this->loadModel('ObjectRelationship');
		$result2 = $this->ObjectRelationship->update();
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

	public function activate() {
		$id = $this->request->data['ObjectTemplate']['data'];
		if (!is_numeric($id)) return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Template not found.')), 'status' => 200, 'type' => 'json'));
		$result = $this->ObjectTemplate->setActive($id);
		if ($result === false) {
			return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Template\'s state could not be toggeled.')), 'status' => 200, 'type' => 'json'));
		}
		$message = (($result == 1) ? 'activated' : 'disabled');
		return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Template ' . $message . '.')), 'status' => 200, 'type' => 'json'));
	}

	public function getToggleField() {
		if (!$this->request->is('ajax')) throw new MethodNotAllowedException('This action is available via AJAX only.');
		$this->layout = 'ajax';
		$this->render('ajax/getToggleField');
	}
}
