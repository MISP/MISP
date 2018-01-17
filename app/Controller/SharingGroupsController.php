<?php
App::uses('AppController', 'Controller');

class SharingGroupsController extends AppController {
	public $components = array('Session', 'RequestHandler');

	public function beforeFilter() {
		parent::beforeFilter();
		if (!empty($this->request->params['admin']) && !$this->_isSiteAdmin()) $this->redirect('/');
		$sgs = $this->SharingGroup->fetchAllAuthorised($this->Auth->user());
		$this->paginate = Set::merge($this->paginate,array('conditions' => array('SharingGroup.id' => $sgs)));
	}

	public $paginate = array(
			'limit' => 60,
			'maxLimit' => 9999,	// LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
			'order' => array(
					'SharingGroup.name' => 'ASC'
			),
			'fields' => array('SharingGroup.id', 'SharingGroup.name', 'SharingGroup.description', 'SharingGroup.releasability', 'SharingGroup.local', 'SharingGroup.active'),
			'contain' => array(
					'SharingGroupOrg' => array(
						'Organisation' => array('fields' => array('Organisation.name', 'Organisation.id', 'Organisation.uuid'))
					),
					'Organisation' => array(
						'fields' => array('Organisation.id', 'Organisation.name', 'Organisation.uuid'),
					),
					'SharingGroupServer' => array(
						'fields' => array('SharingGroupServer.all_orgs'),
						'Server' => array(
							'fields' => array('Server.name', 'Server.id')
						)
					)
			),
	);

	public function add() {
		if (!$this->userRole['perm_sharing_group']) throw new MethodNotAllowedException('You don\'t have the required privileges to do that.');
		$orgs = $this->SharingGroup->Organisation->find('all', array(
			'conditions' => array('local' => 1),
			'recursive' => -1,
			'fields' => array('id', 'name', 'uuid')
		));
		if ($this->request->is('post')) {
			if ($this->_isRest()) {
				$sg = $this->request->data;
				if (isset($this->request->data['SharingGroup'])) {
					$this->request->data = $this->request->data['SharingGroup'];
				}
				$id = $this->SharingGroup->captureSG($this->request->data, $this->Auth->user());
				if ($id) {
					$sg = $this->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'simplified', false, $id);
					return $this->RestResponse->viewData($sg, $this->response->type());
				} else {
					return $this->RestResponse->saveFailResponse('SharingGroup', 'add', false, 'Could not save sharing group.', $this->response->type());
				}
			} else {
				$json = json_decode($this->request->data['SharingGroup']['json'], true);
				$sg = $json['sharingGroup'];
				if (!empty($json['organisations'])) {
					$sg['Organisation'] = $json['organisations'];
				}
				if (!empty($json['servers'])) {
					$sg['Server'] = $json['servers'];
				}
			}
			$this->SharingGroup->create();
			$sg['organisation_uuid'] = $this->Auth->user('Organisation')['uuid'];
			$sg['local'] = 1;
			$sg['org_id'] = $this->Auth->user('org_id');
			$this->request->data['SharingGroup']['organisation_uuid'] = $this->Auth->user('Organisation')['uuid'];
			if ($this->SharingGroup->save(array('SharingGroup' => $sg))) {
				if (!empty($sg['Organisation'])) {
					foreach ($sg['Organisation'] as $org) {
						$this->SharingGroup->SharingGroupOrg->create();
						$this->SharingGroup->SharingGroupOrg->save(array(
								'sharing_group_id' => $this->SharingGroup->id,
								'org_id' => $org['id'],
								'extend' => $org['extend']
						));
					}
				}
				if (!$sg['roaming'] && !empty($sg['Server'])) {
					foreach ($sg['Server'] as $server) {
						$this->SharingGroup->SharingGroupServer->create();
						$this->SharingGroup->SharingGroupServer->save(array(
								'sharing_group_id' => $this->SharingGroup->id,
								'server_id' => $server['id'],
								'all_orgs' => $server['all_orgs']
						));
					}
				}
				$this->redirect('/SharingGroups/view/' . $this->SharingGroup->id);
			} else {
				$validationReplacements = array(
					'notempty' => 'This field cannot be left empty.',
				);
				$validationErrors = $this->SharingGroup->validationErrors;
				$failedField = array_keys($validationErrors)[0];
				$reason = reset($this->SharingGroup->validationErrors)[0];
				foreach ($validationReplacements as $k => $vR) if ($reason == $k) $reason = $vR;
				$this->Session->setFlash('The sharing group could not be added. ' . ucfirst($failedField) . ': ' . $reason);
			}
		} else if ($this->_isRest()) {
			return $this->RestResponse->describe('SharingGroup', 'add', false, $this->response->type());
		}
		$this->set('orgs', $orgs);
		$this->set('localInstance', Configure::read('MISP.baseurl'));
		// We just pass true and allow the user to edit, since he/she is just about to create the SG. This is needed to reuse the view for the edit
		$this->set('user', $this->Auth->user());
	}

	public function edit($id = false) {
		if (!$this->userRole['perm_sharing_group']) throw new MethodNotAllowedException('You don\'t have the required privileges to do that.');
		if (empty($id)) throw new NotFoundException('Invalid sharing group.');
		// add check for perm_sharing_group
		$this->SharingGroup->id = $id;
		if (!$this->SharingGroup->exists()) throw new NotFoundException('Invalid sharing group.');
		if (!$this->_isSiteAdmin() && !$this->SharingGroup->checkIfAuthorisedExtend($this->Auth->user(), $id)) throw new MethodNotAllowedException('Action not allowed.');

		// check if the user is eligible to edit the SG (original creator or extend)
		$sharingGroup = $this->SharingGroup->find('first', array(
			'conditions' => array('SharingGroup.id' => $id),
			'recursive' => -1,
			'contain' => array(
					'SharingGroupOrg' => array(
						'Organisation' => array('name', 'local', 'id')
					),
					'SharingGroupServer' => array(
						'Server' => array(
							'fields' => array('name', 'url', 'id')
						)
					),
					'Organisation' => array(
						'fields' => array('name', 'local', 'id')
					),
			),
		));
		if ($this->request->is('post')) {
			if ($this->_isRest()) {
				if (isset($this->request->data['SharingGroup'])) {
					$this->request->data = $this->request->data['SharingGroup'];
				}
				$this->request->data['uuid'] = $sharingGroup['SharingGroup']['uuid'];
				$id = $this->SharingGroup->captureSG($this->request->data, $this->Auth->user());
				if ($id) {
					$sg = $this->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'simplified', false, $id);
					return $this->RestResponse->viewData($sg, $this->response->type());
				} else {
					return $this->RestResponse->saveFailResponse('SharingGroup', 'add', false, 'Could not save sharing group.', $this->response->type());
				}
			} else {
				$json = json_decode($this->request->data['SharingGroup']['json'], true);
				$sg = $json['sharingGroup'];
				$sg['id'] = $id;
				$fields = array('name', 'releasability', 'description', 'active', 'roaming');
				$existingSG = $this->SharingGroup->find('first', array('recursive' => -1, 'conditions' => array('SharingGroup.id' => $id)));
				foreach ($fields as $field) $existingSG['SharingGroup'][$field] = $sg[$field];
				unset($existingSG['SharingGroup']['modified']);
				if ($this->SharingGroup->save($existingSG)) {
					$this->SharingGroup->SharingGroupOrg->updateOrgsForSG($id, $json['organisations'], $sharingGroup['SharingGroupOrg'], $this->Auth->user());
					$this->SharingGroup->SharingGroupServer->updateServersForSG($id, $json['servers'], $sharingGroup['SharingGroupServer'], $json['sharingGroup']['roaming'], $this->Auth->user());
					$this->redirect('/SharingGroups/view/' . $id);
				} else {
					$validationReplacements = array(
						'notempty' => 'This field cannot be left empty.',
					);
					$validationErrors = $this->SharingGroup->validationErrors;
					$failedField = array_keys($validationErrors)[0];
					$reason = reset($this->SharingGroup->validationErrors)[0];
					foreach ($validationReplacements as $k => $vR) if ($reason == $k) $reason = $vR;
					$this->Session->setFlash('The sharing group could not be edited. ' . ucfirst($failedField) . ': ' . $reason);
				}
			}
		} else if ($this->_isRest()) {
			return $this->RestResponse->describe('SharingGroup', 'edit', false, $this->response->type());
		}
		$orgs = $this->SharingGroup->Organisation->find('all', array(
			'conditions' => array('local' => 1),
			'recursive' => -1,
			'fields' => array('id', 'name')
		));
		$this->set('sharingGroup', $sharingGroup);
		$this->set('id', $id);
		$this->set('orgs', $orgs);
		$this->set('localInstance', Configure::read('MISP.baseurl'));
		// We just pass true and allow the user to edit, since he/she is just about to create the SG. This is needed to reuse the view for the edit
		$this->set('user', $this->Auth->user());
	}

	public function delete($id) {
		if (!$this->userRole['perm_sharing_group']) throw new MethodNotAllowedException('You don\'t have the required privileges to do that.');
		if (!$this->request->is('post')) throw new MethodNotAllowedException('Action not allowed, post request expected.');
		if (!$this->SharingGroup->checkIfOwner($this->Auth->user(), $id)) throw new MethodNotAllowedException('Action not allowed.');
		$deletedSg = $this->SharingGroup->find('first', array(
			'conditions' => array('id' => $id),
			'recursive' => -1,
			'fields' => array('active')
		));
		if ($this->SharingGroup->delete($id)) {
			if ($this->_isRest()) {
				return $this->RestResponse->saveSuccessResponse('SharingGroups', 'delete', $id, $this->response->type());
			}
			$this->Session->setFlash(__('Sharing Group deleted'));
		} else {
			if ($this->_isRest()) {
				return $this->RestResponse->saveFailResponse('SharingGroups', 'delete', $id, 'The sharing group could not be deleted.', $this->response->type());
			}
			$this->Session->setFlash(__('Sharing Group could not be deleted. Make sure that there are no events, attributes or threads belonging to this sharing group.'));
		}

		if ($deletedSg['SharingGroup']['active']) $this->redirect('/SharingGroups/index');
		else $this->redirect('/SharingGroups/index/true');
	}

	public function index($passive = false) {
		if ($passive === 'true') $passive = true;
		if ($passive === true) $this->paginate['conditions'][] = array('SharingGroup.active' => 0);
		else $this->paginate['conditions'][] = array('SharingGroup.active' => 1);
		$result = $this->paginate();
		// check if the current user can modify or delete the SG
		foreach ($result as $k => $sg) {
			if ($sg['Organisation']['uuid'] == $this->Auth->user('Organisation')['uuid'] && $this->userRole['perm_sharing_group']) {
				$result[$k]['editable'] = true;
			} else {
				$result[$k]['editable'] = false;
				if (!empty($sg['SharingGroupOrg'])) {
					foreach ($sg['SharingGroupOrg'] as $sgo) {
						if ($sgo['org_id'] == $this->Auth->user('org_id') && $sgo['extend']) $result[$k]['editable'] = true;
					}
				}
			}
		}
		$this->set('passive', $passive);
		if ($this->_isRest()) {
			$this->set('response', $result);
			$this->set('_serialize', array('response'));
		} else {
			$this->set('sharingGroups', $result);
		}
	}

	public function view($id) {
		if (!$this->SharingGroup->checkIfAuthorised($this->Auth->user(), $id)) throw new MethodNotAllowedException('Sharing group doesn\'t exist or you do not have permission to access it.');
		$this->SharingGroup->id = $id;
		$this->SharingGroup->contain(
			array(
				'SharingGroupOrg' => array(
					'Organisation' => array(
						'fields' => array('id', 'name', 'uuid', 'local')
					)
				),
				'Organisation',
				'SharingGroupServer' => array(
					'Server' => array(
						'fields' => array('id', 'name', 'url')
					)
				)
			)
		);
		$this->SharingGroup->read();
		$sg = $this->SharingGroup->data;
		if (isset($sg['SharingGroupServer'])) {
			foreach ($sg['SharingGroupServer'] as $key => $sgs) {
				if ($sgs['server_id'] == 0) $sg['SharingGroupServer'][$key]['Server'] = array('id' => "0", 'name' => 'Local instance', 'url' => Configure::read('MISP.baseurl'));
			}
		}
		if ($sg['SharingGroup']['sync_user_id']) {
			$this->loadModel('User');
			$sync_user = $this->User->find('first', array(
					'conditions' => array('User.id' => $sg['SharingGroup']['sync_user_id']),
					'recursive' => -1,
					'fields' => array('User.id', 'User.org_id'),
					'contain' => array('Organisation' => array(
						'fields' => array('Organisation.name')
					))
			));
			if (empty($sync_user)) $sg['SharingGroup']['sync_org_name'] = 'N/A';
			$sg['SharingGroup']['sync_org_name'] = $sync_user['Organisation']['name'];
		}
		if ($this->_isRest()) {
			return $this->RestResponse->viewData($sg, $this->response->type());
		}
		$this->set('mayModify', $this->SharingGroup->checkIfAuthorisedExtend($this->Auth->user(), $id));
		$this->set('id', $id);
		$this->set('sg', $sg);
	}
}
