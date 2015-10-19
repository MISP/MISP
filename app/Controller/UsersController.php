<?php
App::uses('AppController', 'Controller');

/**
 * Users Controller
 *
 * @property User $User
 */
class UsersController extends AppController {

	public $newkey;

	public $components = array(
			'Security',
			'Email',
			);

	public $paginate = array(
			'limit' => 60,
			'order' => array(
					'User.org' => 'ASC'
			)
	);

	public function beforeFilter() {
		parent::beforeFilter();

		// what pages are allowed for non-logged-in users
		$this->Auth->allow('login', 'logout');
	}

/**
 * view method
 *
 * @param string $id
 * @return void
 * @throws NotFoundException
 */
	public function view($id = null) {
		if ("me" == $id) $id = $this->Auth->user('id');
		if (!$this->_isSiteAdmin() && $this->Auth->user('id') != $id) {
			throw new NotFoundException(__('Invalid user or not authorised.'));
		}
		$this->User->id = $id;
		$this->User->recursive = 0;
		if (!$this->User->exists()) {
			throw new NotFoundException(__('Invalid user'));
		}
		$this->set('user', $this->User->read(null, $id));
	}

/**
 * edit method
 *
 * @param string $id
 * @return void
 * @throws NotFoundException
 */
	public function edit($id = null) {
		$me = false;
		if ("me" == $id) {
			$id = $this->Auth->user('id');
			$me = true;
		}
		$this->User->read(null, $id);
		if (!$this->User->exists() && !$me && !$this->_isSiteAdmin() && !($this->_isAdmin() && $this->Auth->user('org') == $this->User->data['User']['org'])) {
			throw new NotFoundException(__('Invalid user or not authorised.'));
		}
		if ($this->request->is('post') || $this->request->is('put')) {
			// What fields should be saved (allowed to be saved)
			$fieldList = array('email', 'autoalert', 'gpgkey', 'nids_sid', 'contactalert');
			if ("" != $this->request->data['User']['password'])
				$fieldList[] = 'password';
			// Save the data
			if ($this->User->save($this->request->data, true ,$fieldList)) {
				$this->Session->setFlash(__('The profile has been updated'));
				$this->_refreshAuth();
				$this->redirect(array('action' => 'view', $id));
			} else {
				$this->Session->setFlash(__('The profile could not be updated. Please, try again.'));
			}
		} else {
			$this->User->recursive = 0;
			$this->User->read(null, $id);
			if (!$this->User->exists() || (!$this->_isSiteAdmin() && $this->Auth->user('org') != $this->User->data['User']['org'])) {
				throw new NotFoundException(__('Invalid user or not authorised.'));
			}
			$this->User->set('password', '');
			$this->request->data = $this->User->data;
		}
		$roles = $this->User->Role->find('list');
		$this->set(compact('roles'));
		$this->set('id', $id);
	}

	public function change_pw() {
		$id = $this->Auth->user('id');
		$this->User->id = $id;
		if ($this->request->is('post') || $this->request->is('put')) {
			// What fields should be saved (allowed to be saved)
			$fieldList[] = 'password';
			// Save the data
			if ($this->User->save($this->request->data, true ,$fieldList)) {
				$this->Session->setFlash(__('Password Changed.'));
				$this->User->saveField('email', $this->Auth->user('email'));
				$this->User->saveField('change_pw', 0);
				$this->_refreshAuth();
				$this->redirect(array('action' => 'view', $id));
			} else {
				$this->Session->setFlash(__('The password could not be updated. Please, try again.'));
			}
		} else {
			$this->User->recursive = 0;
			$this->User->read(null, $id);
			$this->User->set('password', '');
			$this->request->data = $this->User->data;
		}
		// XXX ACL roles
		$this->extraLog("change_pw");
		$roles = $this->User->Role->find('list');
		$this->set(compact('roles'));
	}

/**
 * delete method
 *
 * @param string $id
 * @return void
 * @throws MethodNotAllowedException
 * @throws NotFoundException
 */
	public function delete($id = null) {
		if ("me" == $id) $id = $this->Auth->user('id');
		if (!$this->request->is('post')) {
			throw new MethodNotAllowedException();
		}
		$this->User->id = $id;
		if (!$this->User->exists()) {
			throw new NotFoundException(__('Invalid user'));
		}
		//if ($this->Auth->User('org') != 'ADMIN' && $this->Auth->User('org') != $this->User->data['User']['org']) $this->redirect(array('controller' => 'users', 'action' => 'index', 'admin' => true));
		//// Only own profile
		//if ($this->Auth->user('id') != $id) {
		//	throw new ForbiddenException('You are not authorized to delete this profile.');
		//}
		if ($this->User->delete()) {
			$this->Session->setFlash(__('User deleted'));
			$this->redirect(array('action' => 'index'));
		}
		$this->Session->setFlash(__('User was not deleted'));
		$this->redirect(array('action' => 'index'));
	}
/**
 * admin_index method
 *
 * @return void
 */
	public function admin_index() {
		$this->User->virtualFields['org_ci'] = 'UPPER(User.org)';
		$urlparams = "";
		$passedArgsArray = array();
		$booleanFields = array('autoalert', 'contactalert', 'termsaccepted');
		$textFields = array('role', 'email');
		// org admins can't see users of other orgs
		if ($this->_isSiteAdmin()) $textFields[] = 'org';
		
		
		// check each of the passed arguments whether they're a filter (could also be a sort for example) and if yes, add it to the pagination conditions
		foreach ($this->passedArgs as $k => $v) {
			if (substr($k, 0, 6) === 'search') {
				if ($v != "") {
					if ($urlparams != "") $urlparams .= "/";
					$urlparams .= $k . ":" . $v;
				}
				$searchTerm = substr($k, 6);
				if (in_array($searchTerm, $booleanFields)) {
					if ($v != "") $this->paginate['conditions'][] = array('User.' . $searchTerm => $v);
				} else if (in_array($searchTerm, $textFields)) {
					if ($v != "") {
						if ($searchTerm == "role") $searchTerm = "role_id";
						$pieces = explode('|', $v);
						$test = array();
						foreach ($pieces as $piece) {
							if ($piece[0] == '!') {
								if ($searchTerm == 'email' || $searchTerm == 'org') $this->paginate['conditions']['AND'][] = array('LOWER(User.' . $searchTerm . ') NOT LIKE' => '%' . strtolower(substr($piece, 1)) . '%');
								else $this->paginate['conditions']['AND'][] = array('User.' . $searchTerm => substr($piece, 1));
							} else {
								if ($searchTerm == 'email' || $searchTerm == 'org') $test['OR'][] = array('LOWER(User.' . $searchTerm . ') LIKE' => '%' . strtolower($piece) . '%');
								else $test['OR'][] = array('User.' . $searchTerm => $piece);
							}
						}
						if (!empty($test)) $this->paginate['conditions']['AND'][] = $test;
					}
				}
				$passedArgsArray[$searchTerm] = $v;
			}
		}
		$this->set('urlparams', $urlparams);
		$this->set('passedArgsArray', $passedArgsArray);
		$this->User->recursive = 0;
		$conditions = array();
		if ($this->_isSiteAdmin()) {
			$this->set('users', $this->paginate());
		} else {
			if (!($this->_isAdmin())) throw new NotFoundException(__('Invalid user or not authorised.'));
			$conditions['User.org LIKE'] = $this->Auth->User('org');
			$this->paginate = array(
					'conditions' => array($conditions),
			);
			$this->set('users', $this->paginate());
		}
	}

	public function admin_filterUserIndex() {
		if (!$this->_isAdmin() && !$this->_isSiteAdmin()) throw new MethodNotAllowedException();
		$passedArgsArray = array();
		$booleanFields = array('autoalert', 'contactalert', 'termsaccepted');
		$textFields = array('role', 'email');
		$showorg = 0;
		// org admins can't see users of other orgs
		if ($this->_isSiteAdmin()) {
			$textFields[] = 'org';
			$showorg = 1;
		}
		$this->set('differentFilters', $booleanFields);
		$this->set('simpleFilters', $textFields);
		$rules = array_merge($booleanFields, $textFields);
		$this->set('showorg', $showorg);
		
		$filtering = array();
		foreach ($booleanFields as $b) {
			$filtering[$b] = '';
		}
		foreach ($textFields as $t) {
			$filtering[$t] = array('OR' => array(), 'NOT' => array());
		}
	
		foreach ($this->passedArgs as $k => $v) {
			if (substr($k, 0, 6) === 'search') {
				$searchTerm = substr($k, 6);
				if (in_array($searchTerm, $booleanFields)) $filtering[$searchTerm] = $v;
				else if (in_array($searchTerm, $textFields)) {
					$pieces = explode('|', $v);
					foreach ($pieces as $piece) {
						if ($piece[0] == '!') $filtering[$searchTerm]['NOT'][] = substr($piece,1);
						else $filtering[$searchTerm]['OR'][] = $piece;
					}
				}
				$passedArgsArray[$searchTerm] = $v;
			}
		}
		$this->set('filtering', json_encode($filtering));
		
		$roles = $this->User->Role->find('all', array('recursive' => -1));
		$roleNames = array();
		$roleJSON = array();
		foreach ($roles as $k => $v) {
			$roleNames[$v['Role']['id']] = $v['Role']['name'];
			$roleJSON[] = array('id' => $v['Role']['id'], 'value' => $v['Role']['name']);
		}
		$this->set('roles', $roleNames);
		$this->set('roleJSON', json_encode($roleJSON));
/*
		$conditions = array();
		if (!$this->_isSiteAdmin()) {
			$conditions = array('OR' => array(array('orgc' => $this->Auth->User('org')), array('distribution' > 0)));
		}
		$events = $this->Event->find('all', array(
				'recursive' => -1,
				'fields' => array('orgc', 'distribution'),
				'conditions' => $conditions,
				'group' => 'orgc'
		));
		
		if (Configure::read('MISP.showorg') != 'false') {
			$orgs = array();
			foreach ($events as $e) {
				$orgs[] = $e['Event']['orgc'];
			}
			$orgs = $this->_arrayToValuesIndexArray($orgs);
			$this->set('showorg', true);
			$this->set('orgs', $orgs);
			$rules[] = 'org';
		} else {
			$this->set('showorg', false);
		}
	*/
		$rules = $this->_arrayToValuesIndexArray($rules);
		$this->set('rules', $rules);
		$this->set('baseurl', Configure::read('MISP.baseurl'));
		$this->layout = 'ajax';
	}

/**
 * admin_view method
 *
 * @param string $id
 * @return void
 * @throws NotFoundException
 */
	public function admin_view($id = null) {
		$this->User->id = $id;
		if (!$this->User->exists()) {
			throw new NotFoundException(__('Invalid user'));
		}
		$this->set('user', $this->User->read(null, $id));
		if (!$this->_isSiteAdmin() && !($this->_isAdmin() && $this->Auth->user('org') == $this->User->data['User']['org'])) throw new MethodNotAllowedException();
		$temp = $this->User->field('invited_by');
		$this->set('id', $id);
		$this->set('user2', $this->User->read(null, $temp));
	}

/**
 * admin_add method
 *
 * @return void
 */
	public function admin_add() {
		if (!$this->_isAdmin()) throw new Exception('Administrators only.');
		$this->set('currentOrg', $this->Auth->User('org'));
		$this->set('isSiteAdmin', $this->_isSiteAdmin());
		$params = null;
		if (!$this->_isSiteAdmin()) {
			$params = array('conditions' => array('perm_site_admin !=' => 1, 'perm_sync !=' => 1, 'perm_regexp_access !=' => 1));
		}
		$roles = $this->User->Role->find('list', $params);
		if ($this->request->is('post')) {
			$this->User->create();
			// set invited by
			$this->loadModel('Role');
			$this->Role->recursive = -1;
			$chosenRole = $this->Role->findById($this->request->data['User']['role_id']);
			$this->request->data['User']['invited_by'] = $this->Auth->user('id');
			if ($chosenRole['Role']['perm_sync']) {
				$this->request->data['User']['change_pw'] = 0;
				$this->request->data['User']['termsaccepted'] = 1;
			} else {
				$this->request->data['User']['change_pw'] = 1;
				$this->request->data['User']['termsaccepted'] = 0;
			}
			$this->request->data['User']['newsread'] = '2000-01-01';
			if (!$this->_isSiteAdmin()) {
				$this->request->data['User']['org'] = $this->Auth->User('org');
				if ($chosenRole['Role']['perm_site_admin'] == 1 || $chosenRole['Role']['perm_regexp_access'] == 1 || $chosenRole['Role']['perm_sync'] == 1) {
					throw new Exception('You are not authorised to assign that role to a user.');
				}
			}
			if ($this->User->save($this->request->data)) {
				$this->Session->setFlash(__('The user has been saved'));
				$this->redirect(array('action' => 'index'));
			} else {
				// reset auth key for a new user
				$this->set('authkey', $this->newkey);
				$this->Session->setFlash(__('The user could not be saved. Please, try again.'));
			}
		} else {
			// generate auth key for a new user
			$this->newkey = $this->User->generateAuthKey();
			$this->set('authkey', $this->newkey);
		}
		$this->set(compact('roles'));
	}

/**
 * admin_edit method
 *
 * @param string $id
 * @return void
 * @throws NotFoundException
 */
	public function admin_edit($id = null) {
		//debug($fields);debug(tru);
		$this->set('currentOrg', $this->Auth->User('org'));
		$this->User->id = $id;
		if (!$this->User->exists()) {
			throw new NotFoundException(__('Invalid user'));
		}
		$params = null;
		if (!$this->_isSiteAdmin()) {
			// Org admins should be able to select the role that is already assigned to an org user when editing them.
			// What happened previously:
			// Org admin edits another org admin of the same org
			// Org admin is not allowed to set privileged access roles (site_admin/sync/regex)
			// MISP automatically chooses the first available option for the user as the selected setting (usually user)
			// Org admin is downgraded to a user
			// Now we make an exception for the already assigned role, both in the form and the actual edit.
			$userToEdit = $this->User->find('first', array(
				'conditions' => array('id' => $id),
				'recursive' => -1,
				'fields' => array('id', 'role_id', 'email'),
			));
			$allowedRole = $userToEdit['User']['role_id'];
			$params = array('conditions' => array(
					'OR' => array(
							'AND' => array(
								'perm_site_admin' => 0, 'perm_sync' => 0, 'perm_regexp_access' => 0
							),
							'id' => $allowedRole,
					)
			));
		}
		$roles = $this->User->Role->find('list', $params);
		$this->set('currentId', $id);
		if ($this->request->is('post') || $this->request->is('put')) {
			$fields = array();
			foreach (array_keys($this->request->data['User']) as $field) {
				if($field != 'password') array_push($fields, $field);
			}
			// TODO Audit, extraLog, fields get orig
			$fieldsOldValues = array();
			foreach ($fields as $field) {
				if($field != 'confirm_password') array_push($fieldsOldValues, $this->User->field($field));
				else array_push($fieldsOldValues, $this->User->field('password'));
			}
			// TODO Audit, extraLog, fields get orig END
			if ("" != $this->request->data['User']['password'])
				$fields[] = 'password';
			$fields[] = 'role_id';
			if (!$this->_isSiteAdmin()) {
				$this->loadModel('Role');
				$this->Role->recursive = -1;
				$chosenRole = $this->Role->findById($this->request->data['User']['role_id']);
				if (($chosenRole['Role']['id'] != $allowedRole) && ($chosenRole['Role']['perm_site_admin'] == 1 || $chosenRole['Role']['perm_regexp_access'] == 1 || $chosenRole['Role']['perm_sync'] == 1)) {
					throw new Exception('You are not authorised to assign that role to a user.');
				}
			}
			if ($this->User->save($this->request->data, true, $fields)) {
				// TODO Audit, extraLog, fields compare
				// newValues to array
				$fieldsNewValues = array();
				foreach ($fields as $field) {
					if ($field != 'confirm_password') {
						$newValue = $this->data['User'][$field];
						if (gettype($newValue) == 'array') {
							$newValueStr = '';
							$cP = 0;
							foreach ($newValue as $newValuePart) {
								if ($cP < 2) $newValueStr .= '-' . $newValuePart;
								else $newValueStr = $newValuePart . $newValueStr;
								$cP++;
							}
							array_push($fieldsNewValues, $newValueStr);
						}
						else array_push($fieldsNewValues, $newValue);
					}
					else array_push($fieldsNewValues, $this->data['User']['password']);
				}
				// compare
				$fieldsResultStr = '';
				$c = 0;
				foreach ($fields as $field) {
					if (isset($fieldsOldValues[$c]) && $fieldsOldValues[$c] != $fieldsNewValues[$c]) {
						if($field != 'confirm_password') $fieldsResultStr = $fieldsResultStr . ', ' . $field . ' (' . $fieldsOldValues[$c] . ') => (' . $fieldsNewValues[$c] . ')';
					}
					$c++;
				}
				$fieldsResultStr = substr($fieldsResultStr, 2);
				$this->extraLog("edit", "user", $fieldsResultStr);	// TODO Audit, check: modify User
				// TODO Audit, extraLog, fields compare END
				$this->Session->setFlash(__('The user has been saved'));
				$this->_refreshAuth(); // in case we modify ourselves
				$this->redirect(array('action' => 'index'));
			} else {
				$this->Session->setFlash(__('The user could not be saved. Please, try again.'));
			}
		} else {
			$this->User->recursive = 0;
			$this->User->read(null, $id);
			if (!$this->_isSiteAdmin() && $this->Auth->User('org') != $this->User->data['User']['org']) $this->redirect(array('controller' => 'users', 'action' => 'index', 'admin' => true));
			$this->User->set('password', '');
			$this->request->data = $this->User->data; // TODO CHECK

		}
		$this->set('id', $id);
		$this->set(compact('roles'));
	}

/**
 * admin_delete method
 *
 * @param string $id
 * @return void
 * @throws MethodNotAllowedException
 * @throws NotFoundException
 */
	public function admin_delete($id = null) {
		if (!$this->request->is('post')) {
			throw new MethodNotAllowedException();
		}
		if (!$this->_isAdmin()) throw new Exception('Administrators only.');
		$this->User->id = $id;
		$user = $this->User->read('email', $id);
		$fieldsDescrStr = 'User (' . $id . '): ' . $user['User']['email'];
		if (!$this->User->exists()) {
			throw new NotFoundException(__('Invalid user'));
		}
		if ($this->User->delete()) {
			$this->extraLog("delete", $fieldsDescrStr, '');	// TODO Audit, check: modify User
			$this->Session->setFlash(__('User deleted'));
			$this->redirect(array('action' => 'index'));
		}
		$this->Session->setFlash(__('User was not deleted'));
		$this->redirect(array('action' => 'index'));
	}

	public function login() {
		if ($this->Auth->login()) {
			$this->extraLog("login");	// TODO Audit, extraLog, check: customLog i.s.o. extraLog, no auth user?: $this->User->customLog('login', $this->Auth->user('id'), array('title' => '','user_id' => $this->Auth->user('id'),'email' => $this->Auth->user('email'),'org' => 'IN2'));
			// TODO removed the auto redirect for now, due to security concerns - will look more into this
			// $this->redirect($this->Auth->redirectUrl());
			$this->redirect(array('controller' => 'events', 'action' => 'index'));
		} else {
			// don't display authError before first login attempt
			if (str_replace("//","/",$this->webroot . $this->Session->read('Auth.redirect')) == $this->webroot && $this->Session->read('Message.auth.message') == $this->Auth->authError) {
				$this->Session->delete('Message.auth');
			}
			// don't display "invalid user" before first login attempt
			if($this->request->is('post')) {
				$this->Session->setFlash(__('Invalid username or password, try again'));
			}
			// populate the DB with the first role (site admin) if it's empty
			$this->loadModel('Role');
			if ($this->Role->find('count') == 0 ) {
				$siteAdmin = array('Role' => array(
					'id' => 1,
					'name' => 'Site Admin',
					'perm_add' => 1,
					'perm_modify' => 1,
					'perm_modify_org' => 1,
					'perm_publish' => 1,
					'perm_sync' => 1,
					'perm_admin' => 1,
					'perm_audit' => 1,
					'perm_auth' => 1,
					'perm_site_admin' => 1,
					'perm_regexp_access' => 1,
					'perm_tagger' => 1,
					'perm_site_admin' => 1
				));
				$this->Role->save($siteAdmin);
			}	
			// populate the DB with the first user if it's empty
			if ($this->User->find('count') == 0 ) {
				$admin = array('User' => array(
					'id' => 1,
					'email' => 'admin@admin.test',
					'org' => 'ADMIN',
					'password' => 'admin',
					'confirm_password' => 'admin',
					'authkey' => $this->User->generateAuthKey(),
					'nids_sid' => 4000000,
					'newsread' => date('Y-m-d'),
					'role_id' => 1,
					'change_pw' => 1
				));
				$this->User->validator()->remove('password'); // password is to simple, remove validation
				$this->User->save($admin);
			}
		}
	}

	public function routeafterlogin() {
		// Terms and Conditions Page
		if (!$this->Auth->user('termsaccepted')) {
			$this->redirect(array('action' => 'terms'));
		}
		// Events list
		$this->redirect(array('controller' => 'events', 'action' => 'index'));
	}

	public function logout() {
		if ($this->Session->check('Auth.User')) { // TODO session, user is logged in, so ..
			$this->extraLog("logout");	// TODO Audit, extraLog, check: customLog i.s.o. extraLog, $this->User->customLog('logout', $this->Auth->user('id'), array());
		}
		$this->Session->setFlash(__('Good-Bye'));
		$this->redirect($this->Auth->logout());
	}
	
	public function resetauthkey($id = null) {
		if (!$id) {
			$this->Session->setFlash(__('Invalid id for user', true), 'default', array(), 'error');
			$this->redirect(array('action' => 'view', $this->Auth->user('id')));
		}
		// reset the key
		$this->User->id = $id;
		if (!$this->User->exists($id)) {
			$this->Session->setFlash(__('Invalid id for user', true), 'default', array(), 'error');
			$this->redirect(array('action' => 'view', $this->Auth->user('id')));
		}
		$this->User->read();
		if ('me' == $id ) $id = $this->Auth->user('id');
		else if (!$this->_isSiteAdmin() && !($this->_isAdmin() && $this->Auth->user('org') == $this->User->data['User']['org']) && ($this->Auth->user('id') != $id)) throw new MethodNotAllowedException();
		$newkey = $this->User->generateAuthKey();
		$this->User->saveField('authkey', $newkey);
		$this->Session->setFlash(__('New authkey generated.', true));
		$this->_refreshAuth();
		$this->redirect($this->referer());
	}

	public function memberslist() {
		// Orglist
		$fields = array('User.org', 'count(User.id) as `num_members`');
		$params = array('recursive' => 0,
							'fields' => $fields,
							'group' => array('User.org'),
							'order' => array('UPPER(User.org)'),
		);
		$orgs = $this->User->find('all', $params);
		$this->set('orgs', $orgs);
	}
	
	public function histogram($selected = null) {
		if (!$this->request->is('ajax')) throw new MethodNotAllowedException('This function can only be accessed via AJAX.');
		if ($selected == '[]') $selected = null;
		$selectedTypes = array();
		if ($selected) $selectedTypes = json_decode($selected);
		$temp = $this->User->Event->find('all', array(
			'recursive' => -1,
			'fields' => array('distinct(orgc)'),
		));
		$orgs = array();
		foreach ($temp as $t) {
			$orgs[] = $t['Event']['orgc'];
		}
		// What org posted what type of attribute
		$this->loadModel('Attribute');
		$conditions = array();
		if ($selected) $conditions[] = array('Attribute.type' => $selectedTypes);
		$fields = array('Event.orgc', 'Attribute.type', 'count(Attribute.type) as `num_types`');
		$params = array('recursive' => 0,
				'fields' => $fields,
				'group' => array('Attribute.type', 'Event.orgc'),
				'order' => array('Event.orgc', 'num_types DESC'),
				'conditions' => $conditions,
		);
		$temp = $this->Attribute->find('all', $params);
		$data = array();
		foreach ($orgs as $k => $org) {
			$data[$org]['total'] = 0;
			$data[$org]['data'] = array();
			foreach ($temp as $t) {
				if ($t['Event']['orgc'] == $org) {
					$data[$org]['data'][$t['Attribute']['type']] = $t[0]['num_types'];
				}
			}
		}
		$max = 1;
		foreach ($data as &$d) {
			foreach ($d['data'] as $t) {
				$d['total'] += $t;
			}
			if ($d['total'] > $max) $max = $d['total'];
		}
		$this->set('data', $data);
		$this->set('max', $max);
		$this->set('selectedTypes', $selectedTypes);
		
		// Nice graphical histogram
		$this->loadModel('Attribute');
		$sigTypes = array_keys($this->Attribute->typeDefinitions);

		App::uses('ColourPaletteTool', 'Tools');
		$paletteTool = new ColourPaletteTool();
		$colours = $paletteTool->createColourPalette(count($sigTypes));
		$typeDb = array();
		foreach($sigTypes as $k => $type) {
			$typeDb[$type] = $colours[$k]; 
		}
		$this->set('typeDb', $typeDb);
		$this->set('sigTypes', $sigTypes);
		$graphInterval = $this->_getIntervals($max);
		$this->layout = 'ajax';
	}
	
	private function _getIntervals($max) {
		$intervals = array();
		if ($max > 5) {
			$maxDecimals = strlen((string) $max);
			//$graphInterval = $max / 10;
			$graphInterval = round($max, -($maxDecimals-2), PHP_ROUND_HALF_DOWN);
			$graphInterval = round($graphInterval / 5);
			for ($i=0; $i<$max; $i+=$graphInterval) {
				$intervals[] = $i;
			}
		} else {
			for ($i=0; $i<$max; $i++) $intervals[] = $i;
		}
		return $intervals;
	}
	
	private function _generateColours($count){
		$pallette = 16777216;
		$array = array();
		$interval = ceil($pallette / $count);
		$colours = array();
		for ($i = 0; $i < $count; $i++) {
			$temp = $i * $interval;
			$array[$i] = $temp;
			$colours[$i] = $this->_convertToHex($temp);
		}
		return $colours;
	}
	
	private function _convertToHex($int) {
		$hex = strval(dechex($int));
		$filler = '';
		for ($i = 0; $i < 6 - (strlen($hex)); $i++) $filler .= '0';
		$filler = '#' . $filler . $hex;
		return $filler;
	}

	public function terms() {
		if ($this->request->is('post') || $this->request->is('put')) {
			$this->User->id = $this->Auth->user('id');
			$this->User->saveField('termsaccepted', true);
			$this->_refreshAuth(); // refresh auth info
			$this->Session->setFlash(__('You accepted the Terms and Conditions.'));
			$this->redirect(array('action' => 'routeafterlogin'));
		}
		$this->set('termsaccepted', $this->Auth->user('termsaccepted'));
	}
	
	public function downloadTerms() {
		if (!Configure::read('MISP.terms_file')) {
			$termsFile = APP ."View/Users/terms";
		} else {
			$termsFile = APP . 'files' . DS . 'terms' . DS .  Configure::read('MISP.terms_file');
		}
		$this->response->file($termsFile, array('download' => true, 'name' => Configure::read('MISP.terms_file')));
		return $this->response;
	}

	public function extraLog($action = null, $description = null, $fieldsResult = null) {	// TODO move audit to AuditsController?
		// new data
		$userId = $this->Auth->user('id');
		$model = 'User';
		$modelId = $this->Auth->user('id');
		if ($action == 'login') {
			$description = "User (" . $this->Auth->user('id') . "): " . $this->data['User']['email'];
		} elseif ($action == 'logout') {
			$description = "User (" . $this->Auth->user('id') . "): " . $this->Auth->user('email');
		} elseif ($action == 'edit') {
			$description = "User (" . $this->User->id . "): " . $this->data['User']['email'];
		} elseif ($action == 'change_pw') {
			$description = "User (" . $this->User->id . "): " . $this->data['User']['email'];
			$fieldsResult = "Password changed.";
		}

		// query
		$this->Log = ClassRegistry::init('Log');
		$this->Log->create();
		$this->Log->save(array(
			'org' => $this->Auth->user('org'),
			'email' => $this->Auth->user('email'),
			'action' => $action,
			'title' => $description,
			'change' => $fieldsResult));

		// write to syslogd as well
		App::import('Lib', 'SysLog.SysLog');
		$syslog = new SysLog();
		if ($fieldsResult) $syslog->write('notice', $description . ' -- ' . $action . ' -- ' . $fieldsResult);
		else $syslog->write('notice', $description . ' -- ' . $action);
	}

/**
 * Used for fields_before and fields for audit
 *
 * @param $array
 */
	public function arrayCopy(array $array) {
		$result = array();
		foreach ($array as $key => $val) {
			if (is_array( $val)) {
				$result[$key] = arrayCopy($val);
			} elseif (is_object($val)) {
				$result[$key] = clone $val;
			} else {
				$result[$key] = $val;
			}
		}
		return $result;
	}

/**
 * @throws NotFoundException
 **/
	public function checkAndCorrectPgps() {
		if (!self::_isAdmin()) throw new NotFoundException();

		$this->set('fails', $this->User->checkAndCorrectPgps());
	}

	public function admin_email() {
		if (!$this->_isAdmin()) throw new MethodNotAllowedException();
		// User has filled in his contact form, send out the email.
		if ($this->request->is('post') || $this->request->is('put')) {
			$conditions = array();
			if (!$this->_isSiteAdmin()) $conditions = array('org' => $this->Auth->user('org'));
			if ($this->request->data['User']['recipient'] != 1) $conditions['id'] = $this->request->data['User']['recipientEmailList'];
			$users = $this->User->find('all', array('recursive' => -1, 'order' => array('email ASC'), 'conditions' => $conditions));
			$this->request->data['User']['message'] = $this->User->adminMessageResolve($this->request->data['User']['message']);
			$failures = '';
			foreach ($users as $user) {
				$password = $this->User->generateRandomPassword();
				$body = str_replace('$password', $password, $this->request->data['User']['message']);
				$body = str_replace('$username', $user['User']['email'], $body);
				$result = $this->User->sendEmail($user, $body, false, $this->request->data['User']['subject']);
				// if sending successful and action was a password change, update the user's password.
				if ($result && $this->request->data['User']['action'] != '0') {
					$this->User->id = $user['User']['id'];
					$this->User->saveField('password', $password);
					$this->User->saveField('change_pw', '1');
				}
				if (!$result) {
					if ($failures != '') $failures .= ', ';
					$failures .= $user['User']['email'];
				}
			}
			if ($failures != '') $this->Session->setFlash(__('E-mails sent, but failed to deliver the messages to the following recipients: ' . $failures));
			else $this->Session->setFlash(__('E-mails sent.'));
		}
		$conditions = array();
		if (!$this->_isSiteAdmin()) $conditions = array('org' => $this->Auth->user('org'));
		$temp = $this->User->find('all', array('recursive' => -1, 'fields' => array('id', 'email'), 'order' => array('email ASC'), 'conditions' => $conditions));
		$emails = array();
		$gpgKeys = array();
		// save all the emails of the users and set it for the dropdown list in the form
		foreach ($temp as $user) {
			$emails[$user['User']['id']] = $user['User']['email'];
		}
		$this->set('users', $temp);
		$this->set('recipientEmail', $emails);
		$this->set('org', Configure::read('MISP.org'));
		$textsToFetch = array('newUserText', 'passwordResetText');
		$this->loadModel('Server');
		foreach ($textsToFetch as $text) {
			${$text} = Configure::read('MISP.' . $text);
			if (!${$text}) ${$text} = $this->Server->serverSettings['MISP'][$text]['value'];
			$this->set($text, ${$text});
		}
	}

	public function initiatePasswordReset($id, $firstTime = false) {
		if (!$this->_isAdmin()) throw new MethodNotAllowedException('You are not authorised to do that.');
		$user = $this->User->find('first', array(
			'conditions' => array('id' => $id),
			'recursive' => -1
		));
		if (!$this->_isSiteAdmin() && $this->Auth->user('org') != $user['User']['org']) throw new MethodNotAllowedException('You are not authorised to do that.');
		if ($this->request->is('post')) {
			if (isset($this->request->data['User']['firstTime'])) $firstTime = $this->request->data['User']['firstTime']; 
			$org = Configure::read('MISP.org');
			$options = array('passwordResetText', 'newUserText');
			$subjects = array('[' . $org . ' MISP] New user registration', '[' . $org .  ' MISP] Password reset');
			$textToFetch = $options[($firstTime ? 0 : 1)];
			$subject = $subjects[($firstTime ? 0 : 1)]; 
			$this->loadModel('Server');
			$body = Configure::read('MISP.' . $textToFetch);
			if (!$body) $body = $this->Server->serverSettings['MISP'][$textToFetch]['value'];
			$body = $this->User->adminMessageResolve($body);
			$password = $this->User->generateRandomPassword();
			$body = str_replace('$password', $password, $body);
			$body = str_replace('$username', $user['User']['email'], $body);
			$result = $this->User->sendEmail($user, $body, false, $subject);
			if ($result) {
				$this->User->id = $user['User']['id'];
				$this->User->saveField('password', $password);
				$this->User->saveField('change_pw', '1');
				return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'New credentials sent.')),'status'=>200));
			}
			return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'There was an error notifying the user. His/her credentials were not altered.')),'status'=>200));
		} else {
			$this->layout = 'ajax';
			$this->set('user', $user);
			$this->set('firstTime', $firstTime);
			$this->render('ajax/passwordResetConfirmationForm');
		}
	}
	
	// shows some statistics about the instance
	public function statistics() {
		
		// set all of the data up for the heatmaps
		$orgs = $this->User->find('all', array('fields' => array('DISTINCT (org) AS org'), 'recursive' => -1));
		$this->loadModel('Log');
		$year = date('Y');
		$month = date('n');
		$day = date('j');
		$month = $month - 5;
		if ($month < 1) {
			$year--;
			$month = 12 + $month;
		}

		// Some additional satistics
		$this_month = strtotime('first day of this month');
		$stats[0] = $this->User->Event->find('count', null);
		$stats[1] = $this->User->Event->find('count', array('conditions' => array('Event.timestamp >' => $this_month)));

		$stats[2] = $this->User->Event->Attribute->find('count', null);
		$stats[3] = $this->User->Event->Attribute->find('count', array('conditions' => array('Attribute.timestamp >' => $this_month)));
		
		$this->loadModel('Correlation');
		$this->Correlation->recursive = -1;
		$stats[4] = $this->Correlation->find('count', null);
		$stats[4] = $stats[4] / 2;
		
		$stats[5] = $this->User->Event->ShadowAttribute->find('count', null);
		
		$stats[6] = $this->User->find('count', null);
		$stats[7] = count($orgs);
		
		$this->loadModel('Thread');
		$stats[8] = $this->Thread->find('count', array('conditions' => array('Thread.post_count >' => 0)));
		$stats[9] = $this->Thread->find('count', array('conditions' => array('Thread.date_created >' => date("Y-m-d H:i:s",$this_month), 'Thread.post_count >' => 0)));

		$stats[10] = $this->Thread->Post->find('count', null);
		$stats[11] = $this->Thread->Post->find('count', array('conditions' => array('Post.date_created >' => date("Y-m-d H:i:s",$this_month))));
		
		$this->set('stats', $stats);
		$this->set('orgs', $orgs);
		$this->set('start', strtotime(date('Y-m-d H:i:s') . ' -5 months'));
		$this->set('end', strtotime(date('Y-m-d H:i:s')));
		$this->set('startDateCal', $year . ', ' . $month . ', 01');
		$range = '[5, 10, 50, 100]';
		$this->set('range', $range);
	}

	public function verifyGPG() {
		if (!self::_isSiteAdmin()) throw new NotFoundException();
		$user_results = $this->User->verifyGPG();
		$this->set('users', $user_results);
	}
	
	public function fetchPGPKey($email) {
		if (!$this->_isAdmin()) throw new Exception('Administrators only.');
		$keys = $this->User->fetchPGPKey($email);
		if (is_numeric($keys)) {
			
			throw new NotFoundException('Could not retrieved any keys from the key server.');
		}
		$this->set('keys', $keys);
		$this->autorender = false;
		$this->layout = false;
		$this->render('ajax/fetchpgpkey');
	}
}
