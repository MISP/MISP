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
			'recursive' => -1,
			'order' => array(
					'Organisation.name' => 'ASC'
			),
			'contain' => array(
				'Organisation' => array('id', 'name'),
				'Role' => array('id', 'name', 'perm_auth')
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
		if (!$this->_isAdmin() && Configure::read('MISP.disableUserSelfManagement')) throw new MethodNotAllowedException('User self-management has been disabled on this instance.');
		$me = false;
		if ("me" == $id) {
			$id = $this->Auth->user('id');
			$me = true;
		}
		$this->User->read(null, $id);
		if (!$this->User->exists() && !$me && !$this->_isSiteAdmin() && !($this->_isAdmin() && $this->Auth->user('org_id') == $this->User->data['User']['org_id'])) {
			throw new NotFoundException(__('Invalid user or not authorised.'));
		}
		if ($this->request->is('post') || $this->request->is('put')) {
			// What fields should be saved (allowed to be saved)
			$fieldList = array('email', 'autoalert', 'gpgkey', 'certif_public', 'nids_sid', 'contactalert', 'disabled');
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
			if (!$this->User->exists() || (!$this->_isSiteAdmin() && $this->Auth->user('org_id') != $this->User->data['User']['org_id'])) {
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
		$this->__extralog("change_pw");
		$roles = $this->User->Role->find('list');
		$this->set(compact('roles'));
	}

/**
 * admin_index method
 *
 * @return void
 */
	public function admin_index() {
		$this->User->virtualFields['org_ci'] = 'UPPER(Organisation.name)';
		$urlParams = "";
		$passedArgsArray = array();
		$booleanFields = array('autoalert', 'contactalert', 'termsaccepted');
		$textFields = array('role', 'email', 'all', 'authkey');
		// org admins can't see users of other orgs
		if ($this->_isSiteAdmin()) $textFields[] = 'org';
		$this->set('passedArgs', json_encode($this->passedArgs));
		// check each of the passed arguments whether they're a filter (could also be a sort for example) and if yes, add it to the pagination conditions
		foreach ($this->passedArgs as $k => $v) {
			if (substr($k, 0, 6) === 'search') {
				if ($v != "") {
					if ($urlParams != "") $urlParams .= "/";
					$urlParams .= $k . ":" . $v;
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
								if ($searchTerm == 'email') {
									$this->paginate['conditions']['AND'][] = array('LOWER(User.' . $searchTerm . ') NOT LIKE' => '%' . strtolower(substr($piece, 1)) . '%');
								}
								else if ($searchTerm == 'org') {
									$this->paginate['conditions']['AND'][] = array('User.org_id !=' => substr($piece, 1));
								} else {
									$this->paginate['conditions']['AND'][] = array('User.' . $searchTerm => substr($piece, 1));
								}
							} else {
								if ($searchTerm == 'email') {
									$test['OR'][] = array('LOWER(User.' . $searchTerm . ') LIKE' => '%' . strtolower($piece) . '%');
								} else if ($searchTerm == 'org') {
									$this->paginate['conditions']['OR'][] = array('User.org_id' => $piece);
								} else if ($searchTerm == 'all') {
									$this->paginate['conditions']['AND'][] = array(
											'OR' => array(
													'UPPER(User.email) LIKE' => '%' . strtoupper($piece) . '%',
													'UPPER(Organisation.name) LIKE' => '%' . strtoupper($piece) . '%',
													'UPPER(Role.name) LIKE' => '%' . strtoupper($piece) . '%',
													'UPPER(User.authkey) LIKE' => '%' . strtoupper($piece) . '%'
											),
									);
								} else {
									$test['OR'][] = array('User.' . $searchTerm => $piece);
								}
							}
						}
						if (!empty($test)) $this->paginate['conditions']['AND'][] = $test;
					}
				}
				$passedArgsArray[$searchTerm] = $v;
			}
		}
		$this->set('urlparams', $urlParams);
		$this->set('passedArgsArray', $passedArgsArray);
		$conditions = array();
		if ($this->_isSiteAdmin()) {
			$this->set('users', $this->paginate());
		} else {
			if (!($this->_isAdmin())) throw new NotFoundException(__('Invalid user or not authorised.'));
			$conditions['User.org_id'] = $this->Auth->user('org_id');
			$this->paginate = array(
					'conditions' => array($conditions),
			);
			$this->set('users', $this->paginate());
		}
	}

	public function index($id) {
		$this->autoRender = false;
		$this->layout = false;
		$passedArgs = $this->passedArgs;
		$org = $this->User->Organisation->read(null, $id);
		if (!$this->User->Organisation->exists() || !($this->_isSiteAdmin() || $this->Auth->user('org_id') == $id)) {
			throw new MethodNotAllowedException('Organisation not found or no authorisation to view it.');
		}
		$user_fields = array('id', 'email', 'gpgkey', 'certif_public', 'nids_sid');
		$conditions = array('org_id' => $id);
		if ($this->_isSiteAdmin() || ($this->_isAdmin() && $this->Auth->user('org_id') == $id)) {
			$user_fields = array_merge($user_fields, array('current_login', 'termsaccepted', 'change_pw', 'authkey'));
		}
		if (isset($this->request->data)) {
			if (isset($this->request->data['searchall'])) $this->request->data['all'] = $this->request->data['searchall'];
			if (isset($this->request->data['all']) && !empty($this->request->data['all'])) {
				$passedArgs['searchall'] = $this->request->data['all'];
				$conditions['OR'][] = array('User.email LIKE' => '%' . $passedArgs['searchall'] . '%');
			}
		}
		$this->set('passedArgs', json_encode($passedArgs));
		$this->paginate = array(
			'conditions' => $conditions,
			'recursive' => -1,
			'fields' => $user_fields,
			'contain' => array(
				'Role' => array(
					'fields' => array('id', 'name', 'perm_auth', 'perm_site_admin'),
				),
			),
		);
		// add roles to the list even though it is not used for the query itself, we can reuse the user_fields array in the view to build the table
		$user_fields = array_merge(array_slice($user_fields, 0, 2), array('role'), array_slice($user_fields, 2));
		$this->set('user_fields', $user_fields);
		$this->set('users', $this->paginate());
		$this->set('org', $org['Organisation']['name']);
		$this->render('ajax/index');
	}

	public function admin_filterUserIndex() {
		if (!$this->_isAdmin() && !$this->_isSiteAdmin()) throw new MethodNotAllowedException();
		$passedArgsArray = array();
		$booleanFields = array('autoalert', 'contactalert', 'termsaccepted');
		$textFields = array('role', 'email', 'authkey');
		$showOrg = 0;
		// org admins can't see users of other orgs
		if ($this->_isSiteAdmin()) {
			$textFields[] = 'org';
			$showOrg = 1;
		}
		$this->set('differentFilters', $booleanFields);
		$this->set('simpleFilters', $textFields);
		$rules = array_merge($booleanFields, $textFields);
		$this->set('showorg', $showOrg);

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
				if (in_array($searchTerm, $booleanFields)) {
					$filtering[$searchTerm] = $v;
				} else if (in_array($searchTerm, $textFields)) {
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
		$temp = $this->User->Organisation->find('all', array(
			'conditions' => array('local' => 1),
			'recursive' => -1,
			'fields' => array('id', 'name'),
			'order' => array('LOWER(name) ASC')
		));
		$orgs = array();
		foreach ($temp as $org) {
			$orgs[$org['Organisation']['id']] = $org['Organisation']['name'];
		}
		$this->set('orgs', $orgs);
		$this->set('roles', $roleNames);
		$this->set('roleJSON', json_encode($roleJSON));
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
		if (!$this->_isSiteAdmin() && !($this->_isAdmin() && $this->Auth->user('org_id') == $this->User->data['User']['org_id'])) {
			throw new MethodNotAllowedException();
		}
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
		$this->set('currentOrg', $this->Auth->user('org_id'));
		$this->set('isSiteAdmin', $this->_isSiteAdmin());
		$params = null;
		if (!$this->_isSiteAdmin()) {
			$params = array('conditions' => array('perm_site_admin !=' => 1, 'perm_sync !=' => 1, 'perm_regexp_access !=' => 1));
		}
		$roles = $this->User->Role->find('list', $params);
		$syncRoles = $this->User->Role->find('list', array('conditions' => array('perm_sync' => 1), 'recursive' => -1));
		if ($this->request->is('post')) {
			if (!array_key_exists($this->request->data['User']['role_id'], $syncRoles)) $this->request->data['User']['server_id'] = 0;
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
			if (!isset($this->request->data['User']['disabled'])) $this->request->data['User']['disabled'] = false;
			$this->request->data['User']['newsread'] = 0;
			if (!$this->_isSiteAdmin()) {
				$this->request->data['User']['org_id'] = $this->Auth->user('org_id');
				$this->loadModel('Role');
				$this->Role->recursive = -1;
				$chosenRole = $this->Role->findById($this->request->data['User']['role_id']);
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
			$this->newkey = $this->User->generateAuthKey();
			$this->set('authkey', $this->newkey);
		}
		$orgs = $this->User->Organisation->find('list', array(
				'conditions' => array('local' => 1),
				'order' => array('lower(name) asc')
		));
		$this->set('orgs', $orgs);
		// generate auth key for a new user
		$this->loadModel('Server');
		$conditions = array();
		if (!$this->_isSiteAdmin()) $conditions['Server.org_id LIKE'] = $this->Auth->user('org_id');
		$temp = $this->Server->find('all', array('conditions' => $conditions, 'recursive' => -1, 'fields' => array('id', 'name', 'url')));
		$servers = array(0 => 'Not bound to a server');
		if (!empty($temp)) foreach ($temp as $t) {
			if (!empty($t['Server']['name'])) $servers[$t['Server']['id']] = $t['Server']['name'];
			else $servers[$t['Server']['id']] = $t['Server']['url'];
		}
		$this->set('servers', $servers);
		$this->set(compact('roles'));
		$this->set(compact('syncRoles'));
	}

/**
 * admin_edit method
 *
 * @param string $id
 * @return void
 * @throws NotFoundException
 */
	public function admin_edit($id = null) {
		$this->set('currentOrg', $this->Auth->user('org_id'));
		$this->User->id = $id;
		if (!$this->User->exists()) {
			throw new NotFoundException(__('Invalid user'));
		}
		$params = array();
		$allowedRole = '';
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
		$syncRoles = $this->User->Role->find('list', array('conditions' => array('perm_sync' => 1), 'recursive' => -1));

		$this->set('currentId', $id);
		if ($this->request->is('post') || $this->request->is('put')) {
			if (!array_key_exists($this->request->data['User']['role_id'], $syncRoles)) $this->request->data['User']['server_id'] = 0;
			$fields = array();
			foreach (array_keys($this->request->data['User']) as $field) {
				if ($field != 'password') array_push($fields, $field);
			}
			// TODO Audit, __extralog, fields get orig
			$fieldsOldValues = array();
			foreach ($fields as $field) {
				if ($field == 'enable_password') continue;
				if ($field != 'confirm_password') array_push($fieldsOldValues, $this->User->field($field));
				else array_push($fieldsOldValues, $this->User->field('password'));
			}
			// TODO Audit, __extralog, fields get orig END
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
				// TODO Audit, __extralog, fields compare
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
						} else {
							array_push($fieldsNewValues, $newValue);
						}
					} else {
						array_push($fieldsNewValues, $this->data['User']['password']);
					}
				}
				// compare
				$fieldsResultStr = '';
				$c = 0;
				foreach ($fields as $field) {
					if (isset($fieldsOldValues[$c]) && $fieldsOldValues[$c] != $fieldsNewValues[$c]) {
						if ($field != 'confirm_password') {
							$fieldsResultStr = $fieldsResultStr . ', ' . $field . ' (' . $fieldsOldValues[$c] . ') => (' . $fieldsNewValues[$c] . ')';
						}
					}
					$c++;
				}
				$fieldsResultStr = substr($fieldsResultStr, 2);
				$this->__extralog("edit", "user", $fieldsResultStr);	// TODO Audit, check: modify User
				// TODO Audit, __extralog, fields compare END
				$this->Session->setFlash(__('The user has been saved'));
				$this->_refreshAuth(); // in case we modify ourselves
				$this->redirect(array('action' => 'index'));
			} else {
				$this->Session->setFlash(__('The user could not be saved. Please, try again.'));
			}
		} else {
			$this->User->read(null, $id);
			if (!$this->_isSiteAdmin() && $this->Auth->user('org_id') != $this->User->data['User']['org_id']) {
				$this->redirect(array('controller' => 'users', 'action' => 'index', 'admin' => true));
			}
			$this->User->set('password', '');
			$this->request->data = $this->User->data; // TODO CHECK
		}
		if ($this->_isSiteAdmin()) {
			$orgs = $this->User->Organisation->find('list', array(
					'conditions' => array('local' => 1),
					'order' => array('lower(name) asc')
			));
		} else {
			$orgs = array();
		}
		$this->loadModel('Server');
		$conditions = array();
		if (!$this->_isSiteAdmin()) $conditions['Server.org_id LIKE'] = $this->Auth->user('org_id');
		$temp = $this->Server->find('all', array('conditions' => $conditions, 'recursive' => -1, 'fields' => array('id', 'name', 'url')));
		$servers = array(0 => 'Not bound to a server');
		foreach ($temp as $t) {
			if (!empty($t['Server']['name'])) $servers[$t['Server']['id']] = $t['Server']['name'];
			else $servers[$t['Server']['id']] = $t['Server']['url'];
		}
		$this->set('servers', $servers);
		$this->set('orgs', $orgs);
		$this->set('id', $id);
		$this->set(compact('roles'));
		$this->set(compact('syncRoles'));
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
		$user = $this->User->find('first', array(
				'conditions' => array('User.id' => $id),
				'recursive' => -1
		));
		if (empty($user) || (!$this->_isSiteAdmin() && $user['User']['org_id'] != $this->Auth->user('id'))) {
			throw new NotFoundException(__('Invalid user'));
		}
		$fieldsDescrStr = 'User (' . $id . '): ' . $user['User']['email'];
		if ($this->User->delete($id)) {
			$this->__extralog("delete", $fieldsDescrStr, '');	// TODO Audit, check: modify User
			$this->Session->setFlash(__('User deleted'));
			$this->redirect(array('action' => 'index'));
		}
		$this->Session->setFlash(__('User was not deleted'));
		$this->redirect(array('action' => 'index'));
	}

	public function updateLoginTime() {
		if (!$this->request->is('post')) throw new MethodNotAllowedException('This feature is only accessible via POST requests');
		$user = $this->User->find('first', array(
			'recursive' => -1,
			'conditions' => array('User.id' => $this->Auth->user('id'))
		));
		$this->User->id = $this->Auth->user('id');
		$this->User->saveField('last_login', time());
		$this->User->saveField('current_login', time());
		$user = $this->User->getAuthUser($user['User']['id']);
		$this->Auth->login($user);
		$this->redirect(array('Controller' => 'User', 'action' => 'dashboard'));
	}

	public function login() {
		if ($this->Auth->login()) {
			$this->__extralog("login");	// TODO Audit, __extralog, check: customLog i.s.o. __extralog, no auth user?: $this->User->customLog('login', $this->Auth->user('id'), array('title' => '','user_id' => $this->Auth->user('id'),'email' => $this->Auth->user('email'),'org' => 'IN2'));
			$this->User->Behaviors->disable('SysLogLogable.SysLogLogable');
			$this->User->id = $this->Auth->user('id');
			$this->User->saveField('last_login', $this->Auth->user('current_login'));
			$this->User->saveField('current_login', time());
			$this->User->Behaviors->enable('SysLogLogable.SysLogLogable');
			// TODO removed the auto redirect for now, due to security concerns - will look more into this
			// $this->redirect($this->Auth->redirectUrl());
			$this->redirect(array('controller' => 'events', 'action' => 'index'));
		} else {
			// don't display authError before first login attempt
			if (str_replace("//","/",$this->webroot . $this->Session->read('Auth.redirect')) == $this->webroot && $this->Session->read('Message.auth.message') == $this->Auth->authError) {
				$this->Session->delete('Message.auth');
			}
			// don't display "invalid user" before first login attempt
			if ($this->request->is('post')) {
				$this->Session->setFlash(__('Invalid username or password, try again'));
			}
			// populate the DB with the first role (site admin) if it's empty
			$this->loadModel('Role');
			if ($this->Role->find('count') == 0 ) {
				$siteAdmin = array('Role' => array(
					'id' => 1,
					'name' => 'Site Admin',
					'permission' => 3,
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
					'perm_sharing_group' => 1,
					'perm_template' => 1,
					'perm_tagger' => 1,
				));
				$this->Role->save($siteAdmin);
			}
			if ($this->User->Organisation->find('count', array('conditions' => array('Organisation.local' => true))) == 0) {
				$org = array('Organisation' => array(
						'id' => 1,
						'name' => !empty(Configure::read('MISP.org')) ? Configure::read('MISP.org') : 'ADMIN',
						'description' => 'Automatically generated admin organisation',
						'type' => 'ADMIN',
						'uuid' => $this->User->Organisation->generateUuid(),
						'local' => 1,
						'sector' => '',
						'nationality' => ''
				));
				$this->User->Organisation->save($org);
				$org_id = $this->User->Organisation->id;
			} else {
				$hostOrg = $this->User->Organisation->find('first', array('conditions' => array('Organisation.name' => Configure::read('MISP.org'), 'Organisation.local' => true), 'recursive' => -1));
				if (!empty($hostOrg)) $org_id = $hostOrg['Organisation']['id'];
				else {
					$firstOrg = $this->User->Organisation->find('first', array('conditions' => array('Organisation.local' => true), 'order' => 'Organisation.id ASC'));
					$org_id = $firstOrg['Organisation']['id'];
				}
			}

			// populate the DB with the first user if it's empty
			if ($this->User->find('count') == 0 ) {
				$admin = array('User' => array(
					'id' => 1,
					'email' => 'admin@admin.test',
					'org_id' => $org_id,
					'password' => 'admin',
					'confirm_password' => 'admin',
					'authkey' => $this->User->generateAuthKey(),
					'nids_sid' => 4000000,
					'newsread' => 0,
					'role_id' => 1,
					'change_pw' => 1
				));
				$this->User->validator()->remove('password'); // password is too simple, remove validation
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
			$this->__extralog("logout");	// TODO Audit, __extralog, check: customLog i.s.o. __extralog, $this->User->customLog('logout', $this->Auth->user('id'), array());
		}
		$this->Session->setFlash(__('Good-Bye'));
		$this->redirect($this->Auth->logout());
	}

	public function resetauthkey($id = null) {
		if (!$this->_isAdmin() && Configure::read('MISP.disableUserSelfManagement')) {
			throw new MethodNotAllowedException('User self-management has been disabled on this instance.');
		}
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
		$user = $this->User->read();
		$oldKey = $this->User->data['User']['authkey'];
		if ($id != 'me' && !$this->_isSiteAdmin() && !($this->_isAdmin() && $this->Auth->user('org_id') == $this->User->data['User']['org_id']) && ($this->Auth->user('id') != $id)) {
			throw new MethodNotAllowedException();
		}
		$newkey = $this->User->generateAuthKey();
		$this->User->saveField('authkey', $newkey);
		$this->__extralog(
				'reset_auth_key',
				'Authentication key for user ' . $user['User']['id'] . ' (' . $user['User']['email'] . ')',
				$fieldsResult = 'authkey(' . $oldKey . ') => (' . $newkey . ')'
		);
		$this->Session->setFlash(__('New authkey generated.', true));
		$this->_refreshAuth();
		$this->redirect($this->referer());
	}

	public function memberslist() {
		// Orglist
		$fields = array('Organisation.name', 'count(User.id) as `num_members`');
		$params = array(
				'fields' => $fields,
				'recursive' => -1,
				'contain' => array('Organisation'),
				'group' => array('Organisation.name', 'Organisation.id'),
				'order' => array('UPPER(Organisation.name)'),
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
			'fields' => array('distinct(orgc_id)'),
			'contain' => array('Orgc' => array('fields' => array('Orgc.name'))),
		));
		$orgs = array();
		foreach ($temp as $t) {
			$orgs[$t['Event']['orgc_id']] = $t['Orgc']['name'];
		}
		// What org posted what type of attribute
		$this->loadModel('Attribute');
		$conditions = array();
		if ($selected) $conditions[] = array('Attribute.type' => $selectedTypes, 'Attribute.deleted' => false);
		$fields = array('Event.orgc_id', 'Attribute.type', 'count(Attribute.type) as `num_types`');
		$params = array('recursive' => 0,
				'fields' => $fields,
				'group' => array('Attribute.type', 'Event.orgc_id'),
				'order' => array('Event.orgc_id', 'num_types DESC'),
				'conditions' => $conditions,
		);
		$temp = $this->Attribute->find('all', $params);
		$data = array();
		foreach ($orgs as $k => $org) {
			$data[$org]['total'] = 0;
			$data[$org]['data'] = array();
			foreach ($temp as $t) {
				if ($t['Event']['orgc_id'] == $k) {
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
		$sigTypes = array_keys($this->Attribute->typeDefinitions);
		App::uses('ColourPaletteTool', 'Tools');
		$paletteTool = new ColourPaletteTool();
		$colours = $paletteTool->createColourPalette(count($sigTypes));
		$typeDb = array();
		foreach ($sigTypes as $k => $type) {
			$typeDb[$type] = $colours[$k];
		}
		$this->set('typeDb', $typeDb);
		$this->set('sigTypes', $sigTypes);
		$this->layout = 'ajax';
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

	private function __extralog($action = null, $description = null, $fieldsResult = null) {	// TODO move audit to AuditsController?
		// new data
		$model = 'User';
		$modelId = $this->Auth->user('id');
		if ($action == 'login') {
			$description = "User (" . $this->Auth->user('id') . "): " . $this->data['User']['email'];
		} else if ($action == 'logout') {
			$description = "User (" . $this->Auth->user('id') . "): " . $this->Auth->user('email');
		} else if ($action == 'edit') {
			$description = "User (" . $this->User->id . "): " . $this->data['User']['email'];
		} else if ($action == 'change_pw') {
			$description = "User (" . $this->User->id . "): " . $this->data['User']['email'];
			$fieldsResult = "Password changed.";
		}

		// query
		$this->Log = ClassRegistry::init('Log');
		$this->Log->create();
		$this->Log->save(array(
			'org' => $this->Auth->user('Organisation')['name'],
			'model' => $model,
			'model_id' => $modelId,
			'email' => $this->Auth->user('email'),
			'action' => $action,
			'title' => $description,
			'change' => isset($fieldsResult) ? $fieldsResult : ''));

		// write to syslogd as well
		App::import('Lib', 'SysLog.SysLog');
		$syslog = new SysLog();
		if (isset($fieldsResult) && $fieldsResult) {
			$syslog->write('notice', $description . ' -- ' . $action . ' -- ' . $fieldsResult);
		} else {
			$syslog->write('notice', $description . ' -- ' . $action);
		}
	}

/**
 * Used for fields_before and fields for audit
 *
 * @param $array
 */
	public function arrayCopy(array $array) {
		$result = array();
		foreach ($array as $key => $val) {
			if (is_array($val)) {
				$result[$key] = arrayCopy($val);
			} else if (is_object($val)) {
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
			if (!$this->_isSiteAdmin()) $conditions = array('org_id' => $this->Auth->user('org_id'));
			if ($this->request->data['User']['recipient'] != 1) $conditions['id'] = $this->request->data['User']['recipientEmailList'];
			$conditions['AND'][] = array('User.disabled' => false);
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
		if (!$this->_isSiteAdmin()) $conditions = array('org_id' => $this->Auth->user('org_id'));
		$conditions['User.disabled'] = false;
		$temp = $this->User->find('all', array('recursive' => -1, 'fields' => array('id', 'email'), 'order' => array('email ASC'), 'conditions' => $conditions));
		$emails = array();
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
		if (!$this->_isSiteAdmin() && $this->Auth->user('org_id') != $user['User']['org_id']) {
			throw new MethodNotAllowedException('You are not authorised to do that.');
		}
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
		$orgs = $this->User->Organisation->find('all', array('fields' => array('DISTINCT (name) AS name'), 'recursive' => -1));
		$this->loadModel('Log');
		$year = date('Y');
		$month = date('n');
		$month = $month - 5;
		if ($month < 1) {
			$year--;
			$month = 12 + $month;
		}
		// Some additional statistics
		$this_month = strtotime('first day of this month');
		$stats[0] = $this->User->Event->find('count', null);
		$stats[1] = $this->User->Event->find('count', array('conditions' => array('Event.timestamp >' => $this_month)));

		$stats[2] = $this->User->Event->Attribute->find('count', array('conditions' => array('Attribute.deleted' => false)));
		$stats[3] = $this->User->Event->Attribute->find('count', array('conditions' => array('Attribute.timestamp >' => $this_month, 'Attribute.deleted' => false)));

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

	public function verifyCertificate() {
		$user_results = $this->User->verifyCertificate();
		$this->set('users', $user_results);
	}

	/**
	 * Refreshes the Auth session with new/updated data
	 * @return void
	 */
	protected function _refreshAuth() {
		$oldUser = $this->Auth->user();
		$newUser = $this->User->find('first', array('conditions' => array('User.id' => $oldUser['id']), 'recursive' => -1,'contain' => array('Organisation', 'Role')));
		// Rearrange it a bit to match the Auth object created during the login
		$newUser['User']['Role'] = $newUser['Role'];
		$newUser['User']['Organisation'] = $newUser['Organisation'];
		unset($newUser['Organisation'], $newUser['Role']);
		$this->Auth->login($newUser['User']);
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

	public function dashboard() {
		$events = array();
		// the last login in the session is not updated after the login - only in the db, so let's fetch it.
		$lastLogin = $this->Auth->user('last_login');
		$this->loadModel('Event');
		$events['changed'] = count($this->Event->fetchEventIds($this->Auth->user(), false, false, false, true, $lastLogin));
		$events['published'] = count($this->Event->fetchEventIds($this->Auth->user(), false, false, false, true, false, $lastLogin));
		$notifications = $this->{$this->modelClass}->populateNotifications($this->Auth->user());
		$this->set('notifications', $notifications);
		$this->set('events', $events);
	}
}
