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
			$fieldList = array('email', 'autoalert', 'gpgkey', 'nids_sid' );
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
			$this->User->set('password', '');
			$this->request->data = $this->User->data;
		}
		$roles = $this->User->Role->find('list');
		$this->set(compact('roles'));
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
		$this->User->recursive = 0;
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
		if ($this->request->is('post')) {
			$this->User->create();
			// set invited by
			$this->request->data['User']['invited_by'] = $this->Auth->user('id');
			$this->request->data['User']['change_pw'] = 1;
			$this->request->data['User']['newsread'] = '2000-01-01';
			if ($this->Auth->User('org') != 'ADMIN') $this->request->data['User']['org'] = $this->Auth->User('org');
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
		// XXX ACL roles
		$roles = $this->User->Role->find('list');
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
			//debug($fields);debug(tru);
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
			if ($this->Auth->User('org') != 'ADMIN' && $this->Auth->User('org') != $this->User->data['User']['org']) $this->redirect(array('controller' => 'users', 'action' => 'index', 'admin' => true));
			$this->User->set('password', '');
			$this->request->data = $this->User->data; // TODO CHECK

		}
		// TODO ACL CLEANUP combobox for orgs
		$orgIds = array('ADMIN', 'NCIRC', 'Other MOD');
		$orgIds = $this->_arrayToValuesIndexArray($orgIds);
		$this->set('orgIds', compact('orgIds'));
		// XXX ACL, Roles in Users
		$roles = $this->User->Role->find('list');
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
			$this->redirect($this->Auth->redirect());
		} else {
			// don't display authError before first login attempt
			if (str_replace("//","/",$this->webroot . $this->Session->read('Auth.redirect')) == $this->webroot && $this->Session->read('Message.auth.message') == $this->Auth->authError) {
				$this->Session->delete('Message.auth');
			}
			// don't display "invalid user" before first login attempt
			if($this->request->is('post')) {
				$this->Session->setFlash(__('Invalid username or password, try again'));
			}

			// populate the DB with the first user if it's empty
			if ($this->User->find('count') == 0 ) {
				$admin = array('User' => array(
						'email' => 'admin@admin.test',
						'org' => 'ADMIN',
						'password' => 'admin',
						'confirm_password' => 'admin',
						'authkey' => $this->User->generateAuthKey(),
						'nids_sid' => 4000000,
						'date' => date('YYY-mm-dd'),
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

		// News page
		$newNewsdate = new DateTime("2012-03-27");	// TODO general, fixed odd date??
		$newsdate = new DateTime($this->Auth->user('newsread'));
		if ($newNewsdate > $newsdate) {
			$this->redirect(array('action' => 'news'));
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
			$this->redirect(array('action' => 'index'));
		}
		if ('me' == $id ) $id = $this->Auth->user('id');
		else if (!$this->_isAdmin()) throw new MethodNotAllowedException();

		// reset the key
		$this->User->id = $id;
		$newkey = $this->User->generateAuthKey();
		$this->User->saveField('authkey', $newkey);
		$this->Session->setFlash(__('New authkey generated.', true));
		$this->_refreshAuth();
		$this->redirect($this->referer());
	}

	public function memberslist() {
		$this->loadModel('Attribute');
		$this->loadModel('Event');

		// Orglist
		$fields = array('User.org', 'count(User.id) as `num_members`');
		$params = array('recursive' => 0,
							'fields' => $fields,
							'group' => array('User.org'),
							'order' => array('User.org'),
		);
		$orgs = $this->User->find('all', $params);
		$this->set('orgs', $orgs);

		// What org posted what type of attribute
		$this->loadModel('Attribute');
		$fields = array('Event.org', 'Attribute.type', 'count(Attribute.type) as `num_types`');
		$params = array('recursive' => 0,
							'fields' => $fields,
							'group' => array('Attribute.type', 'Event.org'),
							'order' => array('Event.org', 'num_types DESC'),
		);
		$typesHistogram = $this->Attribute->find('all', $params);
		$this->set('typesHistogram', $typesHistogram);

		// Nice graphical histogram
		$this->loadModel('Attribute');
		$sigTypes = array_keys($this->Attribute->typeDefinitions);
		$replace = array('-', '|');
		$graphFields = '';
		foreach ($sigTypes as &$sigType) {
			if ($graphFields != "") $graphFields .= ", ";
			$graphFields .= "'" . $sigType . "'";
		}
		$graphFields = str_replace($replace, "_", $graphFields);
		$this->set('graphFields', $graphFields);

		$graphData = array();
		$prevRowOrg = "";
		$i = -1;
		foreach ($typesHistogram as &$row) {
			if ($prevRowOrg != $row['Event']['org']) {
				$i++;
				$graphData[] = "";
				$prevRowOrg = $row['Event']['org'];
				$graphData[$i] .= "org: '" . $row['Event']['org'] . "'";
			}
			$graphData[$i] .= ', ' . str_replace($replace, "_", $row['Attribute']['type']) . ': ' . $row[0]['num_types'];
		}
		$this->set('graphData', $graphData);
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

	public function news() {
		$this->User->id = $this->Auth->user('id');
		$this->User->saveField('newsread', date("Y-m-d"));
		$this->_refreshAuth(); // refresh auth info
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

	public function setRoleId($fk = '2') { // TODO generateAllFor<FieldName>
		$params = array(
				'conditions' => array('User.role_id' => ''),
				'recursive' => 0,
				'fields' => array('User.id'),
		);
		$users = $this->User->find('all', $params);
		foreach ($users as $user) {
			$this->User->id = $user['User']['id'];
			$this->User->saveField('role_id', $fk);
		}
	}

/**
 * generateAllFor<FieldName>
 **/
	public function generateAllFor($field) {
		parent::generateAllFor($field);
	}

/**
 * @throws NotFoundException
 **/
	public function checkAndCorrectPgps() {
		if (!self::_isAdmin()) throw new NotFoundException();

		$this->set('fails', $this->User->checkAndCorrectPgps());
	}

	public function admin_email() {
		if (!$this->_isSiteAdmin()) {
			throw new MethodNotAllowedException();
		}
		$this->User->recursive = 0;
		$temp = $this->User->find('all', array('fields' => array('email', 'gpgkey')));
		$emails = array();
		$gpgKeys = array();
		// save all the emails of the users and set it for the dropdown list in the form
		foreach ($temp as $user) {
			array_push($emails, $user['User']['email']);
			array_push($gpgKeys, $user['User']['gpgkey']);
		}
		$this->set('recipientEmail', $emails);

		// User has filled in his contact form, send out the email.
		if ($this->request->is('post') || $this->request->is('put')) {
			$message1 = null;
			$message2 = null;
			$recipients = array();
			$messageP = array();
			// Formulating the message and the subject that will be common to the e-mail(s) sent
			if ($this->request->data['User']['action'] == '0') {
				// Custom message
				$subject = $this->request->data['User']['subject'];
				$message1 .= $this->request->data['User']['message'];
			} else {
				// Temp password
				if ($this->request->data['User']['customMessage']) {
					$message1 .= $this->request->data['User']['message'];
				} else {
					$message1 .= "Dear MISP user,\n\nA password reset has been triggered for your account. Use the below provided temporary password to log into MISP at ";
					$message1 .= Configure::read('CyDefSIG.baseurl');
					$message1 .= ", where you will be prompted to manually change your password to something of your own choice.";
				}
				//$message .= "\n\nYour temporary password: " . $password;
				$subject = 'Password reset on ' . Configure::read('CyDefSIG.org') . ' MISP';
			}
			if (Configure::read('CyDefSIG.contact')) {
				$message2 .= "\n\nIf you have any questions, contact us at: " . Configure::read('CyDefSIG.contact') . ".";
			}
			$message2 .= "\n\nBest Regards,\n" . Configure::read('CyDefSIG.org') . ' MISP support';

			// Setting up the list of recipient(s) based on the setting and creating the final message for each user, including the password
			// If the recipient is all users, and the action to create a password, create it and for each user and squeeze it between the main message and the signature
			if ($this->request->data['User']['recipient'] == 0) {
				$recipients = $emails;
				$recipientGPG = $gpgKeys;
				if ($this->request->data['User']['action'] == '1') {
					$i = 0;
					foreach ($recipients as $rec) {
						$password = $this->__randomPassword();
						$messageP = "\n\nYour temporary password: " . $password;
						$message[$i] = $message1 . $messageP . $message2;
						$recipientPass[$i] = $password;
						$i++;
					}
				} else {
					$i = 0;
					foreach ($recipients as $rec) {
						$message[$i] = $message1;
						$i++;
					}
				}
			}

			// If the recipient is a user, and the action to create a password, create it and squeeze it between the main message and the signature
			if ($this->request->data['User']['recipient'] == 1) {
				$recipients[0] = $emails[$this->request->data['User']['recipientEmailList']];
				$recipientGPG[0] = $gpgKeys[$this->request->data['User']['recipientEmailList']];
				if ($this->request->data['User']['action'] == '1') {
					$password = $this->__randomPassword();
					$message[0] = $message1 . "\n\nYour temporary password: " . $password . $message2;
					$recipientPass[0] = $password;
				} else {
					$message[0] = $message1;
				}
			}

			// If the recipient is a future user, and the action to create a password, create it and squeeze it between the main message and the signature
			if ($this->request->data['User']['recipient'] == 2) {
				$recipients[0] = $this->request->data['User']['recipientEmail'];
				$recipientGPG[0] = $this->request->data['User']['gpg'];
				if ($this->request->data['User']['action'] == '1') {
					$password = $this->__randomPassword();
					$message[0] = $message1 . "\n\nYour temporary password: " . $password . $message2;
					$recipientPass[0] = $password;
				} else {
					$message[0] = $message1;
				}
			}
			require_once 'Crypt/GPG.php';
			$i = 0;
			foreach ($recipients as $recipient) {
				if (!empty($recipientGPG[$i])) {
					$gpg = new Crypt_GPG(array('homedir' => Configure::read('GnuPG.homedir')));	// , 'debug' => true
					$gpg->addSignKey(Configure::read('GnuPG.email'), Configure::read('GnuPG.password'));
					$messageSigned = $gpg->sign($message[$i], Crypt_GPG::SIGN_MODE_CLEAR);
					$keyImportOutput = $gpg->importKey($recipientGPG[$i]);
					try {
						$gpg = new Crypt_GPG(array('homedir' => Configure::read('GnuPG.homedir')));
						$gpg->addEncryptKey($keyImportOutput['fingerprint']); // use the key that was given in the import

						$encryptedMessage = $gpg->encrypt($messageSigned, true);
					} catch (Exception $e){
						// catch errors like expired PGP keys
						$this->log($e->getMessage());
						// no need to return here, as we want to send out mails to the other users if GPG encryption fails for a single user
					}
				} else {
					$encryptedMessage = $message[$i];
				}

				// prepare the email
				$this->Email->from = Configure::read('CyDefSIG.email');
				$this->Email->to = $recipients[$i];
				$this->Email->subject = $subject;
				//$this->Email->delivery = 'debug';   // do not really send out mails, only display it on the screen
				$this->Email->template = 'body';
				$this->Email->sendAs = 'text';		// both text or html
				$this->set('body', $encryptedMessage);

				// send it
				$result = $this->Email->send();

				// if sending successful and action was a password change, update the user's password.
				if ($result && $this->request->data['User']['action'] == '1') {
					$this->User->recursive = 0;
					$temp = $this->User->findByEmail($recipients[$i]);
					$this->User->id = $temp['User']['id'];
					$this->User->read();
					$this->User->saveField('password', $recipientPass[$i]);
					$this->User->saveField('change_pw', '1');
				}
				// If you wish to send multiple emails using a loop, you'll need
				// to reset the email fields using the reset method of the Email component.
				$this->Email->reset();
				$i++;
			}
			$this->Session->setFlash(__('E-mails sent.'));
		}
		// User didn't see the contact form yet. Present it to him.
	}

	private function __randomPassword() {
		$alphabet = "abcdefghijklmnopqrstuwxyzABCDEFGHIJKLMNOPQRSTUWXYZ0123456789";
		$pass = array();
		$alphaLength = strlen($alphabet) - 1;
		for ($i = 0; $i < 8; $i++) {
			$n = rand(0, $alphaLength);
			$pass[] = $alphabet[$n];
		}
		return implode($pass);
	}

}
