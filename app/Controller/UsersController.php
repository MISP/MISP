<?php
App::uses('AppController', 'Controller');
/**
 * Users Controller
 *
 * @property User $User
 */
class UsersController extends AppController {


    public $components = array('Acl','Security');	// TODO ACL, components
    public $paginate = array(
            'limit' => 60,
            'order' => array(
                    'User.org' => 'ASC'
            )
    );

    function beforeFilter() {
        parent::beforeFilter();

        // what pages are allowed for non-logged-in users
        $this->Auth->allow('login', 'logout'); // TODO ACL, remove/add ,'initDB','checkDB' if needed
    }

    public function isAuthorized($user) {
        // Admins can access everything
        if (parent::isAuthorized($user)) {
            return true;
        }
        // Do not allow admin routing
        if (isset($this->request->params['admin']) && true == $this->request->params['admin'])
            return false;
        // Only on own user for these actions
        if (in_array($this->action, array('view', 'edit', 'delete', 'resetauthkey'))) {
            $userid = $this->request->params['pass'][0];
            if ("me" == $userid ) return true;
            return ($userid === $this->Auth->user('id'));
        }
        // the other pages are allowed by logged in users
        return true;
    }


/**
 * view method
 *
 * @param string $id
 * @return void
 */
	public function view($id = null) {
	    if ("me" == $id) $id = $this->Auth->user('id');
	    $this->User->id = $id;
		if (!$this->User->exists()) {
			throw new NotFoundException(__('Invalid user'));
		}
		// Only own profile verified by isAuthorized
		$this->set('user', $this->User->read(null, $id));
	}


/**
 * edit method
 *
 * @param string $id
 * @return void
 */
	public function edit($id = null) {
	    if ("me" == $id) $id = $this->Auth->user('id');
	    $this->User->id = $id;
		if (!$this->User->exists()) {
			throw new NotFoundException(__('Invalid user'));
		}
		// Only own profile verified by isAuthorized
		if ($this->request->is('post') || $this->request->is('put')) {
		    // What fields should be saved (allowed to be saved)
		    $fieldList=array('email', 'autoalert', 'gpgkey', 'nids_sid');	// TODO ACL, check, My Profile not edit group_id.
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
		    $this->User->recursive=0;
		    $this->User->read(null, $id);
		    $this->User->set('password', '');
			$this->request->data = $this->User->data;
		}
		$this->request->data['User']['org']=$this->Auth->user('org');
		// XXX ACL groups
		$groups = $this->User->Group->find('list');
		$this->set(compact('groups'));
	}

/**
 * delete method
 *
 * @param string $id
 * @return void
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
// 		Replaced by isAuthorized
// 		// Only own profile
// 		if ($this->Auth->user('id') != $id) {
// 		    throw new ForbiddenException('You are not authorized to delete this profile.');
// 		}
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
		$this->set('users', $this->paginate());
	}

/**
 * admin_view method
 *
 * @param string $id
 * @return void
 */
	public function admin_view($id = null) {
		$this->User->id = $id;
		if (!$this->User->exists()) {
			throw new NotFoundException(__('Invalid user'));
		}
		$this->set('user', $this->User->read(null, $id));
	}

/**
 * admin_add method
 *
 * @return void
 */
	public function admin_add() {
		if ($this->request->is('post')) {
			$this->User->create();
			if ($this->User->save($this->request->data)) {
				$this->Session->setFlash(__('The user has been saved'));
				$this->redirect(array('action' => 'index'));
			} else {
				$this->Session->setFlash(__('The user could not be saved. Please, try again.'));
			}
		} else {
			// generate auth key for a new user
			$newkey = $this->User->generateAuthKey();
			$this->set('authkey', $newkey);
		}
		// XXX ACL groups
		$groups = $this->User->Group->find('list');
		$this->set(compact('groups'));
	}

/**
 * admin_edit method
 *
 * @param string $id
 * @return void
 */
	public function admin_edit($id = null) {
		$this->User->id = $id;
		if (!$this->User->exists()) {
			throw new NotFoundException(__('Invalid user'));
		}
		if ($this->request->is('post') || $this->request->is('put')) {
			$fields = array();
			foreach (array_keys($this->request->data['User']) as $field) {
				if($field != 'password') array_push($fields, $field);
			}
			// TODO Audit, extraLog, fields get orig
			$fields_oldValues = array();
			foreach ($fields as $field) {
				if($field != 'confirm_password') array_push($fields_oldValues, $this->User->field($field));
				else array_push($fields_oldValues, $this->User->field('password'));
			}
			// TODO Audit, extraLog, fields get orig END
			if ("" != $this->request->data['User']['password'])
				$fields[] = 'password';
			if ($this->User->save($this->request->data, true, $fields)) {
				// TODO Audit, extraLog, fields compare
				// newValues to array
				$fields_newValues = array();
				foreach ($fields as $field) {
					if($field != 'confirm_password') {
						$newValue = $this->data['User'][$field];
						if (gettype($newValue) == 'array') {
							$newValueStr = '';
							$c_p = 0;
							foreach ($newValue as $newValuePart) {
								if ($c_p < 2) $newValueStr .= '-' . $newValuePart;
								else  $newValueStr = $newValuePart.$newValueStr;
								$c_p++;
							}
							array_push($fields_newValues, $newValueStr);
						}
						else array_push($fields_newValues, $newValue);
					}
					else array_push($fields_newValues, $this->data['User']['password']);
				}
				// compare
				$fields_result_str = '';
				$c = 0;
				foreach ($fields as $field) {
					if ($fields_oldValues[$c] != $fields_newValues[$c]) {
						if($field != 'confirm_password') $fields_result_str = $fields_result_str. ', '.$field.' ('.$fields_oldValues[$c]. ') => ('.$fields_newValues[$c].')';
					}
					$c++;
				}
				$fields_result_str = substr($fields_result_str, 2);
				$this->extraLog("admin_modify", "user", $fields_result_str);	// TODO Audit, check: modify User
				// TODO Audit, extraLog, fields compare END
				$this->Session->setFlash(__('The user has been saved'));
				$this->_refreshAuth(); // in case we modify ourselves
				$this->redirect(array('action' => 'index'));
			} else {
				$this->Session->setFlash(__('The user could not be saved. Please, try again.'));
			}
		} else {
			$this->User->recursive=0;
			$this->User->read(null, $id);
			$this->User->set('password', '');
			$this->request->data = $this->User->data;

		}
        // TODO ACL CLEANUP combobox for orgs
        $org_ids =  array('ADMIN', 'NCIRC','Other MOD');
        $org_ids = $this->_arrayToValuesIndexArray($org_ids);
        $this->set('org_ids',compact('org_ids'));
		// XXX ACL, Groups in Users
		$groups = $this->User->Group->find('list');
		$this->set(compact('groups'));
	}

/**
 * admin_delete method
 *
 * @param string $id
 * @return void
 */
	public function admin_delete($id = null) {
		if (!$this->request->is('post')) {
			throw new MethodNotAllowedException();
		}
		$this->User->id = $id;
		if (!$this->User->exists()) {
			throw new NotFoundException(__('Invalid user'));
		}
		if ($this->User->delete()) {
			$this->Session->setFlash(__('User deleted'));
			$this->redirect(array('action' => 'index'));
		}
		$this->Session->setFlash(__('User was not deleted'));
		$this->redirect(array('action' => 'index'));
	}


	public function login() {
	    // FIXME implement authentication brute-force protection
	    if ($this->Auth->login()) {
	        $this->extraLog("login");	// TODO Audit, extraLog, check: customLog i.s.o. extraLog, no auth user?: $this->User->customLog('login', $this->Auth->user('id'), array('title' => '','user_id' => $this->Auth->user('id'),'email' => $this->Auth->user('email'),'org' => 'IN2'));
	        $this->redirect($this->Auth->redirect());
	    } else {
                // don't display "invalid user" before first login attempt
               if($this->request->is('post')) $this->Session->setFlash(__('Invalid username or password, try again'));

	    }
	}

	public function routeafterlogin() {
	    // Terms and Conditions Page
	    if (!$this->Auth->user('termsaccepted')) {
	        $this->redirect(array('action' => 'terms'));
	    }

	    // News page
	    $new_newsdate = new DateTime("2012-03-27");	// TODO general, fixed odd date??
	    $newsdate = new DateTime($this->Auth->user('newsread'));
	    if ($new_newsdate > $newsdate) {
	        $this->redirect(array('action' => 'news'));
	    }

	    // Events list
	    $this->redirect(array('controller' => 'events', 'action' => 'index'));
	}

	public function logout() {
		$this->extraLog("logout");	// TODO Audit, extraLog, check: customLog i.s.o. extraLog, $this->User->customLog('logout', $this->Auth->user('id'), array());
	    $this->Session->setFlash('Good-Bye');
	    $this->redirect($this->Auth->logout());
	}


	public function resetauthkey($id = null) {
	    if (!$id) {
	        $this->Session->setFlash(__('Invalid id for user', true), 'default', array(), 'error');
	        $this->redirect(array('action'=>'index'));
	    }
	    if ('me' == $id ) $id = $this->Auth->user('id');

// 	    Replaced by isAuthorized
// 	    // only allow reset key for own account, except for admins
// 	    if (!$this->_isAdmin() && $id != $this->Auth->user('id')) {
// 	        throw new ForbiddenException('Not authorized to reset the key for this user');
// 	    }

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
	    $types_histogram = $this->Attribute->find('all', $params);
	    $this->set('types_histogram', $types_histogram);

	    // Nice graphical histogram
	    $this->loadModel('Attribute');
	    $sig_types = array_keys($this->Attribute->type_definitions);

	    $graph_fields = '';
	    foreach ($sig_types as $sig_type) {
	        if ($graph_fields != "")  $graph_fields .= ", ";
	        $graph_fields .= "'".$sig_type."'";
	    }
	    $this->set('graph_fields', $graph_fields);

	    $replace = array('-', '|');
	    $graph_data=array();
	    $prev_row_org = "";
	    $i = -1;
	    foreach ($types_histogram as $row) {
	        if ($prev_row_org != $row['Event']['org']) {
	            $i++; $graph_data[] = "";
	            $prev_row_org = $row['Event']['org'];
    	        $graph_data[$i] .= "org: '".$row['Event']['org']."'";
	        }
	        $graph_data[$i] .= ', '.str_replace($replace, "_", $row['Attribute']['type']).': '.$row[0]['num_types'];
	    }
	    $this->set('graph_data', $graph_data);

	}

	public function terms() {
	    if ($this->request->is('post') || $this->request->is('put')) {
	        $this->User->id = $this->Auth->user('id');
	        $this->User->saveField('termsaccepted', true);

	        $this->_refreshAuth();  // refresh auth info
	        $this->Session->setFlash(__('You accepted the Terms and Conditions.'));
	        $this->redirect(array('action' => 'routeafterlogin'));
    	}
    	$this->set('termsaccepted', $this->Auth->user('termsaccepted'));
	}

	public function news() {
	    $this->User->id = $this->Auth->user('id');
	    $this->User->saveField('newsread', date("Y-m-d"));
	    $this->_refreshAuth();  // refresh auth info
	}

    public function extraLog($action = null, $description = null, $fields_result = null) {	// TODO move audit to AuditsController?
		// configuration
		ClassRegistry::init('ConnectionManager');
    	$dbh = ConnectionManager::getDataSource('default');
		$dbhost     = $dbh->config['host'];
    	$dbport     = $dbh->config['port'];
		$dbname     = $dbh->config['database'];
		$dbuser     = $dbh->config['login'];
    	$dbpass     = $dbh->config['password'];
    	$dbprefix   = $dbh->config['prefix'];	// TODO Audit, extra, db prefix delimiter?
		
		// database connection
		$conn = new PDO("mysql:host=$dbhost;port=$dbport;dbname=$dbname",$dbuser,$dbpass);

		// new data
		$user_id = $this->Auth->user('id');
		$model = 'User';
		$model_id = $this->Auth->user('id');
		$org = $this->Auth->user('org');
		$email = $this->Auth->user('email');
		$action_date = new DateTime();
		$action_date_str = $action_date->format('Y-m-d H:i:sP');
		$description = "User (". $this->Auth->user('id')."): " .$this->Auth->user('email');

				// query
		$sql = "INSERT INTO ".$dbprefix."logs (org,email,created,action,title,`change`) VALUES (:org,:email,:created,:action,:title,:change)";
		$q = $conn->prepare($sql);
		$q->execute(array(':org'=>$org,
				          ':email'=>$email,
				          ':created'=>$action_date_str,
				          ':action'=>$action,
				          ':title'=>$description,
				          ':change'=>$fields_result));

		// database connection disconnect
		$dbh = null;
		
		// write to syslogd as well
		$syslog = new SysLog();
		if ($fields_result) $syslog->write('notice', $description.' -- '.$action.' -- '.$fields_result);
		else $syslog->write('notice', $description.' -- '.$action);		
	}
	
	// used for fields_before and fields for audit
	public function arrayCopy( array $array ) {
        $result = array();
        foreach( $array as $key => $val ) {
            if( is_array( $val ) ) {
                $result[$key] = arrayCopy( $val );
            } elseif ( is_object( $val ) ) {
                $result[$key] = clone $val;
            } else {
                $result[$key] = $val;
            }
        }
        return $result;
	}
	
	// TODO ACL examples
	
	public function checkDB() {		
		define('DEBUG', 3);	// general
		$group = $this->User->Group;
		//Allow admins to everything
		$group->id = 2;
		echo 'check1 controllers: ';
		if ($this->Acl->check($group, 'controllers', '*')) echo 'true';
		else echo 'false';
		echo '<br>';
		echo 'check2 Events: ';
		if ($this->Acl->check($group, 'controllers/Events', '*')) echo 'true';
		else echo 'false';
		echo '<br>';
		echo 'check3 Attributes: ';
		if ($this->Acl->check($group, 'controllers/Attributes', '*')) echo 'true';
		else echo 'false';
		echo '<br>';
		exit;
	}
		
	public function initDB() {
		$group = $this->User->Group;
		//Allow admins to everything
		$group->id = 2;
		$this->Acl->allow($group, 'controllers');
		$this->Acl->deny($group, 'controllers/Groups');
		$this->Acl->allow($group, 'controllers/Users');
		$this->Acl->allow($group, 'controllers/Events');
		$this->Acl->allow($group, 'controllers/Attributes');
		echo "all done";
		exit;
	}
}
