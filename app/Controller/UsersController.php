<?php
App::uses('AppController', 'Controller');
/**
 * Users Controller
 *
 * @property User $User
 */
class UsersController extends AppController {

    
    public $components = array('Security');

    function beforeFilter() {
        parent::beforeFilter();
    
        // what pages are allowed for non-logged-in users
        $this->Auth->allow('login', 'logout');

        // These variables are required for every view
        $this->set('me', $this->Auth->user());
        $this->set('isAdmin', $this->_isAdmin());
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
        if (in_array($this->action, array('edit', 'delete', 'resetauthkey'))) {
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
		// Only own profile 
		if ($this->Auth->user('id') != $id) {
		    throw new ForbiddenException('You are not authorized to access this profile.');
		}
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
// 		Replaced by isAuthorized
// 		// Only own profile
// 		if ($this->Auth->user('id') != $id) {
// 		    throw new ForbiddenException('You are not authorized to edit this profile.');
// 		}
		if ($this->request->is('post') || $this->request->is('put')) {
		    // What fields should be saved (allowed to be saved)
		    $fieldList=array('email', 'autoalert', 'gpgkey', 'nids_sid' );
		    if ("" != $this->data['User']['password'])
		        $fieldList[] = 'password';
		    // Save the data
		    if ($this->User->save($this->request->data, true ,$fieldList)) {
				$this->Session->setFlash(__('The profile has been updated'));
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
		}
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
			if ($this->User->save($this->request->data)) {
				$this->Session->setFlash(__('The user has been saved'));
				$this->redirect(array('action' => 'index'));
			} else {
				$this->Session->setFlash(__('The user could not be saved. Please, try again.'));
			}
		} else {
			$this->request->data = $this->User->read(null, $id);
		}
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
	        $this->redirect($this->Auth->redirect());
	    } else {
	        $this->Session->setFlash(__('Invalid username or password, try again'));
	    }
	}
	
	public function routeafterlogin() {
	    // Terms and Conditions Page
	    if (!$this->Auth->user('termsaccepted')) {
	        $this->redirect(array('action' => 'terms'));
	    }
	
	    // News page
	    $new_newsdate = new DateTime("2012-03-15");
	    $newsdate = new DateTime($this->Auth->user('newsread'));
	    if ($new_newsdate > $newsdate) {
	        $this->redirect(array('action' => 'news'));
	    }
	
	    // Events list
	    $this->redirect(array('controller' => 'events', 'action' => 'index'));
	}
	
	public function logout() {
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
	    $this->loadModel('Signature');
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
	
	    // What org posted what type of signature
	    $this->loadModel('Signature');
	    $fields = array('Event.org', 'Signature.type', 'count(Signature.type) as `num_types`');
	    $params = array('recursive' => 0,
	                        'fields' => $fields,
	                        'group' => array('Signature.type', 'Event.org'),
	                        'order' => array('Event.org', 'num_types DESC'),
	    );
	    $types_histogram = $this->Signature->find('all', $params);
	    $this->set('types_histogram', $types_histogram);
	    
	    // Nice graphical histogram
	    $this->loadModel('Signature');
	    $sig_types = $this->Signature->validate['type']['rule'][1];
	    
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
	        $graph_data[$i] .= ', '.str_replace($replace, "_", $row['Signature']['type']).': '.$row[0]['num_types'];
	    }
	    $this->set('graph_data', $graph_data);
	    
	  
// 	    var store = Ext.create('Ext.data.JsonStore', {
// 	        fields: ['year', 'comedy', 'action', 'drama', 'thriller'],
// 	        data: [
// 	        {
//             year: 2005, comedy: 34000000, action: 23890000, drama: 18450000, thriller: 20060000},
//             {
//             year: 2006, comedy: 56703000, action: 38900000, drama: 12650000, thriller: 21000000},
//             {
//             year: 2007, comedy: 42100000, action: 50410000, drama: 25780000, thriller: 23040000},
//             {
//             year: 2008, comedy: 38910000, action: 56070000, drama: 24810000, thriller: 26940000}
//             ]
// 	    });
	
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
	
	
	

}
