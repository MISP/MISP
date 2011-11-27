<?php
class UsersController extends AppController {

    var $name = 'Users';
    var $components = array('Recaptcha.Recaptcha');

    function beforeFilter() {
        parent::beforeFilter();
        
        // what pages are allowed for everyone
        $this->Auth->allow('login', 'logout');
                
        // These variables are required for every view
        $me_user = $this->Auth->user();
        $this->set('me', $me_user['User']);
        $this->set('isAdmin', $this->isAdmin());
    }
    

    function index() {
        if (!$this->isAdmin()) {
        	$this->Session->setFlash(__('Not authorized to list users', true), 'default', array(), 'error');
            $this->redirect(array('controller' => 'events' , 'action' => 'index'));
        }
        
        $this->User->recursive = 0;
        $this->set('users', $this->paginate());
    }

    function view($id = null) {
        $me_user = $this->Auth->user();
        if (!$id) {
            $this->Session->setFlash(__('Invalid user', true), 'default', array(), 'error');
            $this->redirect(array('action' => 'index'));
        }
        
        if ('me' == $id ) $id = $me_user['User']['id'];

        // only allow access to own profile, except for admins
        if (!$this->isAdmin() && $id != $me_user['User']['id']) {
        	$this->Session->setFlash(__('Not authorized to view this user', true), 'default', array(), 'error');
            $this->redirect(array('controller' => 'events' , 'action' => 'index'));
        }
        
        $user = $this->User->read(null, $id);
        
        if (empty($me['User']['gpgkey'])) {
            $this->Session->setFlash(__('No GPG key set in your profile. To receive emails, submit your public key in your profile.', true), 'default', array(), 'gpg');
        }
        
        $this->set('user', $user);
    }

    function add() {
        if (!$this->isAdmin()) {
        	$this->Session->setFlash(__('Not authorized to create new users', true), 'default', array(), 'error');
            $this->redirect(array('controller' => 'events' , 'action' => 'index'));
        }

        if (!empty($this->data)) {
            if ($this->data['User']['password'] == '1deba050eee85e4ea7447edc6c289e4f55b81d45' ) { 
                // FIXME bug of auth ??? when passwd is empty it adds this hash
                $this->data['User']['password'] = '';
            }
            if (empty($this->data['User']['authkey'])) $this->data['User']['authkey'] = sha1('foo'+time()); // FIXME write more secure authkey generation into a function
            $this->User->create();
            
            if ($this->User->save($this->data)) {
                // TODO send out email to user to inform of new user
                // TODO send out email to admins to inform of new user
                $this->Session->setFlash(__('The user has been saved', true));
                $this->redirect(array('action' => 'index'));
            } else {
                $this->Session->setFlash(__('The user could not be saved. Please, try again.', true), 'default', array(), 'error');
            }
        }
        $groups = $this->User->Group->find('list');
        $this->set(compact('groups'));
    }

    function edit($id = null) {
    	$user = $this->Auth->user();
        
        if (!$id && empty($this->data)) {
            $this->Session->setFlash(__('Invalid user', true), 'default', array(), 'error');
            $this->redirect(array('action' => 'index'));
        }
        if ('me' == $id ) $id = $user['User']['id'];

        // only allow access to own profile, except for admins
        if (!$this->isAdmin() && $id != $user['User']['id']) {
        	$this->Session->setFlash(__('Not authorized to edit this user', true), 'default', array(), 'error');
            $this->redirect(array('action' => 'index'));
        }
        
        if (!empty($this->data)) {
            $this->User->read(null, $id);
            
            if ("" != $this->data['User']['password'] && $this->data['User']['password'] != '1deba050eee85e4ea7447edc6c289e4f55b81d45' ) // FIXME bug of auth ??? when passwd is empty it adds this hash
				    $this->User->set('password', $this->data['User']['password']);
            $this->User->set('email', $this->data['User']['email']);
            $this->User->set('autoalert', $this->data['User']['autoalert']);	
            $this->User->set('gpgkey', $this->data['User']['gpgkey']);	
            // LATER import the gpg key in the keychain, and remove the old key
            // TODO check the key for validity
			// LATER let the user reset his XML key


			// administrative actions 
			if ($this->isAdmin()) {
				$this->User->set('group_id', $this->data['User']['group_id']);
				$this->User->set('org', $this->data['User']['org']);
			}
			
            if ($this->User->save()) {
                $this->Session->setFlash(__('The user has been saved', true));
                $this->redirect(array('action' => 'view', $id));
            } else {
                $this->Session->setFlash(__('The user could not be saved. Please, try again.', true), 'default', array(), 'error');
            }

//             if (empty($this->data['User']['authkey'])) $this->data['User']['authkey'] = sha1('foo'+time()); // TODO place authkey generation into a function
//             if ($this->User->save($this->data)) {
//                 $this->Session->setFlash(__('The user has been saved', true));
//                 $this->redirect(array('action' => 'index'));
//             } else {
//                 $this->Session->setFlash(__('The user could not be saved. Please, try again.', true), 'default', array(), 'error');
//             }
        }
        if (empty($this->data)) {
            $this->data = $this->User->read(null, $id);    
        }
        $this->data['User']['password'] = ""; // empty out the password
        $groups = $this->User->Group->find('list');
        $this->set(compact('groups'));
    }

    function delete($id = null) {
        $me_user = $this->Auth->user();
        if (!$id) {
            $this->Session->setFlash(__('Invalid id for user', true), 'default', array(), 'error');
            $this->redirect(array('action'=>'index'));
        }
        if ('me' == $id ) $id = $user['User']['id'];
        
        // only allow delete own account, except for admins
        if (!$this->isAdmin() && $id != $me_user['User']['id']) {
        	$this->Session->setFlash(__('Not authorized to delete this user', true), 'default', array(), 'error');
            $this->redirect(array('action' => 'index'));
        }
        
        if ($this->User->delete($id)) {
            $this->Session->setFlash(__('User deleted', true));
            if (!$this->isAdmin()) {
                // user deletes himself, force logout
                $this->redirect(array('action'=>'logout'));
            }
        }
        $this->Session->setFlash(__('User was not deleted', true), 'default', array(), 'error');
        $this->redirect(array('action' => 'index'));
    }
    
    
    
    function login() {
//        if (!empty($this->data)) {
//            // FIXME get the captcha to work
//            if ($this->Recaptcha->verify()) {
//                // do something, save you data, login, whatever
//                
//            } else {
//                // display the raw API error
//                $this->Session->setFlash($this->Recaptcha->error);
//                $this->redirect($this->Auth->logout());
//            }
//        }
        
        // if user is already logged in
        if ($this->Session->read('Auth.User')) {
            $this->Session->setFlash('You are already logged in!');
            $this->redirect('/', null, false);
        }
    
    }       

     
    function logout() {
        $this->Session->setFlash('Good-Bye');
        $this->redirect($this->Auth->logout());
    }
    
    
    
    
    function initDB() {
        $group =& $this->User->Group;
        //Allow admins to everything
        $group->id = 1;     
        $this->Acl->allow($group, 'controllers');
     
        //allow managers to posts and widgets
        $group->id = 2;
        $this->Acl->deny($group, 'controllers');
        $this->Acl->allow($group, 'controllers/Events');
        $this->Acl->allow($group, 'controllers/Signatures');
        $this->Acl->allow($group, 'controllers/Users');
     
        //we add an exit to avoid an ugly "missing views" error message
        echo "all done";
        exit;
    }
    


}
