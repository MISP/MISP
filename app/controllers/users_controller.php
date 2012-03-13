<?php
class UsersController extends AppController {

    var $name = 'Users';
//     var $components = array('Security');  FIXME results in 404 when editing form, caused by the $this->data['User']['password'] = ""; // empty out the password

    function beforeFilter() {
        parent::beforeFilter();
        
        // what pages are allowed for everyone
        $this->Auth->allow('login', 'logout');

        // Prevent XSRF
//         $this->Security->requireAuth('add', 'edit');
        
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
        
        if (empty($me_user['User']['gpgkey'])) {
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
            if (empty($this->data['User']['authkey'])) $this->data['User']['authkey'] = $this->User->generateAuthKey();
            $this->User->create();
            
            if ($this->User->save($this->data)) {
                // LATER send out email to user to inform of new user
                // LATER send out email to admins to inform of new user
                $this->Session->setFlash(__('The user has been saved', true));
                $this->redirect(array('action' => 'index'));
            } else {
                $this->Session->setFlash(__('The user could not be saved. Please, try again.', true), 'default', array(), 'error');
                return;
            }
        }
        $groups = $this->User->Group->find('list');
        $this->set(compact('groups'));
    }

    function edit($id = null) {        
    	$me_user = $this->Auth->user();
        
        if (!$id && empty($this->data)) {
            $this->Session->setFlash(__('Invalid user', true), 'default', array(), 'error');
            $this->redirect(array('action' => 'index'));
        }
        if ('me' == $id ) $id = $me_user['User']['id'];

        // only allow access to own profile, except for admins
        if (!$this->isAdmin() && $id != $me_user['User']['id']) {
        	$this->Session->setFlash(__('Not authorized to edit this user', true), 'default', array(), 'error');
            $this->redirect(array('action' => 'index'));
        }
        
        if (!empty($this->data)) {
            $this->User->read(null, $id);
            
            if ("" != $this->data['User']['password'] && $this->data['User']['password'] != Security::hash('', null, true))   // workaround because password is automagically hashed
				    $this->User->set('password', $this->data['User']['password']);
            $this->User->set('email', $this->data['User']['email']);
            $this->User->set('autoalert', $this->data['User']['autoalert']);	
            $this->User->set('gpgkey', $this->data['User']['gpgkey']);	
            $this->User->set('nids_sid', $this->data['User']['nids_sid']);

			// administrative actions 
			if ($this->isAdmin()) {
				$this->User->set('group_id', $this->data['User']['group_id']);
				$this->User->set('org', $this->data['User']['org']);
			}
			
            if ($this->User->save()) {
                $this->Session->setFlash(__('The user has been saved', true));
                $this->Session->write('Auth', $this->User->read(null, $me_user['User']['id']));  // refresh auth info
                $this->redirect(array('action' => 'view', $id));
            } else {
                $this->Session->setFlash(__('The user could not be saved. Please, try again.', true), 'default', array(), 'error');
            }

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
        if ('me' == $id ) $id = $me_user['User']['id'];
        
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
            
        } else {
            $this->Session->setFlash(__('User was not deleted', true), 'default', array(), 'error');
        }
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


    function routeafterlogin() {
        $me_user = $this->Auth->user();
        
        // Terms and Conditions Page
        if (0 == $me_user['User']['termsaccepted']) {
            $this->redirect(array('action' => 'terms'));
        }
        
        // News page
        $new_newsdate = new DateTime("2012-03-12");
        $newsdate = new DateTime($me_user['User']['newsread']);
        if ($new_newsdate > $newsdate) {
            $this->redirect(array('action' => 'news'));
        }
        
        // Events list
        $this->redirect(array('controller' => 'events', 'action' => 'index'));
    }
    
    function logout() {
        $this->Session->setFlash('Good-Bye');
        $this->redirect($this->Auth->logout());
    }
    
    function resetauthkey($id = null) {
        $me_user = $this->Auth->user();
        if (!$id) {
            $this->Session->setFlash(__('Invalid id for user', true), 'default', array(), 'error');
            $this->redirect(array('action'=>'index'));
        }
        if ('me' == $id ) $id = $me_user['User']['id'];
        
        // only allow reset key for own account, except for admins
        if (!$this->isAdmin() && $id != $me_user['User']['id']) {
            $this->Session->setFlash(__('Not authorized to reset the key for this user', true), 'default', array(), 'error');
            $this->redirect(array('action' => 'index'));
        }
        
        
        $data = array(
           'User' => array(
                'id'          =>    $id,
                'authkey'   =>    $this->User->generateAuthKey()
            )
        );
        if ($this->User->save( $data, false, array('authkey') )) {
            $this->Session->setFlash(__('New authkey generated.', true));
            $this->Session->write('Auth', $this->User->read(null, $me_user['User']['id']));  // refresh auth info
        } else {
            $this->Session->setFlash(__('Auth key could not be changed. Please, try again.', true), 'default', array(), 'error');
        }
        
        $this->redirect($this->referer());
        
    }

    
    function memberslist() {
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
        
//         $fields = array('User.org', 'count(User.id) as `num_members`', 'count(Event.id) as `num_events`');
//         $params = array('recursive' => 0,
//                                 'fields' => $fields,
//                                 'group' => array('User.org'),
//                                 'order' => array('User.org'),
//         );
//         $orgs = $this->Event->find('all', $params);
//         $this->set('orgs', $orgs);
        
        
        
        
        // What org posted what type of signature
        // LATER beautify types_histogram
        $this->loadModel('Signature');
        $fields = array('Event.org', 'Signature.type', 'count(Signature.type) as `num_types`');
        $params = array('recursive' => 0,
                        'fields' => $fields,
                        'group' => array('Signature.type', 'Event.org'),
                        'order' => array('Event.org', 'num_types DESC'),
        );
        $types_histogram = $this->Signature->find('all', $params);
        $this->set('types_histogram', $types_histogram);
        
        
    }
    
    
    
    
    function terms() {
        $me_user = $this->Auth->user();
        
        if (!empty($this->data)) {
            $user = $this->User->read(null, $me_user['User']['id']);
            $user['User']['termsaccepted'] = 1;
            $this->User->save($user);
            $this->Session->write('Auth', $user);  // refresh auth info

            $this->redirect(array('action' => 'routeafterlogin'));
        }

        $this->set('termsaccepted', $me_user['User']['termsaccepted']);
        
    }
    
    function news() {
        $me_user = $this->Auth->user();
        
        $user = $this->User->read(null, $me_user['User']['id']);
        $user['User']['newsread'] = date("Y-m-d");
        $this->User->save($user);
        $this->Session->write('Auth', $user);  // refresh auth info
        
        
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
