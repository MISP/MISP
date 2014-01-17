<?php
/**
 * Application level Controller
 *
 * This file is application-wide controller file. You can put all
 * application-wide controller-related methods here.
 *
 * PHP 5
 *
 * CakePHP(tm) : Rapid Development Framework (http://cakephp.org)
 * Copyright 2005-2012, Cake Software Foundation, Inc. (http://cakefoundation.org)
 *
 * Licensed under The MIT License
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright     Copyright 2005-2012, Cake Software Foundation, Inc. (http://cakefoundation.org)
 * @link          http://cakephp.org CakePHP(tm) Project
 * @package       app.Controller
 * @since         CakePHP(tm) v 0.2.9
 * @license       MIT License (http://www.opensource.org/licenses/mit-license.php)
 */

// TODO GPG encryption has issues when keys are expired

App::uses('Controller', 'Controller');
App::uses('File', 'Utility');

/**
 * Application Controller
 *
 * Add your application-wide methods in the class below, your controllers
 * will inherit them.
 *
 * @package       app.Controller
 * @link http://book.cakephp.org/2.0/en/controllers.html#the-app-controller
 *
 * @throws ForbiddenException // TODO Exception
 */
class AppController extends Controller {

	public $defaultModel = '';

	public $debugMode = false;

	public function __construct($id = false, $table = null, $ds = null) {
		parent::__construct($id, $table, $ds);

		$name = get_class($this);
		$name = str_replace('sController', '', $name);
		$name = str_replace('Controller', '', $name);
		$this->defaultModel = $name;
	}

	public $components = array(
			'Session',
			'Auth' => array(
				'className' => 'SecureAuth',
				'authenticate' => array(
					'Form' => array(
						'fields' => array('username' => 'email')
					)
				),
				'authError' => 'Unauthorised access.',
				'loginRedirect' => array('controller' => 'users', 'action' => 'routeafterlogin'),
				'logoutRedirect' => array('controller' => 'users', 'action' => 'login'),
				//'authorize' => array('Controller', // Added this line
				//'Actions' => array('actionPath' => 'controllers')) // TODO ACL, 4: tell actionPath
				),
	);

	public function beforeFilter() {
		
		// send users away that are using ancient versions of IE
		// Make sure to update this if IE 20 comes out :)
		if(preg_match('/(?i)msie [2-8]/',$_SERVER['HTTP_USER_AGENT']) && !strpos($_SERVER['HTTP_USER_AGENT'], 'Opera')) throw new MethodNotAllowedException('You are using an unsecure version of IE, please download Google Chrome, Mozilla Firefox or update to a newer version of IE.');
		
		// REST authentication
		if ($this->_isRest() || $this->isJson()) {
			// disable CSRF for REST access
			if (array_key_exists('Security', $this->components))
				$this->Security->csrfCheck = false;

			// Authenticate user with authkey in Authorization HTTP header
			if (!empty($_SERVER['HTTP_AUTHORIZATION'])) {
				$user = $this->checkAuthUser($_SERVER['HTTP_AUTHORIZATION']);
				if ($user) {
				    // User found in the db, add the user info to the session
				    $this->Session->renew();
				    $this->Session->write(AuthComponent::$sessionKey, $user['User']);
				} else {
					// User not authenticated correctly
					// reset the session information
					$this->Session->destroy();
					throw new ForbiddenException('The authentication key provided cannot be used for syncing.');
				}
			}
		}
		// user must accept terms
		//
		if ($this->Session->check('Auth.User') && !$this->Auth->user('termsaccepted') && (!in_array($this->request->here, array('/users/terms', '/users/logout', '/users/login')))) {
		    $this->redirect(array('controller' => 'users', 'action' => 'terms', 'admin' => false));
		}
		if ($this->Session->check('Auth.User') && $this->Auth->user('change_pw') && (!in_array($this->request->here, array('/users/terms', '/users/change_pw', '/users/logout', '/users/login')))) {
		    $this->redirect(array('controller' => 'users', 'action' => 'change_pw', 'admin' => false));
		}

		// We don't want to run these role checks before the user is logged in, but we want them available for every view once the user is logged on
		// instead of using checkAction(), like we normally do from controllers when trying to find out about a permission flag, we can use getActions()
		// getActions returns all the flags in a single SQL query
		if ($this->Auth->user()) {
			$role = $this->getActions();
			$this->set('me', $this->Auth->user());
			$this->set('isAdmin', $role['perm_admin']);
			$this->set('isSiteAdmin', $role['perm_site_admin']);
			$this->set('isAclAdd', $role['perm_add']);
			$this->set('isAclModify', $role['perm_modify']);
			$this->set('isAclModifyOrg', $role['perm_modify_org']);
			$this->set('isAclPublish', $role['perm_publish']);
			$this->set('isAclSync', $role['perm_sync']);
			$this->set('isAclAdmin', $role['perm_admin']);
			$this->set('isAclAudit', $role['perm_audit']);
			$this->set('isAclAuth', $role['perm_auth']);
			$this->set('isAclRegexp', $role['perm_regexp_access']);
			$this->userRole = $role;
		} else {
			$this->set('me', false);
			$this->set('isAdmin', false);
			$this->set('isSiteAdmin', false);
			$this->set('isAclAdd', false);
			$this->set('isAclModify', false);
			$this->set('isAclModifyOrg', false);
			$this->set('isAclPublish', false);
			$this->set('isAclSync', false);
			$this->set('isAclAdmin', false);
			$this->set('isAclAudit', false);
			$this->set('isAclAuth', false);
			$this->set('isAclRegexp', false);
		}
		if (Configure::read('debug') > 0) {
			$this->debugMode = 'debugOn';
		} else {
			$this->debugMode = 'debugOff';
		}
		$this->set('debugMode', $this->debugMode);
		$proposalCount = $this->_getProposalCount();
		$this->set('proposalCount', $proposalCount[0]);
		$this->set('proposalEventCount', $proposalCount[1]);
	}

	public $userRole = null;

	public function isJson(){
		return $this->request->header('Accept') === 'application/json';
	}

	//public function blackhole($type) {
	//	// handle errors.
	//	throw new Exception(__d('cake_dev', 'The request has been black-holed'));
	//	//throw new BadRequestException(__d('cake_dev', 'The request has been black-holed'));
	//}

	protected function _isRest() {
		return (isset($this->RequestHandler) && ($this->RequestHandler->isXml() || $this->isJson()));
	}

	private function _getProposalCount() {
		$this->loadModel('ShadowAttribute');
		$this->ShadowAttribute->recursive = -1;
		$shadowAttributes = $this->ShadowAttribute->find('all', array(
				'recursive' => -1,
				'fields' => array('event_id', 'event_org'),
				'conditions' => array( 
					'ShadowAttribute.event_org' => $this->Auth->user('org')
		)));
		$results = array();
		$eventIds = array();
		$results[0] = count($shadowAttributes);
		foreach ($shadowAttributes as $sa) {
			if (!in_array($sa['ShadowAttribute']['event_id'], $eventIds)) $eventIds[] = $sa['ShadowAttribute']['event_id'];
		}
		$results[1] = count($eventIds);
		return $results;
	}
	
/**
 * Convert an array to the same array but with the values also as index instead of an interface_exists
 */
	protected function _arrayToValuesIndexArray($oldArray) {
		$newArray = Array();
		foreach ($oldArray as $value)
		$newArray[$value] = $value;
		return $newArray;
	}

/**
 * checks if the currently logged user is an administrator (an admin that can manage the users and events of his own organisation)
 */
	protected function _isAdmin() {
		$org = $this->Auth->user('org');
		if ($this->userRole['perm_site_admin'] || $this->userRole['perm_admin']) {
			return true;
		}
		return false;
	}

/**
 * checks if the currently logged user is a site administrator (an admin that can manage any user or event on the instance and create / edit the roles).
 */
	protected function _isSiteAdmin() {
		return $this->userRole['perm_site_admin'];
	}

	protected function _checkOrg() {
		return $this->Auth->user('org');
	}

/**
 * Refreshes the Auth session with new/updated data
 * @return void
 */
	protected function _refreshAuth() {
		$this->loadModel('User');
		$this->User->recursive = -1;
		$user = $this->User->findById($this->Auth->user('id'));
		$this->Auth->login($user['User']);
	}

/**
 *
 * @param $action
 * @return boolean
 */

	// pass an action to this method for it to check the active user's access to the action
	public function checkAction($action = 'perm_sync') {
		$this->loadModel('Role');
		$this->Role->recursive = -1;
		$role = $this->Role->findById($this->Auth->user('role_id'));
		if ($role['Role'][$action]) return true;
		return false;
	}

	// returns the role of the currently authenticated user as an array, used to set the permission variables for views in the AppController's beforeFilter() method
	public function getActions() {
		$this->loadModel('Role');
		$this->Role->recursive = -1;
		$role = $this->Role->findById($this->Auth->user('role_id'));
		return $role['Role'];
	}

/**
 *
 * @param unknown $authkey
 * @return boolean or user array
 */
	public function checkAuthUser($authkey) {
		$this->loadModel('User');
		$this->User->recursive = -1;
		$user = $this->User->findByAuthkey($authkey);
		if (isset($user['User'])) {
			$this->loadModel('Role');
			$this->Role->recursive = -1;
			$role = $this->Role->findById($user['User']['role_id']);
			$user['User']['siteAdmin'] = false;
			if ($role['Role']['perm_site_admin']) $user['User']['siteAdmin'] = true;
			if ($role['Role']['perm_auth']) {
				return $user;
			}
		}
		return false;
	}

	public function generatePrivate() {
		$this->generatePrivateForAttributes();
		$this->generatePrivateForEvents();
	}

	public function generatePrivateForAttributes() {
		if (!self::_isSiteAdmin()) throw new NotFoundException();

		$this->loadModel('Attribute');
		$attributes = $this->Attribute->find('all', array('recursive' => 0));
		foreach ($attributes as $attribute) {
			if ($attribute['Attribute']['private']) {
				$attribute['Attribute']['private'] = true;
				$attribute['Attribute']['cluster'] = false;
				$attribute['Attribute']['communitie'] = false;
			} else {
				$attribute['Attribute']['private'] = false;
				$attribute['Attribute']['cluster'] = false;
				$attribute['Attribute']['communitie'] = false;
			}
			$this->Attribute->save($attribute);
		}
	}

	public function generatePrivateForEvents() {
		if (!self::_isSiteAdmin()) throw new NotFoundException();

		$this->loadModel('Event');
		$events = $this->Event->find('all', array('recursive' => 0));
		foreach ($events as $event) {
			if ($event['Event']['private']) {
				$event['Event']['private'] = true;
				$event['Event']['cluster'] = false;
				$event['Event']['communitie'] = false;
			} else {
				$event['Event']['private'] = false;
				$event['Event']['cluster'] = false;
				$event['Event']['communitie'] = false;
			}
			$event['Event']['orgc'] = $event['Event']['org'];
			$event['Event']['dist_change'] = 0;
			$event['Event']['analysis'] = 2;
			$this->Event->save($event);
		}
	}

	public function generateCount() {
		if (!self::_isSiteAdmin()) throw new NotFoundException();
		// do one SQL query with the counts
		// loop over events, update in db
		$this->loadModel('Attribute');
		$events = $this->Attribute->find('all', array(
			'recursive' => -1,
			'fields' => array('event_id', 'count(event_id) as attribute_count'),
			'group' => array('Attribute.event_id'),
			'order' => array('Attribute.event_id ASC'),
		));
		foreach ($events as $k => $event) {
			$this->Event->read(null, $event['Attribute']['event_id']);
			$this->Event->set('attribute_count', $event[0]['attribute_count']);
			$this->Event->save();
		}
		$this->Session->setFlash(__('All done. attribute_count generated from scratch for ' . $k . ' events.'));
		$this->redirect(array('controller' => 'pages', 'action' => 'display', 'administration'));
	}

/**
 * CakePHP returns false if filesize is 0 at lib/cake/Utility/File.php:384
 */
	public function checkEmpty($fileP = '/var/www/cydefsig/app/files/test') {
		// Check if there were problems with the file upload
		// only keep the last part of the filename, this should prevent directory attacks
		$filename = basename($fileP);
		$tmpfile = new File($fileP);

		debug($fileP);
		debug($tmpfile);
		debug($tmpfile->size());
		debug($tmpfile->md5());
		debug(md5_file($fileP));
		$md5 = !$tmpfile->size() ? md5_file($fileP) : $tmpfile->md5();
		debug($md5);
	}

/**
 * generateAllFor<FieldName>
 *
 * @throws NotFoundException // TODO Exception
 **/
	public function generateAllFor($field) {
		if (!self::_isSiteAdmin()) throw new NotFoundException();

		// contain the newValue and oldValue
		$methodArgs = $this->params['pass'];
		// use call_user_func_array() to pass the newValue and oldValue
		$success = call_user_func_array(array($this->{$this->defaultModel}, 'generateAllFor' . $field), $methodArgs);

		// give feedback
		$this->set('succes', $success);
		$this->render('succes');
	}

	public function call($method, $dummySecond) {
		$this->__call($method, $dummySecond);
	}

	public function __call($method, $dummySecond) {
		$args = $this->params['pass']; // TODO this is naughty
		if (strpos($method, 'generateAllFor') === 0) {
			// massage the args
			$methodArgs = $args;
			$methodArgs[0] = str_replace('generateAllFor', '', $method); // TODO
			//array_unshift($methodArgs, str_replace('generateAllFor', '', $method));
			// do the actual call
			return call_user_func_array(array($this, 'generateAllFor'), $methodArgs);
		}

		//if (strpos($method, 'findBy') === 0) {
		//	//debug(true);debug(tru);
		//}
		return false;
	}
}