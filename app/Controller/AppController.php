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
App::uses('Sanitize', 'Utility');

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

	public function __construct($id = false, $table = null, $ds = null) {
		parent::__construct($id, $table, $ds);

		$name = get_class($this);
		$name = str_replace('sController', '', $name);
		$name = str_replace('Controller', '', $name);
		$this->defaultModel = $name;
	}

	public $components = array(
			'Acl',			// TODO ACL, components
			'Session',
			'Auth' => array(
				'className' => 'SecureAuth',
				'authenticate' => array(
					'Form' => array(
						'fields' => array('username' => 'email')
					)
				),
				'authError' => 'Did you really think you are allowed to see that?',
				'loginRedirect' => array('controller' => 'users', 'action' => 'routeafterlogin'),
				'logoutRedirect' => array('controller' => 'users', 'action' => 'login'),
				'authorize' => array('Controller', // Added this line
				'Actions' => array('actionPath' => 'controllers')) // TODO ACL, 4: tell actionPath
				)
	);

	public function isAuthorized($user) {
		if (self::_isAdmin()) {
			return true; // admin can access every action on every controller
		}
		return false; // The rest don't
	}

	public function beforeFilter() {
		// user must accept terms
		//
		// TODO $this->Session->check('Auth.User') (16:32:45) andras.iklody@gmail.com: think this was documented as check('Auth')

		if ($this->Session->check('Auth.User') && !$this->Auth->user('termsaccepted') && (!in_array($this->request->here, array('/users/terms', '/users/logout', '/users/login')))) {
			$this->redirect(array('controller' => 'users', 'action' => 'terms', 'admin' => false));
		}
		if ($this->Session->check('Auth.User') && $this->Auth->user('change_pw') && (!in_array($this->request->here, array('/users/terms', '/users/change_pw', '/users/logout', '/users/login')))) {
			$this->redirect(array('controller' => 'users', 'action' => 'change_pw', 'admin' => false));
		}

		// REST things
		if ($this->_isRest()) {
			// disable CSRF for REST access
			if (array_key_exists('Security', $this->components))
				$this->Security->csrfCheck = false;

			// Authenticate user with authkey in Authorization HTTP header
			if (!empty($_SERVER['HTTP_AUTHORIZATION'])) {
				//Sanitize the authkey
				$authkey = Sanitize::clean($_SERVER['HTTP_AUTHORIZATION']);
				if (!$this->checkAuthUser($authkey)) {
					throw new ForbiddenException('The authentication key provided cannot be used for syncing.');
				}
				$this->loadModel('User');
				$params = array(
						'conditions' => array('User.authkey' => $authkey),
						'recursive' => 0,
				);
				$user = $this->User->find('first', $params);

				if ($user) {
					// User found in the db, add the user info to the session
					$this->Session->renew();
					$this->Session->write(AuthComponent::$sessionKey, $user['User']);
				} else {
					// User not authenticated correctly
					// reset the session information
					$this->Session->destroy();
					throw new ForbiddenException('Incorrect authentication key');
				}
			}
		} else {
			//$this->Security->blackHoleCallback = 'blackhole'; // TODO needs more investigation
		}

		// These variables are required for every view
		$this->set('me', Sanitize::clean($this->Auth->user()));
		$this->set('isAdmin', $this->_isAdmin());
		$this->set('isSiteAdmin', $this->_isSiteAdmin());

		// TODO ACL: 5: from Controller to Views
		$this->set('isAclAdd', $this->checkAcl('add'));
		$this->set('isAclModify', $this->checkAcl('edit'));
		$this->set('isAclModifyOrg', $this->checkRole());
		$this->set('isAclPublish', $this->checkAcl('publish'));
		$this->set('isAclAdd2', $this->checkAction('perm_add'));
		$this->set('isAclSync', $this->checkAction('perm_sync'));
		$this->set('isAclAdmin', $this->checkAction('perm_admin'));
		$this->set('isAclAudit', $this->checkAction('perm_audit'));
		$this->set('isAclAuth', $this->checkAction('perm_auth'));
	}

	//public function blackhole($type) {
	//	// handle errors.
	//	throw new Exception(__d('cake_dev', 'The request has been black-holed'));
	//	//throw new BadRequestException(__d('cake_dev', 'The request has been black-holed'));
	//}

	protected function _isRest() {
		return (isset($this->RequestHandler) && $this->RequestHandler->isXml());
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
 * checks if the currently logged user is an administrator
 */
	protected function _isAdmin() {
		$org = $this->Auth->user('org');
		if ((isset($org) && $org === 'ADMIN') || $this->checkAction('perm_admin')) {
			return true;
		}
		return false;
	}

/**
 * checks if the currently logged user is a site administrator
 */
	protected function _isSiteAdmin() {
		$org = $this->Auth->user('org');
		if (isset($org) && $org === 'ADMIN') {
			return true;
		}
		return false;
	}

	protected function _checkOrg() {
		return $this->Auth->user('org');
	}

/**
 * Refreshes the Auth session with new/updated data
 * @return void
 */
	protected function _refreshAuth() {
		if (isset($this->User)) {
			$user = $this->User->read(false, $this->Auth->user('id'));
		} else {
			$user = ClassRegistry::init('User')->findById($this->Auth->user('id'));
		}
		$this->Auth->login($user['User']);
	}

/**
 * Updates the missing fields from v0.1 to v0.2 of CyDefSIG
 * First you will need to manually update the database to the new schema.
 * Log in as admin user and
 * Then run this function by setting debug = 1 (or more) and call /events/migrate01to02
 *
 * @throws NotFoundException // TODO Exception
 */
	public function migrate01to02() {
		if (!self::_isAdmin()) throw new NotFoundException();

		// generate uuids for events who have no uuid
		$this->loadModel('Event');
		$params = array(
				'conditions' => array('Event.uuid' => ''),
				'recursive' => 0,
				'fields' => array('Event.id'),
		);
		$events = $this->Event->find('all', $params);

		echo '<p>Generating UUID for events: ';
		foreach ($events as $event) {
			$this->Event->id = $event['Event']['id'];
			$this->Event->saveField('uuid', String::uuid());
			echo $event['Event']['id'] . ' ';
		}
		echo "</p>";
		// generate uuids for attributes who have no uuid
		$this->loadModel('Attribute');
		$params = array(
				'conditions' => array('Attribute.uuid' => ''),
				'recursive' => 0,
				'fields' => array('Attribute.id'),
		);
		$attributes = $this->Attribute->find('all', $params);
		echo '<p>Generating UUID for attributes: ';
		foreach ($attributes as $attribute) {
			$this->Attribute->id = $attribute['Attribute']['id'];
			$this->Attribute->saveField('uuid', String::uuid());
			echo $attribute['Attribute']['id'] . ' ';
		}
		echo "</p>";
	}

/**
 * Updates the missing fields from v0.2 to v0.2.1 of CyDefSIG
 * First you will need to manually update the database to the new schema.
 * Log in as admin user and
 * Then run this function by setting debug = 1 (or more) and call /events/migrate02to021
 *
 * @throws NotFoundException // TODO Exception
 */
	private function __explodeValueToValues() {
		// search for composite value1 fields and explode it to value1 and value2
		$this->loadModel('Attribute');
		$params = array(
				'conditions' => array(
						'OR' => array(
								'Attribute.type' => $this->Attribute->getCompositeTypes()
						)
				),
				'recursive' => 0,
				'fields' => array('Attribute.id', 'Attribute.value1'),
		);
		$attributes = $this->Attribute->find('all', $params);
		echo '<h2>Exploding composite fields in 2 columns: </h2><ul>';
		foreach ($attributes as $attribute) {
			$pieces = explode('|', $attribute['Attribute']['value1']);
			if (2 != count($pieces)) continue;	// do nothing if not 2 pieces

			$this->Attribute->id = $attribute['Attribute']['id'];
			echo '<li>' . $attribute['Attribute']['id'] . ' --> ' . $attribute['Attribute']['value1'] . ' --> ' . $pieces[0] . ' --> ' . $pieces[1] . '</li> ';
			$this->Attribute->saveField('value1', $pieces[0]);
			$this->Attribute->id = $attribute['Attribute']['id'];
			$this->Attribute->saveField('value2', $pieces[1]);
		}
		echo "</ul> DONE.";
	}

	public function migrate02to021() {
		if (!self::_isAdmin()) {
			throw new NotFoundException();
		}

		// search for composite value1 fields and explode it to value1 and value2
		$this->__explodeValueToValues();
	}

	public function migrate021to022() {
		if (!self::_isAdmin()) throw new NotFoundException();

		// replace description by comment

		// replace empty category
		// not easy as we have to guess the category from the type
		//$this->loadModel('Attribute');
		// $params = array(
		//		 'conditions' => array('Attribute.type' => ''),
		//		 'recursive' => 0,
		//		 'fields' => array('Attribute.id'),
		// );
		// $attributes = $this->Attribute->find('all', $params);
		// echo '<p>Replacing empty categories by OtherExploding composite fields in 2 columns: </p><ul>';
		// foreach ($attributes as $attribute) {
		//	 $pieces = explode('|', $attribute['Attribute']['value1']);
		//	 if (2 != sizeof($pieces)) continue;	// do nothing if not 2 pieces

		//	 $this->Attribute->id = $attribute['Attribute']['id'];
		//	 echo '<li>'.$attribute['Attribute']['id'].' --> '.$attribute['Attribute']['value1'].' --> '.$pieces[0].' --> '.$pieces[1].'</li> ';
		//	 $this->Attribute->saveField('value1', $pieces[0]);
		//	 $this->Attribute->id = $attribute['Attribute']['id'];
		//	 $this->Attribute->saveField('value2', $pieces[1]);
		// }
		// echo "</ul> DONE</p>";

		// search for incompatible combination of category / type
	}

	public function migratemisp02to10() {
		if (!self::_isAdmin()) {
			throw new NotFoundException();
		}

		// add missing columns, rename other columns
		$queries = array(
		// ATTRIBUTES
				// rename value to value1
				"ALTER TABLE `attributes` CHANGE `value` `value1` TEXT CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL "
				// add value2
				,"ALTER TABLE `attributes` ADD `value2` TEXT CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL AFTER `value1` "
				// fix the keys
				,"ALTER TABLE `attributes` DROP INDEX `uuid`;"
				,"ALTER TABLE `attributes` ADD INDEX `value1_key` ( `value1` ( 5 ) ) ;"
				,"ALTER TABLE `attributes` ADD INDEX `value2_key` ( `value2` ( 5 ) ) ;"
		// EVENTS
				// remove useless things
				,"ALTER TABLE `events` DROP `user_id`"
				,"ALTER TABLE `events` DROP `alerted`"
				,"ALTER TABLE `events` ADD `revision` INT( 10 ) NOT NULL DEFAULT '0' AFTER `uuid` "
				// fix the keys
				,"ALTER TABLE events DROP INDEX uuid"
				,"ALTER TABLE events DROP INDEX info"
		// SERVERS
				// rename lastfetchedid to lastpushedid
				,"ALTER TABLE `servers` CHANGE `lastfetchedid` `lastpushedid` INT( 11 ) NOT NULL "
				// add lastpulledid
				,"ALTER TABLE `servers` ADD `lastpulledid` INT( 11 ) NOT NULL AFTER `lastpushedid` "
		// USERS
				// fix keys
				,"ALTER TABLE `users` DROP INDEX `username`"
				,"ALTER TABLE `users` ADD INDEX `email` ( `email` ) "
		);
		// execute the queries
		foreach ($queries as &$query) {
			$result = $this->{$this->modelClass}->query($query);
		}
	}

	public function migratemisp10to11() {
		if (!self::_isAdmin()) {
			throw new NotFoundException();
		}

		// add missing columns, rename other columns
		$queries = array(
		// EVENTS
				// bring user_id back in
				"ALTER TABLE `events` ADD `user_id` INT( 11 ) NOT NULL AFTER `info` "
		);
		// execute the queries
		foreach ($queries as &$query) {
			$result = $this->{$this->modelClass}->query($query);
		}
	}

	public function migratemisp11to2($yourOrg = 'NCIRC') {
		if (!self::_isAdmin()) {
			throw new NotFoundException();
		}

		$this->generatePrivate();
		$this->generateCorrelation(); // 	TODO
		$this->generateCount();
		// Deprecated - hop unused currently, also, it would generate hop count 1 for all local events created by other hosted orgs.
		// $this->generateHop($yourOrg);
		$this->generateArosAcos();
	}

	public function generateArosAcos() {
		if (!self::_isAdmin()) throw new NotFoundException();
		$this->loadModel('Role');
		$roles = $this->Role->find('all',array('recursive' => 0));
		foreach ($roles as $role) {
			$this->generateACL($role);
		}
		exit;
	}

	public function generateACL($inc) {
		if (!self::_isAdmin()) throw new NotFoundException();
		if ($inc['Role']['permission'] == null) $inc['Role']['permission'] = 0;
		switch ($inc['Role']['permission']) {
			case '0':
				$permAdd = false;
				$permModify = false;
				$PermModifyOrg = false;
				$permPublish = false;
				break;
			case '1':
				$permAdd = true;
				$permModify = true;
				$PermModifyOrg = false;
				$permPublish = false;
				break;
			case '2':
				$permAdd = true;
				$permModify = true;
				$PermModifyOrg = true;
				$permPublish = false;
				break;
			case '3':
				$permAdd = true;
				$permModify = true;
				$PermModifyOrg = true;
				$permPublish = true;
				break;
			default:
				break;
		}
		//$this->Acl->allow($inc, 'controllers/Events/add');
		if ($permAdd) {
			$this->Acl->allow($inc, 'controllers/Events/add');
			$this->Acl->allow($inc, 'controllers/Attributes/add');
		} else {
			$this->Acl->deny($inc, 'controllers/Events/add');
			$this->Acl->deny($inc, 'controllers/Attributes/add');
		}
		if ($permModify) {
			$this->Acl->allow($inc, 'controllers/Events/edit');
			$this->Acl->allow($inc, 'controllers/Attributes/edit');
		} else {
			$this->Acl->deny($inc, 'controllers/Events/edit');
			$this->Acl->deny($inc, 'controllers/Attributes/edit');
		}
		if ($permPublish) {
			$this->Acl->allow($inc, 'controllers/Events/publish');
		} else {
			$this->Acl->deny($inc, 'controllers/Events/publish');
		}
		if (isset($inc['Role']['perm_sync'])) {
			if ($inc['Role']['perm_sync']) {
				$this->Acl->allow($inc, 'controllers/Servers');
			}
		} else {
				$this->Acl->deny($inc, 'controllers/Servers');
		}

		if (isset($inc['Role']['perm_audit'])) {
			if ($inc['Role']['perm_audit']) {
				$this->Acl->allow($inc, 'controllers/Logs');
			}
		} else {
			$this->Acl->deny($inc, 'controllers/Logs');
		}

		if (isset($inc['Role']['perm_admin']) && $inc['Role']['perm_admin']) {
				//$this->Acl->allow($inc, 'controllers/Logs');
		} else {
			$this->Acl->deny($inc, 'controllers/Roles');
			//$this->Acl->deny($inc, 'controllers');
		}
		if (isset($inc['Role']['perm_auth'])) {
			if ($inc['Role']['perm_auth']) {
			}
		} else {
			$this->Acl->deny($inc, 'controllers/Events/export');
		}
	}

	public function generateCorrelation() {
		if (!self::_isAdmin()) throw new NotFoundException();

		$this->loadModel('Correlation');
		$this->Correlation->deleteAll(array('id !=' => ''), false);
		$this->loadModel('Attribute');
		$fields = array('Attribute.id', 'Attribute.event_id', 'Attribute.private', 'Attribute.cluster', 'Event.date', 'Event.org');
		// get all attributes..
		$attributes = $this->Attribute->find('all',array('recursive' => 0));
		// for all attributes..
		foreach ($attributes as $attribute) {
			$this->Attribute->setInitialRelatedAttributes($attribute['Attribute'], $fields = array());

			//// i want to keep this in repo for a moment
			//$relatedAttributes = $this->Attribute->getRelatedAttributes($attribute['Attribute'], $fields);
			//if ($relatedAttributes) {
			//	foreach ($relatedAttributes as $relatedAttribute) {
			//		// and store into table
			//		$this->Correlation->create();
			//		$this->Correlation->save(array('Correlation' => array(
			//		'1_event_id' => $attribute['Attribute']['event_id'], '1_attribute_id' => $attribute['Attribute']['id'],
			//		'event_id' => $relatedAttribute['Attribute']['event_id'], 'attribute_id' => $relatedAttribute['Attribute']['id'],
			//		'date' => $relatedAttribute['Event']['date'])));
			//	}
			//}
		}
	}

/**
 * TODO ACL, 6b: check on Role and per Model (not used)
 */
	public function checkAccess() {
		$aco = ucfirst($this->params['controller']);
		$user = ClassRegistry::init('User')->findById($this->Auth->user('id'));
		return $this->Acl->check($user, 'controllers/' . $aco, '*');
	}

/**
 * TODO ACL, EXTRA: mixed in Org!!
 */
	public function checkRole() {
		$modifyRole = false;
		$user = ClassRegistry::init('User')->findById($this->Auth->user('id'));
		if (isset($user['User'])) {
			$role = ClassRegistry::init('Role')->findById($user['User']['role_id']);
			if ($role['Role']['perm_modify_org']) {
				$modifyRole = true;
			}
		}
		return $modifyRole;
	}

/**
 * TODO ACL, EXTRA: mixed in Sync!!
 */
	public function checkAction($action = 'perm_sync') {
		$maySync = false;
		$user = ClassRegistry::init('User')->findById($this->Auth->user('id'));
		if (isset($user['User'])) {
			$role = ClassRegistry::init('Role')->findById($user['User']['role_id']);
			if ($role['Role'][$action]) {
				$maySync = true;
			}
		}
		return $maySync;
	}

/**
 *
 * @param unknown $authkey
 * @return boolean
 */
	public function checkAuthUser($authkey) {
		$result = false;
		$user = ClassRegistry::init('User')->findByAuthkey($authkey);
		if (isset($user['User'])) {
			$role = ClassRegistry::init('Role')->findById($user['User']['role_id']);
			if ($role['Role']['perm_auth']) {
				$result = true;
			}
		}
		return $result;
	}

/**
 * TODO ACL, 6: check on Role and any Model
 *
 * @throws NotFoundException // TODO Exception
 */
	public function checkAcl($action) {
		$aco = 'Events';	// TODO ACL was 'Attributes'
		$user = ClassRegistry::init('User')->findById($this->Auth->user('id'));
		// TODO ACL, CHECK, below if indicates some wrong: Fatal error: Call to a member function check() on a non-object in /var/www/cydefsig/app/Controller/AppController.php on line 289
		if ($this->Acl) {
			return $this->Acl->check($user, 'controllers/' . $aco . '/' . $action, '*');
		} else {
			return true;
		}
	}

	public function generatePrivate() {
		$this->generatePrivateForAttributes();
		$this->generatePrivateForEvents();
	}

	public function generatePrivateForAttributes() {
		if (!self::_isAdmin()) throw new NotFoundException();

		$this->loadModel('Attribute');
		$attributes = $this->Attribute->find('all', array('recursive' => 0));
		foreach ($attributes as $attribute) {
			if ($attribute['Attribute']['private']) {
				$attribute['Attribute']['private'] = true;
				$attribute['Attribute']['cluster'] = false;
				$attribute['Attribute']['communitie'] = false;
			} else {
				$attribute['Attribute']['private'] = false;
				$attribute['Attribute']['cluster'] = true;
				$attribute['Attribute']['communitie'] = false;
			}
			$this->Attribute->save($attribute);
		}
	}

	public function generatePrivateForEvents() {
		if (!self::_isAdmin()) throw new NotFoundException();

		$this->loadModel('Event');
		$events = $this->Event->find('all', array('recursive' => 0));
		foreach ($events as $event) {
			if ($event['Event']['private']) {
				$event['Event']['private'] = true;
				$event['Event']['cluster'] = false;
				$event['Event']['communitie'] = false;
			} else {
				$event['Event']['private'] = false;
				$event['Event']['cluster'] = true;
				$event['Event']['communitie'] = false;
			}
			$event['Event']['orgc'] = $event['Event']['org'];
			$event['Event']['dist_change'] = 0;
			$event['Event']['analysis'] = 2;
			$event['Event']['hop_count'] = 0;
			$this->Event->save($event);
		}
	}

	public function generateCount() {
		if (!self::_isAdmin()) throw new NotFoundException();

		$this->loadModel('Attribute');
		$attributes = $this->Attribute->find('all', array('recursive' => 0));
		// for all attributes..
		foreach ($attributes as $attribute) {
			$this->Attribute->save($attribute);
		}
	}

/**
 * generate Hop count
 * 0: orig
 * +1: one step downstream
 *
 * @throws NotFoundException
 *
 * @param unknown_type $yourOrg being f.i. 'NCIRC' or 'MIL.be'
 */
	public function generateHop($yourOrg = 'NCIRC') {
		if (!self::_isAdmin()) throw new NotFoundException();

		$this->loadModel('Event');
		$events = $this->Event->find('all', array('recursive' => 0));
		// for all attributes..
		foreach ($events as $event) {
			$event['Event']['hop_count'] = $event['Event']['org'] == $yourOrg ? '0' : '1';
			$this->Event->save($event);
		}
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
		if (!self::_isAdmin()) throw new NotFoundException();

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

	public $reservedTags = array( // TODO custom Tags like <Random>
		array('<Random>', '[RaDdom]')
	);

	public function beforeSanitizeClean($str) {
		// TODO custom Tags like <Random>
		foreach ($this->reservedTags as $reservedTagset) {
			$str = str_replace($reservedTagset[0], $reservedTagset[1], $str);
		}
		return $str;
	}

	public function counterSanitizeClean($str) {
		// TODO custom Tags like <Random>
		foreach ($this->reservedTags as $reservedTagset) {
			$str = str_replace($reservedTagset[1], $reservedTagset[0], $str);
		}

		// TODO standard HTML 'markup'
		$str = str_replace('\n', chr(10), $str);
		$str = str_replace('\\\\', '\\', $str);
		$str = str_replace('&amp;', '&', $str);
		$str = str_replace('&quot;', '"', $str);

		return $str;
	}
}