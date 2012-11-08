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
/**
 * Application Controller
 *
 * Add your application-wide methods in the class below, your controllers
 * will inherit them.
 *
 * @package       app.Controller
 * @link http://book.cakephp.org/2.0/en/controllers.html#the-app-controller
 */
class AppController extends Controller {

	public $components = array(
			'Acl',			// TODO XXX remove
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
		// REST things
		if ($this->_isRest()) {
			// disable CSRF for REST access
			if (array_key_exists('Security', $this->components))
				$this->Security->csrfCheck = false;

			// Authenticate user with authkey in Authorization HTTP header
			if (!empty($_SERVER['HTTP_AUTHORIZATION'])) {
				$authkey = $_SERVER['HTTP_AUTHORIZATION'];
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
		$this->set('me', $this->Auth->user());
		$this->set('isAdmin', $this->_isAdmin());

		// TODO ACL: 5: from Controller to Views
		$this->set('isAclAdd', $this->checkAcl('add'));
		$this->set('isAclModify', $this->checkAcl('edit'));
		$this->set('isAclModifyOrg', $this->checkGroup());
		$this->set('isAclPublish', $this->checkAcl('publish'));
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
		if (isset($org) && $org === 'ADMIN') {
			return true;
		}
		return false;
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
 * @throws NotFoundException
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

	public function generateCorrelation() {
		if (!self::_isAdmin()) throw new NotFoundException();

		$this->loadModel('Correlation');
		$this->loadModel('Attribute');
		$fields = array('Attribute.id', 'Attribute.event_id', 'Attribute.private', 'Event.date', 'Event.org');
		// get all attributes..
		$attributes = $this->Attribute->find('all',array('recursive' => 0));
		// for all attributes..
		foreach ($attributes as $attribute) {
			$this->Attribute->setRelatedAttributes($attribute['Attribute'], $fields = array());

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
 * TODO ACL, 6b: check on Group and per Model (not used)
 */
	public function checkAccess() {
		$aco = ucfirst($this->params['controller']);
		$user = ClassRegistry::init('User')->findById($this->Auth->user('id'));
		return $this->Acl->check($user, 'controllers/' . $aco, '*');
	}

/**
 * TODO ACL, EXTRA: mixed in Org!!
 */
	public function checkGroup() {
		$modifyGroup = false;
		$user = ClassRegistry::init('User')->findById($this->Auth->user('id'));
		if (isset($user)) {
			$group = ClassRegistry::init('Group')->findById($user['User']['group_id']);
			if ($group['Group']['perm_modify_org']) {
				$modifyGroup = true;
			}
		}
		return $modifyGroup;
	}

/**
 * TODO ACL, 6: check on Group and any Model
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
		if (!self::_isAdmin()) throw new NotFoundException();

		$this->loadModel('Correlation');
		$this->loadModel('Attribute');
		$attributes = $this->Attribute->find('all',array('recursive' => 0));
		foreach ($attributes as $attribute) {
			if ($attribute['Attribute']['private']) {
				$attribute['Attribute']['private'] = false;
				$attribute['Attribute']['pull'] = true;
			}
			$this->Attribute->save($attribute);
		}

		$this->loadModel('Event');
		$events = $this->Event->find('all',array('recursive' => 0));
		foreach ($events as $event) {
			if ($event['Event']['private']) {
				$event['Event']['private'] = false;
				$event['Event']['pull'] = true;
			}
			$this->Event->save($event);
		}
	}
}
