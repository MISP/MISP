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
 * Copyright 2005-2011, Cake Software Foundation, Inc. (http://cakefoundation.org)
 *
 * Licensed under The MIT License
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright     Copyright 2005-2011, Cake Software Foundation, Inc. (http://cakefoundation.org)
 * @link          http://cakephp.org CakePHP(tm) Project
 * @package       app.Controller
 * @since         CakePHP(tm) v 0.2.9
 * @license       MIT License (http://www.opensource.org/licenses/mit-license.php)
 */

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
    		'Session',
    		'Auth' => array(
                'authenticate' => array(
                    'Form' => array(
                        'fields' => array('username' => 'email')
                    )
                ),
    			'loginRedirect' => array('controller' => 'users', 'action' => 'routeafterlogin'),
     			'logoutRedirect' => array('controller' => 'users', 'action' => 'login'),
    			'authorize' => array('Controller') // Added this line
    )
    );


    public function isAuthorized($user) {
        if (isset($user['org']) && $user['org'] === 'admin') {
            return true; // admin can access every action on every controller
        }
        return false; // The rest don't
    }

    function beforeFilter() {

    }


    /**
     * Convert an array to the same array but with the values also as index instead of an interface_exists
     */
    function _arrayToValuesIndexArray($old_array) {
        $new_array = Array();
        foreach ($old_array as $value)
        $new_array[$value] = $value;
        return $new_array;
    }

    /**
     * checks if the currently logged user is an administrator
     */
    public function _isAdmin() {
        $user = $this->Auth->user();
        if (isset($user['org']) && $user['org'] === 'admin') {
            return true;
        }
        return false;
    }

    /**
     * Refreshes the Auth session with new/updated data
     * @return void
     */
    function _refreshAuth() {
		if (isset($this->User)) {
		    $user = $this->User->read(false, $this->Auth->user('id'));
		} else {
		    $user= ClassRegistry::init('User')->findById($this->Auth->user('id'));
		}
		$this->Auth->login($user['User']);
    }


    /**
     * Updates the missing fields from v0.1 to v0.2 of CyDefSIG
     */
    function migrate () {
        // generate uuids for events who have no uuid
        $this->loadModel('Event');


        // generate uuids for attributes who have no uuid
        $this->loadModel('Attribute');

        debug("foo");
    }



}
