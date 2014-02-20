<?php
/**
 * Routes configuration
 *
 * In this file, you set up routes to your controllers and their actions.
 * Routes are very important mechanism that allows you to freely connect
 * different urls to chosen controllers and their actions (functions).
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
 * @package       app.Config
 * @since         CakePHP(tm) v 0.2.9
 * @license       MIT License (http://www.opensource.org/licenses/mit-license.php)
 */
/**
 * Here, we are connecting '/' (base path) to controller called 'Pages',
 * its action called 'display', and we pass a param to select the view file
 * to use (in this case, /app/View/Pages/home.ctp)...
 */
	Router::connect('/', array('controller' => 'events', 'action' => 'index'));

	// admin Paginator
	//Router::connect('/whitelists/admin_add/*', array('controller' => 'whitelists', 'action' => 'add', 'admin' => true));
	Router::connect('/whitelists/admin_index/*', array('controller' => 'whitelists', 'action' => 'index', 'admin' => true));
	//Router::connect('/whitelists/admin_edit/*', array('controller' => 'whitelists', 'action' => 'edit', 'admin' => true));
	//Router::connect('/whitelists/admin_delete/*', array('controller' => 'whitelists', 'action' => 'delete', 'admin' => true));

//	Router::connect('/regexp/admin_index/*', array('controller' => 'regexp', 'action' => 'index', 'admin' => true));

	Router::connect('/users/admin_index/*', array('controller' => 'users', 'action' => 'index', 'admin' => true));
	Router::connect('/roles/admin_index/*', array('controller' => 'roles', 'action' => 'index', 'admin' => true));
	Router::connect('/logs/admin_search/*', array('controller' => 'logs', 'action' => 'search', 'admin' => true));
//	Router::connect('/roles/admin_add/*', array('controller' => 'roles', 'action' => 'add', 'admin' => true));
//	Router::connect('/roles/admin_edit/*', array('controller' => 'roles', 'action' => 'edit', 'admin' => true));
	Router::connect('/logs/admin_index/*', array('controller' => 'logs', 'action' => 'index', 'admin' => true));
//	Router::connect('/logs/admin_search/*', array('controller' => 'logs', 'action' => 'search', 'admin' => true));

//	Router::connect('/admin/users/terms', array('controller' => 'users', 'action' => 'terms'));
	//Router::connect('/admin/users/login', array('controller' => 'users', 'action' => 'login', 'admin' => false));
	//Router::connect('/admin/users/routeafterlogin', array('controller' => 'users', 'action' => 'routeafterlogin'));

//	Router::connect('/admin/users/edit/:id', array('controller' => 'users', 'action' => 'edit'), array('pass' => array('field', 'id')));
//	Router::connect('/admin/users/view/:id', array('controller' => 'users', 'action' => 'view'), array('pass' => array('field', 'id')));
//	Router::connect('/:controller/:field/:newValue/:oldValue', array('action' => 'call'), array('pass' => array('field', 'newValue', 'oldValue')));

	// Activate REST
	Router::mapResources(array('events', 'attributes'));
	Router::parseExtensions('xml', 'json');

/**
 * Load all plugin routes.  See the CakePlugin documentation on
 * how to customize the loading of plugin routes.
 */
	CakePlugin::routes();

/**
 * Load the CakePHP default routes. Only remove this if you do not want to use
 * the built-in default routes.
 */
	require CAKE . 'Config' . DS . 'routes.php';
