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
	Router::connect('/allowedlists/admin_index/*', array('controller' => 'allowedlists', 'action' => 'index', 'admin' => true));
	Router::connect('/users/admin_index/*', array('controller' => 'users', 'action' => 'index', 'admin' => true));
	Router::connect('/roles/admin_index/*', array('controller' => 'roles', 'action' => 'index', 'admin' => true));
	Router::connect('/logs/admin_search/*', array('controller' => 'logs', 'action' => 'search', 'admin' => true));
	Router::connect('/audit_logs/admin_index/*', array('controller' => 'audit_logs', 'action' => 'index', 'admin' => true));
	Router::connect('/access_logs/admin_index/*', array('controller' => 'access_logs', 'action' => 'index', 'admin' => true));
	Router::connect('/logs/admin_index/*', array('controller' => 'logs', 'action' => 'index', 'admin' => true));
	Router::connect('/regexp/admin_index/*', array('controller' => 'regexp', 'action' => 'index', 'admin' => true));

	// Activate REST
	Router::mapResources(array('events', 'attributes'));
	Router::parseExtensions('xml', 'json', 'csv');

	Router::connectNamed(
		array('attributesPage' => array('controller' => 'events', 'action' => 'view'))
	);
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
