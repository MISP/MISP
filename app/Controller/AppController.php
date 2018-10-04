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

// TODO GnuPG encryption has issues when keys are expired

App::uses('ConnectionManager', 'Model');
App::uses('Controller', 'Controller');
App::uses('File', 'Utility');
App::uses('RequestRearrangeTool', 'Tools');

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
class AppController extends Controller
{
    public $defaultModel = '';

    public $debugMode = false;

    public $helpers = array('Utility', 'OrgImg');

    private $__queryVersion = '44';
    public $pyMispVersion = '2.4.95';
    public $phpmin = '5.6.5';
    public $phprec = '7.0.16';

    public $baseurl = '';
	public $sql_dump = false;

    // Used for _isAutomation(), a check that returns true if the controller & action combo matches an action that is a non-xml and non-json automation method
    // This is used to allow authentication via headers for methods not covered by _isRest() - as that only checks for JSON and XML formats
    public $automationArray = array(
        'events' => array('csv', 'nids', 'hids', 'xml', 'restSearch', 'stix', 'updateGraph', 'downloadOpenIOCEvent'),
        'attributes' => array('text', 'downloadAttachment', 'returnAttributes', 'restSearch', 'rpz', 'bro'),
    );

    public function __construct($id = false, $table = null, $ds = null)
    {
        parent::__construct($id, $table, $ds);

        $name = get_class($this);
        $name = str_replace('sController', '', $name);
        $name = str_replace('Controller', '', $name);
        $this->defaultModel = $name;
    }

    public $components = array(
            'Session',
            'Auth' => array(
                'authError' => 'Unauthorised access.',
                'loginRedirect' => array('controller' => 'users', 'action' => 'routeafterlogin'),
                'logoutRedirect' => array('controller' => 'users', 'action' => 'login', 'admin' => false),
                'authenticate' => array(
                    'Form' => array(
                        'passwordHasher' => 'Blowfish',
                        'fields' => array(
                            'username' => 'email'
                        )
                    )
                )
            ),
            'Security',
            'ACL',
            'RestResponse',
            'Flash'
			//,'DebugKit.Toolbar'
    );

    private function __isApiFunction($controller, $action)
    {
        if (isset($this->automationArray[$controller]) && in_array($action, $this->automationArray[$controller])) {
            return true;
        }
        return false;
    }

    public function beforeFilter()
    {
		if (!empty($this->params['named']['sql'])) {
			$this->sql_dump = 1;
		}
        // check for a supported datasource configuration
        $dataSourceConfig = ConnectionManager::getDataSource('default')->config;
        if (!isset($dataSourceConfig['encoding'])) {
            $db = ConnectionManager::getDataSource('default');
            $db->setConfig(array('encoding' => 'utf8'));
            ConnectionManager::create('default', $db->config);
        }
        $dataSource = $dataSourceConfig['datasource'];
        if ($dataSource != 'Database/Mysql' && $dataSource != 'Database/Postgres') {
            throw new Exception('datasource not supported: ' . $dataSource);
        }

        $this->set('ajax', $this->request->is('ajax'));
        $this->set('queryVersion', $this->__queryVersion);
        $this->loadModel('User');
        $auth_user_fields = $this->User->describeAuthFields();
        $language = Configure::read('MISP.language');
        if (!empty($language) && $language !== 'eng') {
            Configure::write('Config.language', $language);
        } else {
            Configure::write('Config.language', 'eng');
        }

        //if fresh installation (salt empty) generate a new salt
        if (!Configure::read('Security.salt')) {
            $this->loadModel('Server');
            $this->Server->serverSettingsSaveValue('Security.salt', $this->User->generateRandomPassword(32));
        }
        // Check if the instance has a UUID, if not assign one.
        if (!Configure::read('MISP.uuid')) {
            $this->loadModel('Server');
            $this->Server->serverSettingsSaveValue('MISP.uuid', CakeText::uuid());
        }
        // check if Apache provides kerberos authentication data
        $envvar = Configure::read('ApacheSecureAuth.apacheEnv');
        if (isset($_SERVER[$envvar])) {
            $this->Auth->className = 'ApacheSecureAuth';
            $this->Auth->authenticate = array(
                'Apache' => array(
                    // envvar = field returned by Apache if user is authenticated
                    'fields' => array('username' => 'email', 'envvar' => $envvar),
                    'userFields' => $auth_user_fields
                )
            );
        } else {
            $this->Auth->authenticate['Form']['userFields'] = $auth_user_fields;
        }
        $versionArray = $this->{$this->modelClass}->checkMISPVersion();
        $this->mispVersion = implode('.', array_values($versionArray));

        $this->Security->blackHoleCallback = 'blackHole';

        // Let us access $baseurl from all views
        $baseurl = Configure::read('MISP.baseurl');
        if (substr($baseurl, -1) == '/') {
            // if the baseurl has a trailing slash, remove it. It can lead to issues with the CSRF protection
            $baseurl = rtrim($baseurl, '/');
            $this->loadModel('Server');
            $this->Server->serverSettingsSaveValue('MISP.baseurl', $baseurl);
        }
        if (trim($baseurl) == 'http://') {
            $this->Server->serverSettingsSaveValue('MISP.baseurl', '');
        }
        $this->baseurl = $baseurl;
        $this->set('baseurl', h($baseurl));

        // send users away that are using ancient versions of IE
        // Make sure to update this if IE 20 comes out :)
        if (isset($_SERVER['HTTP_USER_AGENT'])) {
            if (preg_match('/(?i)msie [2-8]/', $_SERVER['HTTP_USER_AGENT']) && !strpos($_SERVER['HTTP_USER_AGENT'], 'Opera')) {
                throw new MethodNotAllowedException('You are using an unsecure and outdated version of IE, please download Google Chrome, Mozilla Firefox or update to a newer version of IE. If you are running IE9 or newer and still receive this error message, please make sure that you are not running your browser in compatibility mode. If you still have issues accessing the site, get in touch with your administration team at ' . Configure::read('MISP.contact'));
            }
        }
        $userLoggedIn = false;
        if (Configure::read('Plugin.CustomAuth_enable')) {
            $userLoggedIn = $this->__customAuthentication($_SERVER);
        }
        if ($this->_isRest()) {
            $this->Security->unlockedActions = array($this->action);
        }
        if (!$userLoggedIn) {
            // REST authentication
            if ($this->_isRest() || $this->_isAutomation()) {
                // disable CSRF for REST access
                if (array_key_exists('Security', $this->components)) {
                    $this->Security->csrfCheck = false;
                }
                // If enabled, allow passing the API key via a named parameter (for crappy legacy systems only)
                $namedParamAuthkey = false;
                if (Configure::read('Security.allow_unsafe_apikey_named_param') && !empty($this->params['named']['apikey'])) {
                    $namedParamAuthkey = $this->params['named']['apikey'];
                }
                // Authenticate user with authkey in Authorization HTTP header
                if (!empty($_SERVER['HTTP_AUTHORIZATION']) || !empty($namedParamAuthkey)) {
                    $found_misp_auth_key = false;
                    $authentication = explode(',', $_SERVER['HTTP_AUTHORIZATION']);
                    if (!empty($namedParamAuthkey)) {
                        $authentication[] = $namedParamAuthkey;
                    }
                    $user = false;
                    foreach ($authentication as $auth_key) {
                        if (preg_match('/^[a-zA-Z0-9]{40}$/', trim($auth_key))) {
                            $found_misp_auth_key = true;
                            $temp = $this->checkAuthUser(trim($auth_key));
                            if ($temp) {
                                $user['User'] = $temp;
                            }
                        }
                    }
                    if ($found_misp_auth_key) {
                        if ($user) {
                            unset($user['User']['gpgkey']);
                            unset($user['User']['certif_public']);
                            // User found in the db, add the user info to the session
                            if (Configure::read('MISP.log_auth')) {
                                $this->Log = ClassRegistry::init('Log');
                                $this->Log->create();
                                $log = array(
                                        'org' => $user['User']['Organisation']['name'],
                                        'model' => 'User',
                                        'model_id' => $user['User']['id'],
                                        'email' => $user['User']['email'],
                                        'action' => 'auth',
                                        'title' => 'Successful authentication using API key',
                                        'change' => 'HTTP method: ' . $_SERVER['REQUEST_METHOD'] . PHP_EOL . 'Target: ' . $this->here,
                                );
                                $this->Log->save($log);
                            }
                            $this->Session->renew();
                            $this->Session->write(AuthComponent::$sessionKey, $user['User']);
                        } else {
                            // User not authenticated correctly
                            // reset the session information
                            $this->Session->destroy();
                            $this->Log = ClassRegistry::init('Log');
                            $this->Log->create();
                            $log = array(
                                    'org' => 'SYSTEM',
                                    'model' => 'User',
                                    'model_id' => 0,
                                    'email' => 'SYSTEM',
                                    'action' => 'auth_fail',
                                    'title' => 'Failed authentication using API key (' . trim($auth_key) . ')',
                                    'change' => null,
                            );
                            $this->Log->save($log);
                            throw new ForbiddenException('Authentication failed. Please make sure you pass the API key of an API enabled user along in the Authorization header.');
                        }
                        unset($user);
                    }
                }
                if ($this->Auth->user() == null) {
                    throw new ForbiddenException('Authentication failed. Please make sure you pass the API key of an API enabled user along in the Authorization header.');
                }
            } elseif (!$this->Session->read(AuthComponent::$sessionKey)) {
                // load authentication plugins from Configure::read('Security.auth')
                $auth = Configure::read('Security.auth');
                if ($auth) {
                    $this->Auth->authenticate = array_merge($auth, $this->Auth->authenticate);
                    if ($this->Auth->startup($this)) {
                        $user = $this->Auth->user();
                        if ($user) {
                            // User found in the db, add the user info to the session
                            $this->Session->renew();
                            $this->Session->write(AuthComponent::$sessionKey, $user);
                        }
                        unset($user);
                    }
                }
                unset($auth);
            }
        }
        $this->set('externalAuthUser', $userLoggedIn);
        // user must accept terms
        //
        // grab the base path from our base url for use in the following checks
        $base_dir = parse_url($baseurl, PHP_URL_PATH);

        // if MISP is running out of the web root already, just set this variable to blank so we don't wind up with '//' in the following if statements
        if ($base_dir == '/') {
            $base_dir = '';
        }

        if ($this->Auth->user()) {
            // update script
            $this->{$this->modelClass}->runUpdates();
            $user = $this->Auth->user();
            if (!isset($user['force_logout']) || $user['force_logout']) {
                $this->loadModel('User');
                $this->User->id = $this->Auth->user('id');
                $this->User->saveField('force_logout', false);
            }
            if ($this->Auth->user('disabled')) {
                $this->Log = ClassRegistry::init('Log');
                $this->Log->create();
                $log = array(
                        'org' => $this->Auth->user('Organisation')['name'],
                        'model' => 'User',
                        'model_id' => $this->Auth->user('id'),
                        'email' => $this->Auth->user('email'),
                        'action' => 'auth_fail',
                        'title' => 'Login attempt by disabled user.',
                        'change' => null,
                );
                $this->Log->save($log);
                $this->Auth->logout();
                if ($this->_isRest()) {
                    throw new ForbiddenException('Authentication failed. Your user account has been disabled.');
                } else {
                    $this->Flash->error('Your user account has been disabled.', array('key' => 'error'));
                    $this->redirect(array('controller' => 'users', 'action' => 'login', 'admin' => false));
                }
            }
            $this->set('default_memory_limit', ini_get('memory_limit'));
            if (isset($this->Auth->user('Role')['memory_limit'])) {
                if ($this->Auth->user('Role')['memory_limit'] !== '') {
                    ini_set('memory_limit', $this->Auth->user('Role')['memory_limit']);
                }
            }
            $this->set('default_max_execution_time', ini_get('max_execution_time'));
            if (isset($this->Auth->user('Role')['max_execution_time'])) {
                if ($this->Auth->user('Role')['max_execution_time'] !== '') {
                    ini_set('max_execution_time', $this->Auth->user('Role')['max_execution_time']);
                }
            }
        } else {
            if (!($this->params['controller'] === 'users' && $this->params['action'] === 'login')) {
                $this->redirect(array('controller' => 'users', 'action' => 'login', 'admin' => false));
            }
        }

        // check if MISP is live
        if ($this->Auth->user() && !Configure::read('MISP.live')) {
            $role = $this->getActions();
            if (!$role['perm_site_admin']) {
                $message = Configure::read('MISP.maintenance_message');
                if (empty($message)) {
                    $this->loadModel('Server');
                    $message = $this->Server->serverSettings['MISP']['maintenance_message']['value'];
                }
                if (strpos($message, '$email') && Configure::read('MISP.email')) {
                    $email = Configure::read('MISP.email');
                    $message = str_replace('$email', $email, $message);
                }
                $this->Flash->info($message);
                $this->Auth->logout();
                throw new MethodNotAllowedException($message);//todo this should pb be removed?
            } else {
                $this->Flash->error('Warning: MISP is currently disabled for all users. Enable it in Server Settings (Administration -> Server Settings -> MISP tab -> live)', array('clear' => 1));
            }
        }

        if ($this->Session->check(AuthComponent::$sessionKey)) {
            if ($this->action !== 'checkIfLoggedIn' || $this->request->params['controller'] !== 'users') {
                if (!empty(Configure::read('MISP.terms_file')) && !$this->Auth->user('termsaccepted') && (!in_array($this->request->here, array($base_dir.'/users/terms', $base_dir.'/users/logout', $base_dir.'/users/login', $base_dir.'/users/downloadTerms')))) {
                    //if ($this->_isRest()) throw new MethodNotAllowedException('You have not accepted the terms of use yet, please log in via the web interface and accept them.');
                    if (!$this->_isRest()) {
                        $this->redirect(array('controller' => 'users', 'action' => 'terms', 'admin' => false));
                    }
                } elseif ($this->Auth->user('change_pw') && (!in_array($this->request->here, array($base_dir.'/users/terms', $base_dir.'/users/change_pw', $base_dir.'/users/logout', $base_dir.'/users/login')))) {
                    //if ($this->_isRest()) throw new MethodNotAllowedException('Your user account is expecting a password change, please log in via the web interface and change it before proceeding.');
                    if (!$this->_isRest()) {
                        $this->redirect(array('controller' => 'users', 'action' => 'change_pw', 'admin' => false));
                    }
                } elseif (!$this->_isRest() && !($this->params['controller'] == 'news' && $this->params['action'] == 'index') && (!in_array($this->request->here, array($base_dir.'/users/terms', $base_dir.'/users/change_pw', $base_dir.'/users/logout', $base_dir.'/users/login')))) {
                    $newsread = $this->User->field('newsread', array('User.id' => $this->Auth->user('id')));
                    $this->loadModel('News');
                    $latest_news = $this->News->field('date_created', array(), 'date_created DESC');
                    if ($latest_news && $newsread < $latest_news) {
                        $this->redirect(array('controller' => 'news', 'action' => 'index', 'admin' => false));
                    }
                }
            }
        }
        unset($base_dir);
        // We don't want to run these role checks before the user is logged in, but we want them available for every view once the user is logged on
        // instead of using checkAction(), like we normally do from controllers when trying to find out about a permission flag, we can use getActions()
        // getActions returns all the flags in a single SQL query
        if ($this->Auth->user()) {
            $versionArray = $this->{$this->modelClass}->checkMISPVersion();
            $this->mispVersionFull = implode('.', array_values($versionArray));
            $this->set('mispVersion', implode('.', array($versionArray['major'], $versionArray['minor'], 0)));
            $this->set('mispVersionFull', $this->mispVersionFull);
            $role = $this->getActions();
            $this->set('me', $this->Auth->user());
            $this->set('isAdmin', $role['perm_admin']);
            $this->set('isSiteAdmin', $role['perm_site_admin']);
            $this->set('isAclAdd', $role['perm_add']);
            $this->set('isAclModify', $role['perm_modify']);
            $this->set('isAclModifyOrg', $role['perm_modify_org']);
            $this->set('isAclPublish', $role['perm_publish']);
            $this->set('isAclDelegate', $role['perm_delegate']);
            $this->set('isAclSync', $role['perm_sync']);
            $this->set('isAclAdmin', $role['perm_admin']);
            $this->set('isAclAudit', $role['perm_audit']);
            $this->set('isAclAuth', $role['perm_auth']);
            $this->set('isAclRegexp', $role['perm_regexp_access']);
            $this->set('isAclTagger', $role['perm_tagger']);
            $this->set('isAclTagEditor', $role['perm_tag_editor']);
            $this->set('isAclTemplate', $role['perm_template']);
            $this->set('isAclSharingGroup', $role['perm_sharing_group']);
            $this->set('isAclSighting', isset($role['perm_sighting']) ? $role['perm_sighting'] : false);
            $this->set('isAclZmq', isset($role['perm_publish_zmq']) ? $role['perm_publish_zmq'] : false);
            $this->userRole = $role;
        } else {
            $this->set('me', false);
        }
        $this->set('br', '<br />');
        $this->set('bold', array('<span class="bold">', '</span>'));
        if ($this->_isSiteAdmin()) {
            if (Configure::read('Session.defaults') == 'database') {
                $db = ConnectionManager::getDataSource('default');
                $sqlResult = $db->query('SELECT COUNT(id) AS session_count FROM cake_sessions WHERE expires < ' . time() . ';');
                if (isset($sqlResult[0][0]['session_count']) && $sqlResult[0][0]['session_count'] > 1000) {
                    $this->loadModel('Server');
                    $this->Server->updateDatabase('cleanSessionTable');
                }
            }
            if (Configure::read('site_admin_debug') && (Configure::read('debug') < 2)) {
                Configure::write('debug', 1);
            }
        }

        $this->debugMode = 'debugOff';
        if (Configure::read('debug') > 1) {
            $this->debugMode = 'debugOn';
        }
        $this->set('loggedInUserName', $this->__convertEmailToName($this->Auth->user('email')));
        $this->set('debugMode', $this->debugMode);
        $notifications = $this->{$this->modelClass}->populateNotifications($this->Auth->user());
        $this->set('notifications', $notifications);
        $this->ACL->checkAccess($this->Auth->user(), Inflector::variable($this->request->params['controller']), $this->action);
    }

	public function afterFilter()
	{
		if (Configure::read('debug') > 1 && !empty($this->sql_dump) && $this->_isRest()) {
			$this->Log = ClassRegistry::init('Log');
			echo json_encode($this->Log->getDataSource()->getLog(false, false), JSON_PRETTY_PRINT);
		}
	}

    public function queryACL($debugType='findMissingFunctionNames', $content = false)
    {
        $this->autoRender = false;
        $this->layout = false;
        $validCommands = array('printAllFunctionNames', 'findMissingFunctionNames', 'printRoleAccess');
        if (!in_array($debugType, $validCommands)) {
            throw new MethodNotAllowedException('Invalid function call.');
        }
        $this->set('data', $this->ACL->$debugType($content));
        $this->set('flags', JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
        $this->response->type('json');
        $this->render('/Servers/json/simple');
    }

    private function __convertEmailToName($email)
    {
        $name = explode('@', $email);
        $name = explode('.', $name[0]);
        foreach ($name as $key => $value) {
            $name[$key] = ucfirst($value);
        }
        $name = implode(' ', $name);
        return $name;
    }

    public function blackhole($type)
    {
        if ($type === 'csrf') {
            throw new BadRequestException($type);
        }
        throw new BadRequestException('The request has been black-holed');
    }

    public $userRole = null;

    protected function _isJson($data=false)
    {
        if ($data) {
            return (json_decode($data) != null) ? true : false;
        }
        return $this->request->header('Accept') === 'application/json' || $this->RequestHandler->prefers() === 'json';
    }

    protected function _isRest()
    {
        $api = $this->__isApiFunction($this->request->params['controller'], $this->request->params['action']);
        if (isset($this->RequestHandler) && ($api || $this->RequestHandler->isXml() || $this->_isJson())) {
            if ($this->_isJson()) {
                if (!empty($this->request->input()) && empty($this->request->input('json_decode'))) {
                    throw new MethodNotAllowedException('Invalid JSON input. Make sure that the JSON input is a correctly formatted JSON string. This request has been blocked to avoid an unfiltered request.');
                }
            }
            return true;
        } else {
            return false;
        }
    }

    protected function _isAutomation()
    {
        foreach ($this->automationArray as $controllerName => $controllerActions) {
            if ($this->params['controller'] == $controllerName && in_array($this->params['action'], $controllerActions)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Convert an array to the same array but with the values also as index instead of an interface_exists
     */
    protected function _arrayToValuesIndexArray($oldArray)
    {
        $newArray = array();
        foreach ($oldArray as $value) {
            $newArray[$value] = $value;
        }
        return $newArray;
    }

    // checks if the currently logged user is an administrator (an admin that can manage the users and events of his own organisation)
    protected function _isAdmin()
    {
        if ($this->userRole['perm_site_admin'] || $this->userRole['perm_admin']) {
            return true;
        }
        return false;
    }

    // checks if the currently logged user is a site administrator (an admin that can manage any user or event on the instance and create / edit the roles).
    protected function _isSiteAdmin()
    {
        return $this->userRole['perm_site_admin'];
    }

    protected function _checkOrg()
    {
        return $this->Auth->user('org_id');
    }

    protected function _getApiAuthUser(&$key, &$exception)
    {
        if (strlen($key) == 40) {
            // check if the key is valid -> search for users based on key
            $user = $this->checkAuthUser($key);
            if (!$user) {
                $exception = $this->RestResponse->throwException(
                    401,
                    __('This authentication key is not authorized to be used for exports. Contact your administrator.')
                );
                return false;
            }
			$key = 'json';
        } else {
            if (!$this->Auth->user('id')) {
                $exception = $this->RestResponse->throwException(
                    401,
                    __('You have to be logged in to do that.')
                );
                return false;
            }
            $user = $this->Auth->user();
        }
        return $user;
    }

    // generic function to standardise on the collection of parameters. Accepts posted request objects, url params, named url params
    protected function _harvestParameters($options, &$exception)
    {
        $data = array();
        if (!empty($options['request']->is('post'))) {
            if (empty($options['request']->data)) {
                $exception = $this->RestResponse->throwException(
                    400,
                    __('Either specify the search terms in the url, or POST a json with the filter parameters.'),
                    '/' . $this->request->params['controller'] . '/' . $this->action
                );
                return false;
            } else {
                if (isset($options['request']->data['request'])) {
                    $data = $options['request']->data['request'];
                } else {
                    $data = $options['request']->data;
                }
            }
        }
        if (!empty($options['paramArray'])) {
            foreach ($options['paramArray'] as $p) {
                if (
                    isset($options['ordered_url_params'][$p]) &&
                    (!in_array(strtolower($options['ordered_url_params'][$p]), array('null', '0', false, 'false', null)))
                ) {
                    $data[$p] = $options['ordered_url_params'][$p];
                    $data[$p] = str_replace(';', ':', $data[$p]);
                }
                if (isset($options['named_params'][$p])) {
                    $data[$p] = $options['named_params'][$p];
                }
            }
        }
        return $data;
    }

    // pass an action to this method for it to check the active user's access to the action
    public function checkAction($action = 'perm_sync')
    {
        $this->loadModel('Role');
        $this->Role->recursive = -1;
        $role = $this->Role->findById($this->Auth->user('role_id'));
        if ($role['Role'][$action]) {
            return true;
        }
        return false;
    }

    // returns the role of the currently authenticated user as an array, used to set the permission variables for views in the AppController's beforeFilter() method
    public function getActions()
    {
        $this->loadModel('Role');
        $this->Role->recursive = -1;
        $role = $this->Role->findById($this->Auth->user('role_id'));
        return $role['Role'];
    }

    public function checkAuthUser($authkey)
    {
        $this->loadModel('User');
        $user = $this->User->getAuthUserByAuthkey($authkey);
        if (empty($user)) {
            return false;
        }
        if (!$user['Role']['perm_auth']) {
            return false;
        }
        if ($user['Role']['perm_site_admin']) {
            $user['siteadmin'] = true;
        }
        return $user;
    }

    public function checkExternalAuthUser($authkey)
    {
        $this->loadModel('User');
        $user = $this->User->getAuthUserByExternalAuth($authkey);
        if (empty($user)) {
            return false;
        }
        if ($user['Role']['perm_site_admin']) {
            $user['siteadmin'] = true;
        }
        return $user;
    }

    public function generateCount()
    {
        if (!self::_isSiteAdmin() || !$this->request->is('post')) {
            throw new NotFoundException();
        }
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
        $this->Flash->success(__('All done. attribute_count generated from scratch for ' . (isset($k) ? $k : 'no') . ' events.'));
        $this->redirect(array('controller' => 'pages', 'action' => 'display', 'administration'));
    }

    public function pruneDuplicateUUIDs()
    {
        if (!$this->_isSiteAdmin() || !$this->request->is('post')) {
            throw new MethodNotAllowedException();
        }
        $this->loadModel('Attribute');
        $duplicates = $this->Attribute->find('all', array(
            'fields' => array('Attribute.uuid', 'count(*) as occurance'),
            'recursive' => -1,
            'group' => array('Attribute.uuid HAVING COUNT(*) > 1'),
        ));
        $counter = 0;
        foreach ($duplicates as $duplicate) {
            $attributes = $this->Attribute->find('all', array(
                'recursive' => -1,
                'conditions' => array('uuid' => $duplicate['Attribute']['uuid'])
            ));
            foreach ($attributes as $k => $attribute) {
                if ($k > 0) {
                    $this->Attribute->delete($attribute['Attribute']['id']);
                    $counter++;
                }
            }
        }
        $this->Server->updateDatabase('makeAttributeUUIDsUnique');
        $this->Flash->success('Done. Deleted ' . $counter . ' duplicate attribute(s).');
        $this->redirect(array('controller' => 'pages', 'action' => 'display', 'administration'));
    }

    public function removeDuplicateEvents()
    {
        if (!$this->_isSiteAdmin() || !$this->request->is('post')) {
            throw new MethodNotAllowedException();
        }
        $this->loadModel('Event');
        $duplicates = $this->Event->find('all', array(
                'fields' => array('Event.uuid', 'count(*) as occurance'),
                'recursive' => -1,
                'group' => array('Event.uuid HAVING COUNT(*) > 1'),
        ));
        $counter = 0;

        // load this so we can remove the blacklist item that will be created, this is the one case when we do not want it.
        if (Configure::read('MISP.enableEventBlacklisting') !== false) {
            $this->EventBlacklist = ClassRegistry::init('EventBlacklist');
        }

        foreach ($duplicates as $duplicate) {
            $events = $this->Event->find('all', array(
                    'recursive' => -1,
                    'conditions' => array('uuid' => $duplicate['Event']['uuid'])
            ));
            foreach ($events as $k => $event) {
                if ($k > 0) {
                    $uuid = $event['Event']['uuid'];
                    $this->Event->delete($event['Event']['id']);
                    $counter++;
                    // remove the blacklist entry that we just created with the event deletion, if the feature is enabled
                    // We do not want to block the UUID, since we just deleted a copy
                    if (Configure::read('MISP.enableEventBlacklisting') !== false) {
                        $this->EventBlacklist->deleteAll(array('EventBlacklist.event_uuid' => $uuid));
                    }
                }
            }
        }
        $this->Server->updateDatabase('makeEventUUIDsUnique');
        $this->Flash->success('Done. Removed ' . $counter . ' duplicate events.');
        $this->redirect(array('controller' => 'pages', 'action' => 'display', 'administration'));
    }

    public function updateDatabase($command)
    {
        if (!$this->_isSiteAdmin() || !$this->request->is('post')) {
            throw new MethodNotAllowedException();
        }
        $this->loadModel('Server');
        if (is_numeric($command)) {
            $command = intval($command);
        }
        $this->Server->updateDatabase($command);
        $this->Flash->success('Done.');
        $this->redirect(array('controller' => 'pages', 'action' => 'display', 'administration'));
    }

    public function upgrade2324()
    {
        if (!$this->_isSiteAdmin() || !$this->request->is('post')) {
            throw new MethodNotAllowedException();
        }
        $this->loadModel('Server');
        if (!Configure::read('MISP.background_jobs')) {
            $this->Server->upgrade2324($this->Auth->user('id'));
            $this->Flash->success('Done. For more details check the audit logs.');
            $this->redirect(array('controller' => 'pages', 'action' => 'display', 'administration'));
        } else {
            $job = ClassRegistry::init('Job');
            $job->create();
            $data = array(
                    'worker' => 'default',
                    'job_type' => 'upgrade_24',
                    'job_input' => 'Old database',
                    'status' => 0,
                    'retries' => 0,
                    'org_id' => 0,
                    'message' => 'Job created.',
            );
            $job->save($data);
            $jobId = $job->id;
            $process_id = CakeResque::enqueue(
                    'default',
                    'AdminShell',
                    array('jobUpgrade24', $jobId, $this->Auth->user('id')),
                    true
            );
            $job->saveField('process_id', $process_id);
            $this->Flash->success(__('Job queued. You can view the progress if you navigate to the active jobs view (administration -> jobs).'));
            $this->redirect(array('controller' => 'pages', 'action' => 'display', 'administration'));
        }
    }

    private function __preAuthException($message)
    {
        $this->set('debugMode', (Configure::read('debug') > 1) ? 'debugOn' : 'debugOff');
        $this->set('me', array());
        throw new ForbiddenException($message);
    }

    private function __customAuthentication($server)
    {
        $result = false;
        if (Configure::read('Plugin.CustomAuth_enable')) {
            $header = Configure::read('Plugin.CustomAuth_header') ? Configure::read('Plugin.CustomAuth_header') : 'Authorization';
            $authName = Configure::read('Plugin.CustomAuth_name') ? Configure::read('Plugin.CustomAuth_name') : 'External authentication';
            $headerNamespace = Configure::read('Plugin.CustomAuth_use_header_namespace') ? (Configure::read('Plugin.CustomAuth_header_namespace') ? Configure::read('Plugin.CustomAuth_header_namespace') : 'HTTP_') : '';
            if (isset($server[$headerNamespace . $header]) && !empty($server[$headerNamespace . $header])) {
                if (Configure::read('Plugin.CustomAuth_only_allow_source') && Configure::read('Plugin.CustomAuth_only_allow_source') !== $server['REMOTE_ADDR']) {
                    $this->Log = ClassRegistry::init('Log');
                    $this->Log->create();
                    $log = array(
                            'org' => 'SYSTEM',
                            'model' => 'User',
                            'model_id' => 0,
                            'email' => 'SYSTEM',
                            'action' => 'auth_fail',
                            'title' => 'Failed authentication using external key (' . trim($server[$headerNamespace . $header]) . ') - the user has not arrived from the expected address. Instead the request came from: ' . $server['REMOTE_ADDR'],
                            'change' => null,
                    );
                    $this->Log->save($log);
                    $this->__preAuthException($authName . ' authentication failed. Contact your MISP support for additional information at: ' . Configure::read('MISP.contact'));
                }
                $temp = $this->checkExternalAuthUser($server[$headerNamespace . $header]);
                $user['User'] = $temp;
                if ($user['User']) {
                    unset($user['User']['gpgkey']);
                    unset($user['User']['certif_public']);
                    $this->Session->renew();
                    $this->Session->write(AuthComponent::$sessionKey, $user['User']);
                    if (Configure::read('MISP.log_auth')) {
                        $this->Log = ClassRegistry::init('Log');
                        $this->Log->create();
                        $log = array(
                            'org' => $user['User']['Organisation']['name'],
                            'model' => 'User',
                            'model_id' => $user['User']['id'],
                            'email' => $user['User']['email'],
                            'action' => 'auth',
                            'title' => 'Successful authentication using ' . $authName . ' key',
                            'change' => 'HTTP method: ' . $_SERVER['REQUEST_METHOD'] . PHP_EOL . 'Target: ' . $this->here,
                        );
                        $this->Log->save($log);
                    }
                    $result = true;
                } else {
                    // User not authenticated correctly
                    // reset the session information
                    $this->Log = ClassRegistry::init('Log');
                    $this->Log->create();
                    $log = array(
                            'org' => 'SYSTEM',
                            'model' => 'User',
                            'model_id' => 0,
                            'email' => 'SYSTEM',
                            'action' => 'auth_fail',
                            'title' => 'Failed authentication using external key (' . trim($server[$headerNamespace . $header]) . ')',
                            'change' => null,
                    );
                    $this->Log->save($log);
                    if (Configure::read('CustomAuth_required')) {
                        $this->Session->destroy();
                        $this->__preAuthException($authName . ' authentication failed. Contact your MISP support for additional information at: ' . Configure::read('MISP.contact'));
                    }
                }
            }
        }
        return $result;
    }

    public function cleanModelCaches()
    {
        if (!$this->_isSiteAdmin() || !$this->request->is('post')) {
            throw new MethodNotAllowedException();
        }
        $this->loadModel('Server');
        $this->Server->cleanCacheFiles();
        $this->Flash->success('Caches cleared.');
        $this->redirect(array('controller' => 'servers', 'action' => 'serverSettings', 'diagnostics'));
    }
}
