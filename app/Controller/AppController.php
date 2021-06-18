<?php
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
 * @property ACLComponent $ACL
 * @property RestResponseComponent $RestResponse
 * @property CRUDComponent $CRUD
 * @property IndexFilterComponent $IndexFilter
 * @property RateLimitComponent $RateLimit
 */
class AppController extends Controller
{
    public $defaultModel = '';

    public $helpers = array('OrgImg', 'FontAwesome', 'UserName', 'DataPathCollector');

    private $__queryVersion = '130';
    public $pyMispVersion = '2.4.144';
    public $phpmin = '7.2';
    public $phprec = '7.4';
    public $phptoonew = '8.0';
    public $pythonmin = '3.6';
    public $pythonrec = '3.7';
    private $isApiAuthed = false;

    public $baseurl = '';
    public $sql_dump = false;

    public $restResponsePayload = null;

    // Used for _isAutomation(), a check that returns true if the controller & action combo matches an action that is a non-xml and non-json automation method
    // This is used to allow authentication via headers for methods not covered by _isRest() - as that only checks for JSON and XML formats
    public $automationArray = array(
        'events' => array('csv', 'nids', 'hids', 'xml', 'restSearch', 'stix', 'updateGraph', 'downloadOpenIOCEvent'),
        'attributes' => array('text', 'downloadAttachment', 'returnAttributes', 'restSearch', 'rpz', 'bro'),
        'objects' => array('restSearch')
    );

    protected $_legacyParams = array();
    /** @var array */
    public $userRole;

    /** @var User */
    public $User;

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
            'CompressedRequestHandler',
            'RestResponse',
            'Flash',
            'Toolbox',
            'RateLimit',
            'IndexFilter',
            'Deprecation',
            'RestSearch',
            'CRUD'
            //,'DebugKit.Toolbar'
    );

    public function beforeFilter()
    {
        $this->_setupBaseurl();
        $this->Auth->loginRedirect = $this->baseurl . '/users/routeafterlogin';

        $customLogout = Configure::read('Plugin.CustomAuth_custom_logout');
        $this->Auth->logoutRedirect = $customLogout ?: ($this->baseurl . '/users/login');

        $this->__sessionMassage();

        // If server is running behind reverse proxy, PHP will not recognize that user is accessing site by HTTPS connection.
        // By setting `Security.force_https` to `true`, session cookie will be set as Secure and CSP headers will upgrade insecure requests.
        if (Configure::read('Security.force_https')) {
            $_SERVER['HTTPS'] = 'on';
        }
        $this->__cors();
        if (Configure::read('Security.check_sec_fetch_site_header')) {
            $secFetchSite = $this->request->header('Sec-Fetch-Site');
            if ($secFetchSite !== false && $secFetchSite !== 'same-origin' && ($this->request->is('post') || $this->request->is('put') || $this->request->is('ajax'))) {
                throw new MethodNotAllowedException("POST, PUT and AJAX requests are allowed just from same origin.");
            }
        }
        if (Configure::read('Security.disable_browser_cache')) {
            $this->response->disableCache();
        }
        if (!$this->_isRest()) {
            $this->__contentSecurityPolicy();
            $this->response->header('X-XSS-Protection', '1; mode=block');
        }

        if (!empty($this->params['named']['sql'])) {
            $this->sql_dump = intval($this->params['named']['sql']);
        }

        $this->_setupDebugMode();
        $this->_setupDatabaseConnection();

        $this->set('ajax', $this->request->is('ajax'));
        $this->set('queryVersion', $this->__queryVersion);
        $this->User = ClassRegistry::init('User');

        $language = Configure::read('MISP.language');
        if (!empty($language) && $language !== 'eng') {
            Configure::write('Config.language', $language);
        } else {
            Configure::write('Config.language', 'eng');
        }

        // For fresh installation (salt empty) generate a new salt
        if (!Configure::read('Security.salt')) {
            $this->loadModel('Server');
            $this->Server->serverSettingsSaveValue('Security.salt', $this->User->generateRandomPassword(32));
        }

        // Check if the instance has a UUID, if not assign one.
        if (!Configure::read('MISP.uuid')) {
            $this->loadModel('Server');
            $this->Server->serverSettingsSaveValue('MISP.uuid', CakeText::uuid());
        }

        // Check if Apache provides kerberos authentication data
        $authUserFields = $this->User->describeAuthFields();
        $envvar = Configure::read('ApacheSecureAuth.apacheEnv');
        if ($envvar && isset($_SERVER[$envvar])) {
            $this->Auth->className = 'ApacheSecureAuth';
            $this->Auth->authenticate = array(
                'Apache' => array(
                    // envvar = field returned by Apache if user is authenticated
                    'fields' => array('username' => 'email', 'envvar' => $envvar),
                    'userFields' => $authUserFields,
                )
            );
        } else {
            $this->Auth->authenticate[AuthComponent::ALL]['userFields'] = $authUserFields;
        }
        if (!empty($this->params['named']['disable_background_processing'])) {
            Configure::write('MISP.background_jobs', 0);
        }
        Configure::write('CurrentController', $this->params['controller']);
        Configure::write('CurrentAction', $this->params['action']);
        $versionArray = $this->User->checkMISPVersion();
        $this->mispVersion = implode('.', array_values($versionArray));
        $this->Security->blackHoleCallback = 'blackHole';

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
            $jsonDecode = function ($dataToDecode) {
                if (empty($dataToDecode)) {
                    return null;
                }
                try {
                    if (defined('JSON_THROW_ON_ERROR')) {
                        // JSON_THROW_ON_ERROR is supported since PHP 7.3
                        return json_decode($dataToDecode, true, 512, JSON_THROW_ON_ERROR);
                    } else {
                        $decoded = json_decode($dataToDecode, true);
                        if ($decoded === null) {
                            throw new UnexpectedValueException('Could not parse JSON: ' . json_last_error_msg(), json_last_error());
                        }
                        return $decoded;
                    }
                } catch (Exception $e) {
                    throw new HttpException('Invalid JSON input. Make sure that the JSON input is a correctly formatted JSON string. This request has been blocked to avoid an unfiltered request.', 405, $e);
                }
            };
            //  Throw exception if JSON in request is invalid. Default CakePHP behaviour would just ignore that error.
            $this->RequestHandler->addInputType('json', [$jsonDecode]);
            $this->Security->unlockedActions = array($this->action);
        }

        if (
            !$userLoggedIn &&
            (
                $this->params['controller'] !== 'users' ||
                $this->params['action'] !== 'register' ||
                empty(Configure::read('Security.allow_self_registration'))
            )
        ) {
            // REST authentication
            if ($this->_isRest() || $this->_isAutomation()) {
                // disable CSRF for REST access
                if (isset($this->components['Security'])) {
                    $this->Security->csrfCheck = false;
                }
                if ($this->__loginByAuthKey() === false || $this->Auth->user() === null) {
                    if ($this->__loginByAuthKey() === null) {
                        $this->loadModel('Log');
                        $this->Log->createLogEntry('SYSTEM', 'auth_fail', 'User', 0, "Failed API authentication. No authkey was provided.");
                    }
                    throw new ForbiddenException('Authentication failed. Please make sure you pass the API key of an API enabled user along in the Authorization header.');
                }
            } elseif (!$this->Session->read(AuthComponent::$sessionKey)) {
                $this->_loadAuthenticationPlugins();
            }
        }

        $user = $this->Auth->user();
        if ($user) {
            Configure::write('CurrentUserId', $user['id']);
            $this->__logAccess($user);

            // Try to run updates
            if ($user['Role']['perm_site_admin'] || (Configure::read('MISP.live') && !$this->_isRest())) {
                $this->User->runUpdates();
            }

            // Put username to response header for webserver or proxy logging
            if (Configure::read('Security.username_in_response_header')) {
                $headerValue = $user['email'];
                if (isset($user['logged_by_authkey']) && $user['logged_by_authkey']) {
                    $headerValue .= isset($user['authkey_id']) ? "/API/{$user['authkey_id']}" :  '/API/default';
                }
                $this->response->header('X-Username', $headerValue);
                $this->RestResponse->setHeader('X-Username', $headerValue);
            }

            if (!$this->__verifyUser($user))  {
                $this->_stop(); // just for sure
            }

            if (isset($user['logged_by_authkey']) && $user['logged_by_authkey'] && !($this->_isRest() || $this->_isAutomation())) {
                throw new ForbiddenException("When user is authenticated by authkey, just REST request can be processed");
            }

            // Put token expiration time to response header that can be processed by automation tool
            if (isset($user['authkey_expiration']) && $user['authkey_expiration']) {
                $expiration = date('c', $user['authkey_expiration']);
                $this->response->header('X-Auth-Key-Expiration', $expiration);
                $this->RestResponse->setHeader('X-Auth-Key-Expiration', $expiration);
            }

            $this->set('default_memory_limit', ini_get('memory_limit'));
            if (isset($user['Role']['memory_limit']) && $user['Role']['memory_limit'] !== '') {
                 ini_set('memory_limit', $user['Role']['memory_limit']);
            }
            $this->set('default_max_execution_time', ini_get('max_execution_time'));
            if (isset($user['Role']['max_execution_time']) && $user['Role']['max_execution_time'] !== '') {
                ini_set('max_execution_time', $user['Role']['max_execution_time']);
            }

            $this->set('mispVersion', "{$versionArray['major']}.{$versionArray['minor']}.0");
            $this->set('mispVersionFull', $this->mispVersion);
            $this->set('me', $user);
            $role = $user['Role'];
            $this->set('isAdmin', $role['perm_admin']);
            $this->set('isSiteAdmin', $role['perm_site_admin']);
            $this->set('hostOrgUser', $user['org_id'] == Configure::read('MISP.host_org_id'));
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
            $this->set('isAclGalaxyEditor', !empty($role['perm_galaxy_editor']));
            $this->set('isAclSharingGroup', $role['perm_sharing_group']);
            $this->set('isAclSighting', isset($role['perm_sighting']) ? $role['perm_sighting'] : false);
            $this->set('isAclZmq', isset($role['perm_publish_zmq']) ? $role['perm_publish_zmq'] : false);
            $this->set('isAclKafka', isset($role['perm_publish_kafka']) ? $role['perm_publish_kafka'] : false);
            $this->set('isAclDecaying', isset($role['perm_decaying']) ? $role['perm_decaying'] : false);
            $this->set('aclComponent', $this->ACL);
            $this->userRole = $role;

            $this->set('loggedInUserName', $this->__convertEmailToName($user['email']));
            $this->__accessMonitor($user);

        } else {
            $preAuthActions = array('login', 'register', 'getGpgPublicKey');
            if (!empty(Configure::read('Security.email_otp_enabled'))) {
                $preAuthActions[] = 'email_otp';
            }
            if (!$this->_isControllerAction(['users' => $preAuthActions, 'servers' => ['cspReport']])) {
                if (!$this->request->is('ajax')) {
                    $this->Session->write('pre_login_requested_url', $this->here);
                }
                $this->_redirectToLogin();
            }

            $this->set('me', false);
        }

        if ($this->Auth->user() && $this->_isSiteAdmin()) {
            if (Configure::read('Session.defaults') === 'database') {
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

        $this->ACL->checkAccess($this->Auth->user(), Inflector::variable($this->request->params['controller']), $this->action);
        if ($this->_isRest()) {
            $this->__rateLimitCheck();
        }
        if ($this->modelClass !== 'CakeError') {
            $deprecationWarnings = $this->Deprecation->checkDeprecation($this->request->params['controller'], $this->action, $this->{$this->modelClass}, $this->Auth->user('id'));
            if ($deprecationWarnings) {
                $deprecationWarnings = __('WARNING: This functionality is deprecated and will be removed in the near future. ') . $deprecationWarnings;
                if ($this->_isRest()) {
                    $this->response->header('X-Deprecation-Warning', $deprecationWarnings);
                    $this->components['RestResponse']['deprecationWarnings'] = $deprecationWarnings;
                } else {
                    $this->Flash->warning($deprecationWarnings);
                }
            }
        }

        // Notifications and homepage is not necessary for AJAX or REST requests
        if ($this->Auth->user() && !$this->_isRest() && !$this->request->is('ajax')) {
            if ($this->request->params['controller'] === 'users' && $this->request->params['action'] === 'dashboard') {
                $notifications = $this->User->populateNotifications($this->Auth->user());
            } else {
                $notifications = $this->User->populateNotifications($this->Auth->user(), 'fast');
            }
            $this->set('notifications', $notifications);

            $homepage = $this->User->UserSetting->getValueForUser($this->Auth->user('id'), 'homepage');
            if (!empty($homepage)) {
                $this->set('homepage', $homepage);
            }
            if (version_compare(phpversion(), '8.0') >= 0) {
                $this->Flash->error(__('WARNING: MISP is currently running under PHP 8.0, which is unsupported. Background jobs will fail, so please contact your administrator to run a supported PHP version (such as 7.4)'));
            }
        }
    }

    /**
     * @return null|bool True if authkey was correct, False if incorrect and Null if not provided
     * @throws Exception
     */
    private function __loginByAuthKey()
    {
        if (Configure::read('Security.authkey_keep_session') && $this->Auth->user()) {
            // Do not check authkey if session is establish and correct, just close session to allow multiple requests
            session_write_close();
            return true;
        }

        // If enabled, allow passing the API key via a named parameter (for crappy legacy systems only)
        $namedParamAuthkey = false;
        if (Configure::read('Security.allow_unsafe_apikey_named_param') && !empty($this->params['named']['apikey'])) {
            $namedParamAuthkey = $this->params['named']['apikey'];
        }
        // Authenticate user with authkey in Authorization HTTP header
        if (!empty($_SERVER['HTTP_AUTHORIZATION']) || !empty($namedParamAuthkey)) {
            $foundMispAuthKey = false;
            $authentication = explode(',', $_SERVER['HTTP_AUTHORIZATION']);
            if (!empty($namedParamAuthkey)) {
                $authentication[] = $namedParamAuthkey;
            }
            $user = false;
            foreach ($authentication as $authKey) {
                $authKey = trim($authKey);
                if (preg_match('/^[a-zA-Z0-9]{40}$/', $authKey)) {
                    $foundMispAuthKey = true;
                    $temp = $this->checkAuthUser($authKey);
                    if ($temp) {
                        $user = $temp;
                        break;
                    }
                }
            }
            if ($foundMispAuthKey) {
                $authKeyToStore = substr($authKey, 0, 4)
                    . str_repeat('*', 32)
                    . substr($authKey, -4);
                if ($user) {
                    unset($user['gpgkey']);
                    unset($user['certif_public']);
                    // User found in the db, add the user info to the session
                    if (Configure::read('MISP.log_auth')) {
                        $this->loadModel('Log');
                        $this->Log->create();
                        $log = array(
                            'org' => $user['Organisation']['name'],
                            'model' => 'User',
                            'model_id' => $user['id'],
                            'email' => $user['email'],
                            'action' => 'auth',
                            'title' => "Successful authentication using API key ($authKeyToStore)",
                            'change' => 'HTTP method: ' . $_SERVER['REQUEST_METHOD'] . PHP_EOL . 'Target: ' . $this->here,
                        );
                        $this->Log->save($log);
                    }
                    $this->Session->renew();
                    $this->Session->write(AuthComponent::$sessionKey, $user);
                    $this->isApiAuthed = true;
                    return true;
                } else {
                    // User not authenticated correctly
                    // reset the session information
                    if ($this->_shouldLog($authKeyToStore)) {
                        $this->loadModel('Log');
                        $this->Log->createLogEntry('SYSTEM', 'auth_fail', 'User', 0, "Failed authentication using API key ($authKeyToStore)");
                    }
                    $this->Session->destroy();
                }
            }
            return false;
        }
        return null;
    }

    /**
     * Check if:
     *  - user exists in database
     *  - is not disabled
     *  - need to force logout
     *  - accepted terms and conditions
     *  - must change password
     *  - reads latest news
     *
     * @param array $user
     * @return bool
     */
    private function __verifyUser(array $user)
    {
        // Skip these checks for 'checkIfLoggedIn' action to make that call fast
        if ($this->_isControllerAction(['users' => ['checkIfLoggedIn']])) {
            return true;
        }

        // Load last user profile modification from database
        $userFromDb = $this->User->find('first', [
            'conditions' => ['id' => $user['id']],
            'recursive' =>  -1,
            'fields' => ['date_modified'],
        ]);

        // Check if user with given ID exists
        if (!$userFromDb) {
            $message = __('Something went wrong. Your user account that you are authenticated with doesn\'t exist anymore.');
            if ($this->_isRest()) {
                // TODO: Why not exception?
                $response = $this->RestResponse->throwException(401, $message);
                $response->send();
                $this->_stop();
            } else {
                $this->Flash->info($message);
                $this->Auth->logout();
                $this->_redirectToLogin();
            }
            return false;
        }

        // Check if session data contain latest changes from db
        if ((int)$user['date_modified'] < (int)$userFromDb['User']['date_modified']) {
            $user = $this->_refreshAuth(); // session data are old, reload from database
        }

        // Check if MISP access is enabled
        if (!Configure::read('MISP.live')) {
            if (!$user['Role']['perm_site_admin']) {
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
                $this->Flash->error(__('Warning: MISP is currently disabled for all users. Enable it in Server Settings (Administration -> Server Settings -> MISP tab -> live). An update might also be in progress, you can see the progress in ') , array('params' => array('url' => $this->baseurl . '/servers/updateProgress/', 'urlName' => __('Update Progress')), 'clear' => 1));
            }
        }

        // Force logout doesn't make sense for API key authentication
        if (!$this->isApiAuthed && $user['force_logout']) {
            $this->User->id = $user['id'];
            $this->User->saveField('force_logout', false);
            $this->Auth->logout();
            $this->_redirectToLogin();
            return false;
        }

        if ($user['disabled']) {
            if ($this->_shouldLog('disabled:' . $user['id'])) {
                $this->Log = ClassRegistry::init('Log');
                $this->Log->createLogEntry($user, 'auth_fail', 'User', $user['id'], 'Login attempt by disabled user.');
            }

            $this->Auth->logout();
            if ($this->_isRest()) {
                throw new ForbiddenException('Authentication failed. Your user account has been disabled.');
            } else {
                $this->Flash->error(__('Your user account has been disabled.'));
                $this->_redirectToLogin();
            }
            return false;
        }

        // Check if auth key is not expired. Make sense when Security.authkey_keep_session is enabled.
        if (isset($user['authkey_expiration']) && $user['authkey_expiration']) {
            $time = isset($_SERVER['REQUEST_TIME']) ? $_SERVER['REQUEST_TIME'] : time();
            if ($user['authkey_expiration'] < $time) {
                if ($this->_shouldLog('expired:' . $user['authkey_id'])) {
                    $this->Log = ClassRegistry::init('Log');
                    $this->Log->createLogEntry($user, 'auth_fail', 'User', $user['id'], "Login attempt by expired auth key {$user['authkey_id']}.");
                }
                $this->Auth->logout();
                throw new ForbiddenException('Auth key is expired');
            }
        }

        if (!empty($user['allowed_ips'])) {
            App::uses('CidrTool', 'Tools');
            $cidrTool = new CidrTool($user['allowed_ips']);
            $remoteIp = $this->_remoteIp();
            if ($remoteIp === null) {
                $this->Auth->logout();
                throw new ForbiddenException('Auth key is limited to IP address, but IP address not found');
            }
            if (!$cidrTool->contains($remoteIp)) {
                if ($this->_shouldLog('not_allowed_ip:' . $user['authkey_id'] . ':' . $remoteIp)) {
                    $this->Log = ClassRegistry::init('Log');
                    $this->Log->createLogEntry($user, 'auth_fail', 'User', $user['id'], "Login attempt from not allowed IP address for auth key {$user['authkey_id']}.");
                }
                $this->Auth->logout();
                throw new ForbiddenException('It is not possible to use this Auth key from your IP address');
            }
        }

        $isUserRequest = !$this->_isRest() && !$this->request->is('ajax') && !$this->_isAutomation();
        // Next checks makes sense just for user direct HTTP request, so skip REST and AJAX calls
        if (!$isUserRequest) {
            return true;
        }

        // Check if user accepted terms and conditions
        if (!$user['termsaccepted'] && !empty(Configure::read('MISP.terms_file')) && !$this->_isControllerAction(['users' => ['terms', 'logout', 'login', 'downloadTerms']])) {
            //if ($this->_isRest()) throw new MethodNotAllowedException('You have not accepted the terms of use yet, please log in via the web interface and accept them.');
            $this->redirect(array('controller' => 'users', 'action' => 'terms', 'admin' => false));
            return false;
        }

        // Check if user must change password
        if ($user['change_pw'] && !$this->_isControllerAction(['users' => ['terms', 'change_pw', 'logout', 'login']])) {
            //if ($this->_isRest()) throw new MethodNotAllowedException('Your user account is expecting a password change, please log in via the web interface and change it before proceeding.');
            $this->redirect(array('controller' => 'users', 'action' => 'change_pw', 'admin' => false));
            return false;
        }

        // Check if user must read news
        if (!$this->_isControllerAction(['news' => ['index'], 'users' => ['terms', 'change_pw', 'login', 'logout']])) {
            $this->loadModel('News');
            $latestNewsCreated = $this->News->field('date_created', array(), 'date_created DESC');
            if ($latestNewsCreated && $user['newsread'] < $latestNewsCreated) {
                $this->redirect(array('controller' => 'news', 'action' => 'index', 'admin' => false));
                return false;
            }
        }

        return true;
    }

    /**
     * @param array $actionsToCheck
     * @return bool
     */
    private function _isControllerAction($actionsToCheck = [])
    {
        $controller = Inflector::variable($this->request->params['controller']);
        if (!isset($actionsToCheck[$controller])) {
            return false;
        }
        return in_array($this->action, $actionsToCheck[$controller], true);
    }

    /**
     * User access monitoring
     * @param array $user
     */
    private function __logAccess(array $user)
    {
        $logUserIps = Configure::read('MISP.log_user_ips');
        if (!$logUserIps)  {
            return;
        }

        $redis = $this->User->setupRedis();
        if (!$redis) {
            return;
        }

        $remoteAddress = $this->_remoteIp();

        $pipe = $redis->multi(Redis::PIPELINE);
        // keep for 30 days
        $pipe->setex('misp:ip_user:' . $remoteAddress, 60 * 60 * 24 * 30, $user['id']);
        $pipe->sadd('misp:user_ip:' . $user['id'], $remoteAddress);

        // Log key usage if enabled
        if (isset($user['authkey_id']) && Configure::read('MISP.log_user_ips_authkeys')) {
            // Use request time if defined
            $time = isset($_SERVER['REQUEST_TIME']) ? $_SERVER['REQUEST_TIME'] : time();
            $hashKey = date("Y-m-d", $time) . ":$remoteAddress";
            $pipe->hIncrBy("misp:authkey_usage:{$user['authkey_id']}", $hashKey, 1);
            // delete after one year of inactivity
            $pipe->expire("misp:authkey_usage:{$user['authkey_id']}", 3600 * 24 * 365);
            $pipe->set("misp:authkey_last_usage:{$user['authkey_id']}", $time);
        }
        $pipe->exec();
    }

    /**
     * @param array $user
     * @throws Exception
     */
    private function __accessMonitor(array $user)
    {
        $userMonitoringEnabled = Configure::read('Security.user_monitoring_enabled');
        if ($userMonitoringEnabled) {
            $redis = $this->User->setupRedis();
            $userMonitoringEnabled = $redis && $redis->sismember('misp:monitored_users', $user['id']);
        }

        if (Configure::read('MISP.log_paranoid') || $userMonitoringEnabled) {
            $change = 'HTTP method: ' . $_SERVER['REQUEST_METHOD'] . PHP_EOL . 'Target: ' . $this->here;
            if (
                (
                    $this->request->is('post') ||
                    $this->request->is('put')
                ) &&
                (
                    !empty(Configure::read('MISP.log_paranoid_include_post_body')) ||
                    $userMonitoringEnabled
                )
            ) {
                $payload = $this->request->input();
                $change .= PHP_EOL . 'Request body: ' . $payload;
            }
            $this->Log = ClassRegistry::init('Log');
            $this->Log->createLogEntry($user, 'request', 'User', $user['id'], 'Paranoid log entry', $change);
        }
    }

    /**
     * Generate Content-Security-Policy HTTP header
     */
    private function __contentSecurityPolicy()
    {
        $default = [
            'default-src' => "'self' data: 'unsafe-inline' 'unsafe-eval'",
            'style-src' => "'self' 'unsafe-inline'",
            'object-src' => "'none'",
            'frame-ancestors' => "'none'",
            'worker-src' => "'none'",
            'child-src' => "'none'",
            'frame-src' => "'none'",
            'base-uri' => "'self'",
            'img-src' => "'self' data:",
            'font-src' => "'self'",
            'form-action' => "'self'",
            'connect-src' => "'self'",
            'manifest-src' => "'none'",
            'report-uri' => '/servers/cspReport',
        ];
        if (env('HTTPS')) {
            $default['upgrade-insecure-requests'] = null;
        }
        $custom = Configure::read('Security.csp');
        if ($custom === false) {
            return;
        }
        if (is_array($custom)) {
            $default = $custom + $default;
        }
        $header = [];
        foreach ($default as $key => $value) {
            if ($value !== false) {
                if ($value === null) {
                    $header[] = $key;
                } else {
                    $header[] = "$key $value";
                }
            }
        }
        $headerName = Configure::read('Security.csp_enforce') ? 'Content-Security-Policy' : 'Content-Security-Policy-Report-Only';
        $this->response->header($headerName, implode('; ', $header));
    }

    private function __cors()
    {
        if (Configure::read('Security.allow_cors')) {
            // Add CORS headers
            $this->response->cors($this->request,
                explode(',', Configure::read('Security.cors_origins')),
                ['*'],
                ['Origin', 'Content-Type', 'Authorization', 'Accept']);

            if ($this->request->is('options')) {
                // Stop here!
                // CORS only needs the headers
                $this->response->send();
                $this->_stop();
            }
        }
    }

    private function __rateLimitCheck()
    {
        $info = array();
        $rateLimitCheck = $this->RateLimit->check(
            $this->Auth->user(),
            $this->request->params['controller'],
            $this->action,
            $this->{$this->modelClass},
            $info,
            $this->response->type()
        );
        if (!empty($info)) {
            $this->RestResponse->setHeader('X-Rate-Limit-Limit', $info['limit']);
            $this->RestResponse->setHeader('X-Rate-Limit-Remaining', $info['remaining']);
            $this->RestResponse->setHeader('X-Rate-Limit-Reset', $info['reset']);
        }
        if ($rateLimitCheck !== true) {
            $this->response->header('X-Rate-Limit-Limit', $info['limit']);
            $this->response->header('X-Rate-Limit-Remaining', $info['remaining']);
            $this->response->header('X-Rate-Limit-Reset', $info['reset']);
            $this->response->body($rateLimitCheck);
            $this->response->statusCode(429);
            $this->response->send();
            $this->_stop();
        }
        return true;
    }

    public function afterFilter()
    {
        if ($this->isApiAuthed && $this->_isRest() && !Configure::read('Security.authkey_keep_session')) {
            $this->Session->destroy();
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

    /*
     * Configure the debugMode view parameter
     */
    protected function _setupDebugMode() {
        $this->set('debugMode', (Configure::read('debug') >= 1) ? 'debugOn' : 'debugOff');
    }

    /*
     * Setup & validate the database connection configuration
     * @throws Exception if the configured database is not supported.
     */
    protected function _setupDatabaseConnection() {
        // check for a supported datasource configuration
        $dataSourceConfig = ConnectionManager::getDataSource('default')->config;
        if (!isset($dataSourceConfig['encoding'])) {
            $db = ConnectionManager::getDataSource('default');
            $db->setConfig(array('encoding' => 'utf8'));
            ConnectionManager::create('default', $db->config);
        }
        $dataSource = $dataSourceConfig['datasource'];
        if (!in_array($dataSource, array('Database/Mysql', 'Database/Postgres', 'Database/MysqlObserver'))) {
            throw new Exception('datasource not supported: ' . $dataSource);
        }
    }

    /*
     * Sanitize the configured `MISP.baseurl` and expose it to the view as `baseurl`.
     */
    protected function _setupBaseurl()
    {
        // Let us access $baseurl from all views
        $baseurl = Configure::read('MISP.baseurl');
        if (substr($baseurl, -1) === '/') {
            // if the baseurl has a trailing slash, remove it. It can lead to issues with the CSRF protection
            $baseurl = rtrim($baseurl, '/');
            $this->loadModel('Server');
            $this->Server->serverSettingsSaveValue('MISP.baseurl', $baseurl);
        }
        if (trim($baseurl) === 'http://') {
            $this->Server->serverSettingsSaveValue('MISP.baseurl', '');
        }
        $this->baseurl = $baseurl;
        $this->set('baseurl', h($baseurl));
    }

    private function __convertEmailToName($email)
    {
        $name = explode('@', (string)$email);
        $name = explode('.', $name[0]);
        foreach ($name as $key => $value) {
            $name[$key] = ucfirst($value);
        }
        $name = implode(' ', $name);
        return $name;
    }

    public function blackhole($type=false)
    {
        if ($type === 'csrf') {
            throw new BadRequestException($type);
        }
        throw new BadRequestException('The request has been black-holed');
    }

    protected function _isRest()
    {
        return $this->IndexFilter->isRest();
    }

    protected function _isAutomation()
    {
        return $this->IndexFilter->isApiFunction($this->params['controller'], $this->params['action']);
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
    protected function _harvestParameters($options, &$exception, $data = array())
    {
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
                    $data = array_merge($data, $options['request']->data['request']);
                } else {
                    $data = array_merge($data, $options['request']->data);
                }
            }
        }
        /*
         * If we simply capture ordered URL params with func_get_args(), reassociate them.
         * We can easily detect this by having ordered_url_params passed as a list instead of a dict.
         */
        if (isset($options['ordered_url_params'][0])) {
            $temp = array();
            foreach ($options['ordered_url_params'] as $k => $url_param) {
                if (!empty($options['paramArray'][$k])) {
                    $temp[$options['paramArray'][$k]] = $url_param;
                }
            }
            $options['ordered_url_params'] = $temp;
        }
        if (!empty($options['paramArray'])) {
            foreach ($options['paramArray'] as $p) {
                if (
                    isset($options['ordered_url_params'][$p]) &&
                    (!in_array(strtolower((string)$options['ordered_url_params'][$p]), array('null', '0', false, 'false', null)))
                ) {
                    $data[$p] = $options['ordered_url_params'][$p];
                    $data[$p] = str_replace(';', ':', $data[$p]);
                }
                if (isset($options['named_params'][$p])) {
                    $data[$p] = str_replace(';', ':', $options['named_params'][$p]);
                }
            }
        }
        foreach ($data as $k => $v) {
            if (!is_array($data[$k])) {
                $data[$k] = trim($data[$k]);
                if (strpos($data[$k], '||')) {
                    $data[$k] = explode('||', $data[$k]);
                }
            }
        }
        if (!empty($options['additional_delimiters'])) {
            if (!is_array($options['additional_delimiters'])) {
                $options['additional_delimiters'] = array($options['additional_delimiters']);
            }
            foreach ($data as $k => $v) {
                $found = false;
                foreach ($options['additional_delimiters'] as $delim) {
                    if (strpos($v, $delim) !== false) {
                        $found = true;
                    }
                }
                if ($found) {
                    $data[$k] = explode($options['additional_delimiters'][0], str_replace($options['additional_delimiters'], $options['additional_delimiters'][0], $v));
                    foreach ($data[$k] as $k2 => $value) {
                        $data[$k][$k2] = trim($data[$k][$k2]);
                    }
                }
            }
        }
        return $data;
    }

    public function checkAuthUser($authkey)
    {
        if (Configure::read('Security.advanced_authkeys')) {
            $this->loadModel('AuthKey');
            $user = $this->AuthKey->getAuthUserByAuthKey($authkey);
        } else {
            $user = $this->User->getAuthUserByAuthKey($authkey);
        }

        if (empty($user)) {
            return false;
        }
        if (!$user['Role']['perm_auth']) {
            return false;
        }
        $user['logged_by_authkey'] = true;
        return $user;
    }

    public function checkExternalAuthUser($authkey)
    {
        $user = $this->User->getAuthUserByExternalAuth($authkey);
        if (empty($user)) {
            return false;
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

        // load this so we can remove the blocklist item that will be created, this is the one case when we do not want it.
        if (Configure::read('MISP.enableEventBlocklisting') !== false) {
            $this->EventBlocklist = ClassRegistry::init('EventBlocklist');
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
                    // remove the blocklist entry that we just created with the event deletion, if the feature is enabled
                    // We do not want to block the UUID, since we just deleted a copy
                    if (Configure::read('MISP.enableEventBlocklisting') !== false) {
                        $this->EventBlocklist->deleteAll(array('EventBlocklist.event_uuid' => $uuid));
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
        if ($liveOff) {
            $this->redirect(array('controller' => 'servers', 'action' => 'updateProgress'));
        } else {
            $this->redirect(array('controller' => 'pages', 'action' => 'display', 'administration'));
        }
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
        $this->set('me', array());
        throw new ForbiddenException($message);
    }

    private function __customAuthentication($server)
    {
        $result = false;
        if (Configure::read('Plugin.CustomAuth_enable')) {
            $header = Configure::read('Plugin.CustomAuth_header') ? Configure::read('Plugin.CustomAuth_header') : 'Authorization';
            $authName = Configure::read('Plugin.CustomAuth_name') ? Configure::read('Plugin.CustomAuth_name') : 'External authentication';
            if (
                !Configure::check('Plugin.CustomAuth_use_header_namespace') ||
                (Configure::check('Plugin.CustomAuth_use_header_namespace') && Configure::read('Plugin.CustomAuth_use_header_namespace'))
            ) {
                if (Configure::check('Plugin.CustomAuth_header_namespace')) {
                    $headerNamespace = Configure::read('Plugin.CustomAuth_header_namespace');
                } else {
                    $headerNamespace = 'HTTP_';
                }
            } else {
                $headerNamespace = '';
            }
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
                    $this->User->updateLoginTimes($user['User']);
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

    private function __sessionMassage()
    {
        if (empty(Configure::read('Session.cookie')) && !empty(Configure::read('MISP.uuid'))) {
            Configure::write('Session.cookie', 'MISP-' . Configure::read('MISP.uuid'));
        }
        if (!empty(Configure::read('Session.cookieTimeout')) || !empty(Configure::read('Session.timeout'))) {
            $session = Configure::read('Session');
            if (!empty($session['cookieTimeout'])) {
                $value = 60 * intval($session['cookieTimeout']);
            } else if (!empty($session['timeout'])) {
                $value = 60 * intval($session['timeout']);
            } else {
                $value = 3600;
            }
            $session['ini']['session.gc_maxlifetime'] = $value;
            Configure::write('Session', $session);
        }
    }

    private function _redirectToLogin() {
        $targetRoute = $this->Auth->loginAction;
        $targetRoute['admin'] = false;
        $this->redirect($targetRoute);
    }

    /**
     * @throws Exception
     */
    protected function _loadAuthenticationPlugins()
    {
        // load authentication plugins from Configure::read('Security.auth')
        $auth = Configure::read('Security.auth');
        if (!$auth) {
            return;
        }
        if (!is_array($auth)) {
            throw new Exception("`Security.auth` config value must be array.");
        }
        $this->Auth->authenticate = array_merge($auth, $this->Auth->authenticate);
        // Disable Form authentication
        if (Configure::read('Security.auth_enforced')) {
            unset($this->Auth->authenticate['Form']);
        }
        if ($this->Auth->startup($this)) {
            $user = $this->Auth->user();
            if ($user) {
                $this->User->updateLoginTimes($user);
                // User found in the db, add the user info to the session
                $this->Session->renew();
                $this->Session->write(AuthComponent::$sessionKey, $user);
            }
        }
    }

    protected function _legacyAPIRemap($options = array())
    {
        $ordered_url_params = array();
        foreach ($options['paramArray'] as $k => $param) {
            if (isset($options['ordered_url_params'][$k])) {
                $ordered_url_params[$param] = $options['ordered_url_params'][$k];
            } else {
                $ordered_url_params[$param] = false;
            }
        }
        $filterData = array(
            'request' => $options['request'],
            'named_params' => $options['named_params'],
            'paramArray' => $options['paramArray'],
            'ordered_url_params' => $ordered_url_params
        );
        $exception = false;
        $filters = $this->_harvestParameters($filterData, $exception);
        if (!empty($options['injectedParams'])) {
            foreach ($options['injectedParams'] as $injectedParam => $injectedValue) {
                $filters[$injectedParam] = $injectedValue;
            }
        }
        if (!empty($options['alias'])) {
            foreach ($options['alias'] as $from => $to) {
                if (!empty($filters[$from])) {
                    $filters[$to] = $filters[$from];
                }
            }
        }
        $this->_legacyParams = $filters;
        return true;
    }

    public function restSearch()
    {
        $scope = empty($this->scopeOverride) ? $this->modelClass : $this->scopeOverride;
        if ($scope === 'MispObject') {
            $scope = 'Object';
        }
        if (empty($this->RestSearch->paramArray[$scope])) {
            throw new NotFoundException(__('RestSearch is not implemented (yet) for this scope.'));
        }
        if (!isset($this->$scope)) {
            $this->loadModel($scope);
        }
        $filterData = array(
            'request' => $this->request,
            'named_params' => $this->params['named'],
            'paramArray' => $this->RestSearch->paramArray[$scope],
            'ordered_url_params' => func_get_args()
        );
        $exception = false;
        $filters = $this->_harvestParameters($filterData, $exception, $this->_legacyParams);
        if (empty($filters) && $this->request->is('get')) {
            throw new InvalidArgumentException(__('Restsearch queries using GET and no parameters are not allowed. If you have passed parameters via a JSON body, make sure you use POST requests.'));
        }
        if (empty($filters['returnFormat'])) {
            $filters['returnFormat'] = 'json';
        }
        unset($filterData);
        if ($filters === false) {
            return $exception;
        }
        $key = empty($filters['key']) ? $filters['returnFormat'] : $filters['key'];
        $user = $this->_getApiAuthUser($key, $exception);
        if ($user === false) {
            return $exception;
        }
        if (isset($filters['returnFormat'])) {
            $returnFormat = $filters['returnFormat'];
        } else {
            $returnFormat = 'json';
        }
        if ($returnFormat === 'download') {
            $returnFormat = 'json';
        }
        if ($returnFormat === 'stix' && $this->IndexFilter->isJson()) {
            $returnFormat = 'stix-json';
        }
        $elementCounter = 0;
        $renderView = false;
        $responseType = empty($this->$scope->validFormats[$returnFormat][0]) ? 'json' : $this->$scope->validFormats[$returnFormat][0];
        // halt execution if we were to query for items above the ID. Blocks the endless caching bug
        if (!empty($filters['page']) && !empty($filters['returnFormat']) && $filters['returnFormat'] === 'cache') {
            if ($this->__cachingOverflow($filters, $scope)) {
                $filename = $this->RestSearch->getFilename($filters, $scope, $responseType);
                return $this->RestResponse->viewData('', $responseType, false, true, $filename, [
                    'X-Result-Count' => 0,
                    'X-Export-Module-Used' => $returnFormat,
                    'X-Response-Format' => $responseType
                ]);
            }
        }
        $final = $this->$scope->restSearch($user, $returnFormat, $filters, false, false, $elementCounter, $renderView);
        if (!empty($renderView) && !empty($final)) {
            $this->layout = false;
            $final = json_decode($final->intoString(), true);
            foreach ($final as $key => $data) {
                $this->set($key, $data);
            }
            $this->render('/Events/module_views/' . $renderView);
        } else {
            $filename = $this->RestSearch->getFilename($filters, $scope, $responseType);
            return $this->RestResponse->viewData($final, $responseType, false, true, $filename, array('X-Result-Count' => $elementCounter, 'X-Export-Module-Used' => $returnFormat, 'X-Response-Format' => $responseType));
        }
    }

    /**
     * Halt execution if we were to query for items above the ID. Blocks the endless caching bug.
     *
     * @param array $filters
     * @param string $scope
     * @return bool
     */
    private function __cachingOverflow($filters, $scope)
    {
        $offset = ($filters['page'] * (empty($filters['limit']) ? 60 : $filters['limit'])) + 1;
        $max_id = $this->$scope->query(sprintf('SELECT max(id) as max_id from %s;', Inflector::tableize($scope)));
        $max_id = intval($max_id[0][0]['max_id']);
        if ($max_id < $offset) {
            return true;
        }
        return false;
    }

    /**
     * Returns true if user can modify given event.
     *
     * @param array $event
     * @return bool
     */
    protected function __canModifyEvent(array $event)
    {
        if (!isset($event['Event'])) {
            throw new InvalidArgumentException('Passed object does not contains Event.');
        }

        if ($this->userRole['perm_site_admin']) {
            return true;
        }
        if ($this->userRole['perm_modify_org'] && $event['Event']['orgc_id'] == $this->Auth->user()['org_id']) {
            return true;
        }
        if ($this->userRole['perm_modify'] && $event['Event']['user_id'] == $this->Auth->user()['id']) {
            return true;
        }
        return false;
    }

    /**
     * Returns true if user can add or remove tags for given event.
     *
     * @param array $event
     * @param bool $isTagLocal
     * @return bool
     */
    protected function __canModifyTag(array $event, $isTagLocal = false)
    {
        // Site admin can add any tag
        if ($this->userRole['perm_site_admin']) {
            return true;
        }
        // User must have tagger or sync permission
        if (!$this->userRole['perm_tagger'] && !$this->userRole['perm_sync']) {
            return false;
        }
        if ($this->__canModifyEvent($event)) {
            return true; // full access
        }
        if ($isTagLocal && Configure::read('MISP.host_org_id') == $this->Auth->user('org_id')) {
            return true;
        }
        return false;
    }

    /**
     * Refresh user data in session, but keep information about authkey.
     * @return array User data in auth format
     */
    protected function _refreshAuth()
    {
        $sessionUser = $this->Auth->user();
        $user = $this->User->getAuthUser($sessionUser['id']);
        if (!$user) {
            throw new RuntimeException("User with ID {$sessionUser['id']} not exists.");
        }
        if (isset($sessionUser['authkey_id'])) {
            // Reload authkey
            $this->loadModel('AuthKey');
            $authKey = $this->AuthKey->find('first', [
                'conditions' => ['id' => $sessionUser['authkey_id'], 'user_id' => $user['id']],
                'fields' => ['id', 'expiration', 'allowed_ips'],
                'recursive' => -1,
            ]);
            if (empty($authKey)) {
                throw new RuntimeException("Auth key with ID {$sessionUser['authkey_id']} not exists.");
            }
            $user['authkey_id'] = $authKey['AuthKey']['id'];
            $user['authkey_expiration'] = $authKey['AuthKey']['expiration'];
            $user['allowed_ips'] = $authKey['AuthKey']['allowed_ips'];
        }
        if (isset($sessionUser['logged_by_authkey'])) {
            $user['logged_by_authkey'] = $sessionUser['logged_by_authkey'];
        }
        $this->Auth->login($user);
        return $user;
    }

    /**
     * @return string|null
     */
    protected function _remoteIp()
    {
        $ipHeader = Configure::read('MISP.log_client_ip_header') ?: 'REMOTE_ADDR';
        return isset($_SERVER[$ipHeader]) ? trim($_SERVER[$ipHeader]) : null;
    }

    /**
     * @param string $key
     * @return bool Returns true if the same log defined by $key was not stored in last hour
     */
    protected function _shouldLog($key)
    {
        if (Configure::read('Security.log_each_individual_auth_fail')) {
            return true;
        }
        $redis = $this->User->setupRedis();
        if ($redis && !$redis->exists('misp:auth_fail_throttling:' . $key)) {
            $redis->setex('misp:auth_fail_throttling:' . $key, 3600, 1);
            return true;
        }
        return false;
    }
}
