<?php
App::uses('ConnectionManager', 'Model');
App::uses('Controller', 'Controller');
App::uses('File', 'Utility');
App::uses('RequestRearrangeTool', 'Tools');
App::uses('BlowfishConstantPasswordHasher', 'Controller/Component/Auth');
App::uses('BetterCakeEventManager', 'Tools');

/**
 * Application Controller
 *
 * Add your application-wide methods in the class below, your controllers
 * will inherit them.
 *
 * @package       app.Controller
 * @link http://book.cakephp.org/2.0/en/controllers.html#the-app-controller
 *
 * @property CRUDComponent $CRUD
 * @property IndexFilterComponent $IndexFilter
 * @property RateLimitComponent $RateLimit
 * @property CompressedRequestHandlerComponent $CompressedRequestHandler
 * @property DeprecationComponent $Deprecation
 * @property RestSearchComponent $RestSearch
 * @property BetterSecurityComponent $Security
 */
class AppController extends Controller
{
    /**
     * @var string
     * @deprecated Use modelClass instead
     */
    public $defaultModel = '';

    public $helpers = array('OrgImg', 'FontAwesome', 'UserName');

    private $__queryVersion = '165';
    public $pyMispVersion = '2.5.1';
    public $phpmin = '8.1';
    public $phprec = '8.2';
    public $phptoonew = '9.0';
    private $isApiAuthed = false;

    /** @var redis */
    private $redis = null;

    /** @var benchmark_results */
    private $benchmark_results = null;

    public $baseurl = '';

    public $restResponsePayload = null;

    protected $_legacyParams = array();
    /** @var array */
    public $userRole;

    /** @var User */
    public $User;

    /** @var AuthComponent */
    public $Auth;

    /** @var ACLComponent */
    public $ACL;

    /** @var BenchmarkComponent */
    public $Benchmark;

    /** @var RestResponseComponent */
    public $RestResponse;

    public $start_time;

    public function __construct($request = null, $response = null)
    {
        parent::__construct($request, $response);
        $this->defaultModel = $this->modelClass;
    }

    public $components = array(
        'Session',
        'Auth' => array(
            'authError' => 'Unauthorised access.',
            'authenticate' => array(
                'Form' => array(
                    'passwordHasher' => 'BlowfishConstant',
                    'fields' => array(
                        'username' => 'email'
                    )
                )
            )
        ),
        'Security' => [
            'className' => 'BetterSecurity',
        ],
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
        if (Configure::read('MISP.system_setting_db')) {
            App::uses('SystemSetting', 'Model');
            SystemSetting::setGlobalSetting();
        }

        // Set the baseurl for redirects
        $baseurl = empty(Configure::read('MISP.baseurl')) ? null : Configure::read('MISP.baseurl');
        if (!empty($baseurl)) {
            Configure::write('App.fullBaseUrl', $baseurl);
            Router::fullBaseUrl($baseurl);
        }

        $this->_setupBaseurl();
        $this->User = ClassRegistry::init('User');
        if (Configure::read('Plugin.Benchmarking_enable')) {
            App::uses('BenchmarkTool', 'Tools');
            $this->Benchmark = new BenchmarkTool($this->User);
            $this->start_time = $this->Benchmark->startBenchmark();
        }
        $controller = $this->request->params['controller'];
        $action = $this->request->params['action'];
        if ($action === 'heartbeat') {
            return;
        }
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
            if ($secFetchSite !== false && $secFetchSite !== 'same-origin' && $this->request->is(['post', 'put', 'ajax'])) {
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

        $this->_setupDatabaseConnection();

        $this->set('debugMode', Configure::read('debug') >= 1 ? 'debugOn' : 'debugOff');
        $isAjax = $this->request->is('ajax');
        $this->set('ajax', $isAjax);
        $this->set('queryVersion', $this->__queryVersion);

        $language = Configure::read('MISP.language');
        if (!empty($language) && $language !== 'eng') {
            Configure::write('Config.language', $language);
        } else {
            Configure::write('Config.language', 'eng');
        }

        if (!empty($this->request->params['named']['disable_background_processing'])) {
            Configure::write('MISP.background_jobs', 0);
        }

        Configure::write('CurrentController', $controller);
        Configure::write('CurrentAction', $action);
        Configure::write('CurrentRequestIsRest', $this->_isRest());
        $versionArray = $this->User->checkMISPVersion();
        $this->mispVersion = implode('.', $versionArray);
        $this->Security->blackHoleCallback = 'blackHole';

        // send users away that are using ancient versions of IE
        // Make sure to update this if IE 20 comes out :)
        if (isset($_SERVER['HTTP_USER_AGENT'])) {
            if (preg_match('/(?i)msie [2-8]/', $_SERVER['HTTP_USER_AGENT']) && !strpos($_SERVER['HTTP_USER_AGENT'], 'Opera')) {
                throw new MethodNotAllowedException('You are using an unsecure and outdated version of IE, please download Google Chrome, Mozilla Firefox or update to a newer version of IE. If you are running IE9 or newer and still receive this error message, please make sure that you are not running your browser in compatibility mode. If you still have issues accessing the site, get in touch with your administration team at ' . Configure::read('MISP.contact'));
            }
        }

        // For fresh installation (salt empty) generate a new salt
        if (!Configure::read('Security.salt')) {
            $this->User->Server->serverSettingsSaveValue('Security.salt', $this->User->generateRandomPassword(32));
        }

        // Check if the instance has a UUID, if not assign one.
        if (!Configure::read('MISP.uuid')) {
            $this->User->Server->serverSettingsSaveValue('MISP.uuid', CakeText::uuid());
        }

        /**
         * Authentication related activities
         */

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

        $userLoggedIn = false;
        if (Configure::read('Plugin.CustomAuth_enable')) {
            $userLoggedIn = $this->__customAuthentication($_SERVER);
        }
        if ($this->_isRest()) {
            $jsonDecode = function ($dataToDecode) {
                if (empty($dataToDecode)) {
                    return null;
                }
                return $this->_jsonDecode($dataToDecode);
            };
            //  Throw exception if JSON in request is invalid. Default CakePHP behaviour would just ignore that error.
            $this->RequestHandler->addInputType('json', [$jsonDecode]);
            $this->Security->unlockedActions = [$action];
            $this->Security->doNotGenerateToken = true;
        }

        if (
            !$userLoggedIn &&
            (
                $controller !== 'users' ||
                (
                    ($action !== 'register' || empty(Configure::read('Security.allow_self_registration'))) &&
                    (!in_array($action, ['forgot', 'password_reset']) || empty(Configure::read('Security.allow_password_forgotten')))
                )
            )
        ) {
            // REST authentication
            if ($this->_isRest() || $this->_isAutomation()) {

                // disable CSRF for REST access
                $this->Security->csrfCheck = false;
                $loginByAuthKeyResult = $this->__loginByAuthKey();
                if ($loginByAuthKeyResult === false || $this->Auth->user() === null) {
                    if ($this->IndexFilter->isXhr()) {
                        throw new ForbiddenException('Authentication failed.');
                    }

                    if ($loginByAuthKeyResult === null) {
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
            if ($user['Role']['perm_site_admin'] || (!$this->_isRest() && !$isAjax && $this->_isLive())) {
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

            if (Configure::read('Security.user_org_uuid_in_response_header')) {
                $userOrgHeaderValue = $user['Organisation']['uuid'];
                $this->response->header('X-UserOrgUUID', $userOrgHeaderValue);
                $this->RestResponse->setHeader('X-UserOrgUUID', $userOrgHeaderValue);
            }

            if (!$this->__verifyUser($user))  {
                $this->_stop(); // just for sure
            }
            $user = $this->Auth->user(); // user info in session could change (see __verifyUser) method, so reload user variable

            if (isset($user['logged_by_authkey']) && $user['logged_by_authkey'] && !($this->_isRest() || $this->_isAutomation())) {
                throw new ForbiddenException("When user is authenticated by authkey, just REST request can be processed.");
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
            $this->set('isAclPublish', $role['perm_publish']);
            $this->set('isAclDelegate', $role['perm_delegate']);
            $this->set('isAclSync', $role['perm_sync']);
            $this->set('isAclAudit', $role['perm_audit']);
            $this->set('isAclRegexp', $role['perm_regexp_access']);
            $this->set('isAclTagger', $role['perm_tagger']);
            $this->set('isAclGalaxyEditor', !empty($role['perm_galaxy_editor']));
            $this->set('isAclSighting', $role['perm_sighting'] ?? false);
            $this->set('isAclAnalystDataCreator', $role['perm_analyst_data'] ?? false);
            $this->set('aclComponent', $this->ACL);
            $this->loadModel('Bookmark');
            $this->set('bookmarks', $this->Bookmark->getBookmarksForUser($user));
            $this->userRole = $role;

            $this->__accessMonitor($user);

        } else {
            $preAuthActions = array('login', 'register', 'getGpgPublicKey', 'logout401', 'otp');
            if (!empty(Configure::read('Security.email_otp_enabled'))) {
                $preAuthActions[] = 'email_otp';
            }
            if (!empty(Configure::read('Security.allow_password_forgotten'))) {
                $preAuthActions[] = 'forgot';
                $preAuthActions[] = 'password_reset';
            }
            if (!$this->_isControllerAction(['users' => $preAuthActions, 'servers' => ['cspReport']])) {
                if ($isAjax) {
                    $response = $this->RestResponse->throwException(401, "Unauthorized");
                    $response->send();
                    $this->_stop();
                } else {
                    $this->Session->write('pre_login_requested_url', $this->request->here);
                    $this->_redirectToLogin();
                }
            }
            $this->set('me', false);
        }

        if ($user && $this->_isSiteAdmin()) {
            if (Configure::read('Session.defaults') === 'database') {
                $db = ConnectionManager::getDataSource('default');
                $sqlResult = $db->query('SELECT COUNT(id) AS session_count FROM cake_sessions WHERE expires < ' . time() . ';');
                if (isset($sqlResult[0][0]['session_count']) && $sqlResult[0][0]['session_count'] > 1000) {
                    $this->User->Server->updateDatabase('cleanSessionTable');
                }
            }
            if (Configure::read('site_admin_debug') && Configure::read('debug') < 2) {
                Configure::write('debug', 1);
            }
        }

        $this->ACL->checkAccess($user, Inflector::variable($controller), $action);
        if ($user && $this->_isRest()) {
            $this->__rateLimitCheck($user);
        }
        if ($this->modelClass !== 'CakeError') {
            $deprecationWarnings = $this->Deprecation->checkDeprecation($controller, $action, $user ? $user['id'] : null);
            if ($deprecationWarnings) {
                $deprecationWarnings = __('WARNING: This functionality is deprecated and will be removed in the near future. ') . $deprecationWarnings;
                if ($this->_isRest()) {
                    $this->response->header('X-Deprecation-Warning', $deprecationWarnings);
                    $this->RestResponse->setHeader('X-Deprecation-Warning', $deprecationWarnings);
                } else {
                    $this->Flash->warning($deprecationWarnings);
                }
            }
        }
        if (Configure::read('MISP.enable_automatic_garbage_collection') && mt_rand(1,100) % 100 == 0) {
            $this->loadModel('AdminSetting');
            $this->AdminSetting->garbageCollect();
        }
    }

    public function beforeRender()
    {
        // Notifications and homepage is not necessary for AJAX or REST requests
        if (!$this->_isRest() && isset($this->User) && !$this->request->is('ajax')) {
            $user = $this->Auth->user();
            if (!$user) {
                return;
            }
            $hasNotifications = $this->User->hasNotifications($user);
            $this->set('hasNotifications', $hasNotifications);

            $homepage = $this->User->UserSetting->getValueForUser($user['id'], 'homepage');
            if (!empty($homepage)) {
                $this->set('homepage', $homepage);
            }
            if (PHP_MAJOR_VERSION < 8) {
                $this->Flash->error(__('WARNING: MISP 2.5.x is currently running under PHP 7.x, which is unsupported. Make sure that you upgrade to PHP 8.x as soon as possible.'));
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
            return true;
        }

        // If enabled, allow passing the API key via a named parameter (for crappy legacy systems only)
        $namedParamAuthkey = false;
        if (Configure::read('Security.allow_unsafe_apikey_named_param') && !empty($this->request->params['named']['apikey'])) {
            $namedParamAuthkey = $this->request->params['named']['apikey'];
        }
        $apikey = null;
        if (!empty($_SERVER['HTTP_AUTHORIZATION'])) {
            $apikey = $_SERVER['HTTP_AUTHORIZATION'];
        }
        if (!empty($_SERVER['HTTP_X_MISP_AUTH'])) {
            $apikey = $_SERVER['HTTP_X_MISP_AUTH'];
        }
        // Authenticate user with authkey in Authorization HTTP header
        if (!empty($apikey) && strcasecmp(substr($apikey, 0, 5), "Basic") == 0) { // Skip Basic Authorizations
            return null;
        }
        if (!empty($apikey) || !empty($namedParamAuthkey)) {
            $foundMispAuthKey = false;
            $authentication = explode(',', $apikey);
            if (!empty($namedParamAuthkey)) {
                $authentication[] = $namedParamAuthkey;
            }
            $user = false;
            foreach ($authentication as $authKey) {
                $authKey = trim($authKey);
                if (preg_match('/^[a-zA-Z0-9]{40}$/', $authKey)) {
                    $foundMispAuthKey = true;
                    $temp = $this->_checkAuthUser($authKey);
                    if ($temp) {
                        $user = $temp;
                        break;
                    }
                }
            }
            if ($foundMispAuthKey) {
                $start = substr($authKey, 0, 4);
                $end = substr($authKey, -4);
                $authKeyToStore = $start
                    . str_repeat('*', 32)
                    . $end;
                if (!empty(Configure::read('Security.allow_unsafe_cleartext_apikey_logging'))) {
                    $authKeyToStore = $authKey;
                }
                $this->__logApiKeyUse($start . $end);
                if ($user) {
                    // User found in the db, add the user info to the session
                    if (Configure::read('MISP.log_auth')) {
                        $this->loadModel('Log');
                        $change = $this->User->UserLoginProfile->_getUserProfile();
                        $change['http_method'] = $_SERVER['REQUEST_METHOD'];
                        $change['target'] = $this->request->here;
                        $this->Log->createLogEntry(
                            $user,
                            'auth',
                            'User',
                            $user['id'],
                            "Successful authentication using API key ($authKeyToStore)",
                            json_encode($change));
                    }
                    $this->User->updateAPIAccessTime($user);
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
            } else {
                    $this->loadModel('Log');
                    $this->Log->createLogEntry('SYSTEM', 'auth_fail', 'User', 0, "Failed authentication using an API key of incorrect length.");
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
        if (!$this->_isLive()) {
            if (!$user['Role']['perm_site_admin']) {
                $message = Configure::read('MISP.maintenance_message');
                if (empty($message)) {
                    $message = $this->User->Server->serverSettings['MISP']['maintenance_message']['value'];
                }
                if (strpos($message, '$email') && Configure::read('MISP.email')) {
                    $email = Configure::read('MISP.email');
                    $message = str_replace('$email', $email, $message);
                }
                $this->Flash->info($message);
                $this->Auth->logout();
                $this->_redirectToLogin();
                return false;
            } else {
                $this->Flash->error(__('Warning: MISP is currently disabled for all users. Enable it in Server Settings (Administration -> Server Settings -> MISP tab -> live). An update might also be in progress, you can see the progress in ') , array('params' => array('url' => $this->baseurl . '/servers/updateProgress/', 'urlName' => __('Update Progress')), 'clear' => 1));
            }
        }

        $sessionCreationTime = $this->Session->read('creation_timestamp');
        if (empty($sessionCreationTime)) {
            $sessionCreationTime = $_SERVER['REQUEST_TIME'] ?? time();
            $this->Session->write('creation_timestamp', $sessionCreationTime);
        }

        // kill existing sessions for a user if the admin/instance decides so
        // exclude API authentication as it doesn't make sense
        if (!$this->isApiAuthed && $this->User->checkForSessionDestruction($user['id'], $sessionCreationTime)) {
            $this->Auth->logout();
            $this->Session->destroy();
            $this->Flash->warning(__('User deauthenticated on administrator request. Please reauthenticate.'));
            $this->_redirectToLogin();
            return false;
        }

        // Force logout doesn't make sense for API key authentication
        if (!$this->isApiAuthed && $user['force_logout']) {
            $this->User->id = $user['id'];
            $this->User->saveField('force_logout', false);
            $this->Auth->logout();
            $this->_redirectToLogin();
            return false;
        }

        if ($user['disabled'] || (isset($user['logged_by_authkey']) && $user['logged_by_authkey']) && !$this->User->checkIfUserIsValid($user)) {
            if ($this->_shouldLog('disabled:' . $user['id'])) {
                $this->Log = ClassRegistry::init('Log');
                $change = $this->User->UserLoginProfile->_getUserProfile();
                $this->Log->createLogEntry($user, 'auth_fail', 'User', $user['id'], 'Login attempt by disabled user.', json_encode($change));
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
            $time = $_SERVER['REQUEST_TIME'] ?? time();
            if ($user['authkey_expiration'] < $time) {
                if ($this->_shouldLog('expired:' . $user['authkey_id'])) {
                    $this->Log = ClassRegistry::init('Log');
                    $change = $this->User->UserLoginProfile->_getUserProfile();
                    $this->Log->createLogEntry($user, 'auth_fail', 'User', $user['id'], "Login attempt by expired auth key {$user['authkey_id']}.", json_encode($change));
                }
                $this->Auth->logout();
                throw new ForbiddenException('Auth key is expired');
            }
        }

        if (!empty($user['allowed_ips'])) {
            App::uses('CidrTool', 'Tools');
            $cidrTool = new CidrTool($user['allowed_ips']);
            $remoteIp = $this->User->_remoteIp();
            if ($remoteIp === null) {
                $this->Auth->logout();
                throw new ForbiddenException('Auth key is limited to IP address, but IP address not found');
            }
            if (!$cidrTool->contains($remoteIp)) {
                if ($this->_shouldLog('not_allowed_ip:' . $user['authkey_id'] . ':' . $remoteIp)) {
                    $this->Log = ClassRegistry::init('Log');
                    $change = $this->User->UserLoginProfile->_getUserProfile();
                    $this->Log->createLogEntry($user, 'auth_fail', 'User', $user['id'], "Login attempt from not allowed IP address {$remoteIp} for auth key {$user['authkey_id']}.", json_encode($change));
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

        // Check if user must create TOTP secret, force them to be on that page as long as needed.
        if (
            empty($user['totp']) &&
            Configure::read('Security.otp_required') &&
            !$this->_isControllerAction(['users' => ['terms', 'change_pw', 'logout', 'login', 'totp_new']]) &&
            empty($user['Role']['perm_skip_otp'])
        ) {  // TOTP is mandatory for users, prevent login until the user has configured their TOTP
            $this->redirect(array('controller' => 'users', 'action' => 'totp_new', 'admin' => false));
            return false;
        }

        // Check if user accepted terms and conditions
        if (!$user['termsaccepted'] && !empty(Configure::read('MISP.terms_file')) && !$this->_isControllerAction(['users' => ['terms', 'logout', 'login', 'downloadTerms', 'totp_new', 'email_otp']])) {
            //if ($this->_isRest()) throw new MethodNotAllowedException('You have not accepted the terms of use yet, please log in via the web interface and accept them.');
            $this->redirect(array('controller' => 'users', 'action' => 'terms', 'admin' => false));
            return false;
        }

        // Check if user must change password
        if ($user['change_pw'] && !$this->_isControllerAction(['users' => ['terms', 'change_pw', 'logout', 'login', 'totp_new', 'email_otp']])) {
            //if ($this->_isRest()) throw new MethodNotAllowedException('Your user account is expecting a password change, please log in via the web interface and change it before proceeding.');
            $this->redirect(array('controller' => 'users', 'action' => 'change_pw', 'admin' => false));
            return false;
        }

        // Check if user must read news
        if (!$this->_isControllerAction(['news' => ['index'], 'users' => ['terms', 'change_pw', 'login', 'logout', 'totp_new', 'email_otp']])) {
            $this->loadModel('News');
            $latestNewsCreated = $this->News->latestNewsTimestamp();
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
        return in_array($this->request->params['action'], $actionsToCheck[$controller], true);
    }

    private function __logApiKeyUse($apikey)
    {
        $redis = $this->User->setupRedis();
        if (!$redis) {
            return;
        }
        $redis->zIncrBy('misp:authkey_log:' . date("Ymd"), 1, $apikey);
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

        $remoteAddress = $this->User->_remoteIp();

        $pipe = $redis->pipeline();
        // keep for 30 days
        $pipe->setex('misp:ip_user:' . $remoteAddress, 60 * 60 * 24 * 30, $user['id']);
        $pipe->sadd('misp:user_ip:' . $user['id'], $remoteAddress);

        // Log key usage if enabled
        if (isset($user['authkey_id']) && Configure::read('MISP.log_user_ips_authkeys')) {
            // Use request time if defined
            $time = $_SERVER['REQUEST_TIME'] ?? time();
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
            try {
                $userMonitoringEnabled = RedisTool::init()->sismember('misp:monitored_users', $user['id']);
            } catch (Exception $e) {
                $userMonitoringEnabled = false;
            }
        }

        $shouldBeLogged = $userMonitoringEnabled ||
            Configure::read('MISP.log_paranoid') ||
            (Configure::read('MISP.log_paranoid_api') && isset($user['logged_by_authkey']));

        if ($shouldBeLogged) {
            $includeRequestBody = !empty(Configure::read('MISP.log_paranoid_include_post_body')) || $userMonitoringEnabled;
            /** @var AccessLog $accessLog */
            $accessLog = ClassRegistry::init('AccessLog');
            $accessLog->logRequest($user, $this->User->_remoteIp(), $this->request, $includeRequestBody);
        }

        if (
            empty(Configure::read('MISP.log_skip_access_logs_in_application_logs')) &&
            $shouldBeLogged
        ) {
            $change = 'HTTP method: ' . $_SERVER['REQUEST_METHOD'] . PHP_EOL . 'Target: ' . $this->request->here;
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
            $this->loadModel('Log');
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

    private function __rateLimitCheck(array $user)
    {
        $rateLimitCheck = $this->RateLimit->check(
            $user,
            $this->request->params['controller'],
            $this->request->params['action'],
        );

        if ($rateLimitCheck) {
            $headers = [
                'X-Rate-Limit-Limit' => $rateLimitCheck['limit'],
                'X-Rate-Limit-Remaining' => $rateLimitCheck['remaining'],
                'X-Rate-Limit-Reset' => $rateLimitCheck['reset'],
            ];

            if ($rateLimitCheck['exceeded']) {
                $response = $this->RestResponse->throwException(
                    429,
                    __('Rate limit exceeded.'),
                    '/' . $this->request->params['controller'] . '/' . $this->request->params['action'],
                    false,
                    false,
                    $headers
                );
                $response->send();
                $this->_stop();
            } else {
                $this->RestResponse->headers = array_merge($this->RestResponse->headers, $headers);
            }
        }
    }

    public function afterFilter()
    {
        // benchmarking
        if (Configure::read('Plugin.Benchmarking_enable') && isset($this->Benchmark)) {
            $this->Benchmark->stopBenchmark([
                'user' => $this->Auth->user('id'),
                'controller' => $this->request->params['controller'],
                'action' => $this->request->params['action'],
                'start_time' => $this->start_time
            ]);

            //if ($redis && !$redis->exists('misp:auth_fail_throttling:' . $key)) {
                //$redis->setex('misp:auth_fail_throttling:' . $key, 3600, 1);
                //return true;
            //}

        }
        if ($this->isApiAuthed && $this->_isRest() && !Configure::read('Security.authkey_keep_session')) {
            $this->Session->destroy();
        }
    }

    public function queryACL($debugType='findMissingFunctionNames', $content = false)
    {
        $validCommands = array('printAllFunctionNames', 'findMissingFunctionNames', 'printRoleAccess');
        if (!in_array($debugType, $validCommands)) {
            throw new MethodNotAllowedException('Invalid function call.');
        }
        return $this->RestResponse->viewData($this->ACL->$debugType($content), 'json');
    }

    /**
     * Setup & validate the database connection configuration
     * @throws Exception if the configured database is not supported.
     */
    protected function _setupDatabaseConnection()
    {
        // check for a supported datasource configuration
        $dataSourceConfig = ConnectionManager::getDataSource('default')->config;
        if (!isset($dataSourceConfig['encoding'])) {
            $db = ConnectionManager::getDataSource('default');
            $db->setConfig(array('encoding' => 'utf8'));
            ConnectionManager::create('default', $db->config);
        }
        $dataSource = $dataSourceConfig['datasource'];
        if (!in_array($dataSource, ['Database/Mysql', 'Database/Postgres', 'Database/MysqlObserver', 'Database/MysqlExtended', 'Database/MysqlObserverExtended'], true)) {
            throw new Exception('Datasource not supported: ' . $dataSource);
        }
    }

    /*
     * Sanitize the configured `MISP.baseurl` and expose it to the view as `baseurl`.
     */
    protected function _setupBaseurl()
    {
        // Let us access $baseurl from all views
        $baseurl = Configure::read('MISP.baseurl');
        if (str_ends_with($baseurl, '/')) {
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
        return $this->IndexFilter->isApiFunction($this->request->params['controller'], $this->request->params['action']);
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

    private function __captureParam($data, $param, $value)
    {
        if ($this->modelClass->checkParam($param)) {
            $data[$param] = $value;
        }
        return $data;
    }

    /**
     * generic function to standardise on the collection of parameters. Accepts posted request objects, url params, named url params
     * @param array $options
     * @param CakeResponse $exception
     * @param array $data
     * @return array|false
     */
    protected function _harvestParameters($options, &$exception = null, $data = [])
    {
        if (!empty($options['paramArray'])) {
            if (!in_array('page', $options['paramArray'])) {
                $options['paramArray'][] = 'page';
            }
            if (!in_array('limit', $options['paramArray'])) {
                $options['paramArray'][] = 'limit';
            }
        }
        $request = $options['request'] ?? $this->request;
        if ($request->is('post')) {
            if (empty($request->data)) {
                $exception = $this->RestResponse->throwException(
                    400,
                    __('Either specify the search terms in the url, or POST a json with the filter parameters.'),
                    '/' . $request->params['controller'] . '/' . $request->action
                );
                return false;
            } else {
                if (isset($request->data['request'])) {
                    $temp = $request->data['request'];
                } else {
                    $temp = $request->data;
                }
                if (empty($options['paramArray'])) {
                    foreach ($options['paramArray'] as $param => $value) {
                        $data = $this->__captureParam($data, $param, $value);
                    }
                    $data = array_merge($data, $temp);
                } else {
                    foreach ($options['paramArray'] as $param) {
                        if (str_ends_with($param, '*')) {
                            $root = substr($param, 0, strlen($param)-1);
                            foreach ($temp as $existingParamKey => $v) {
                                $leftover = substr($existingParamKey, strlen($param)-1);
                                if (
                                    $root == substr($existingParamKey, 0, strlen($root)) &&
                                    preg_match('/^[\w_-. ]+$/', $leftover) == 1
                                ) {
                                    $data[$existingParamKey] = $temp[$existingParamKey];
                                    break;
                                }
                            }
                        } else if (isset($temp[$param])) {
                            $data[$param] = $temp[$param];
                        }
                    }
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
        foreach ($data as &$v) {
            if (is_string($v)) {
                $v = trim($v);
                if (strpos($v, '||')) {
                    $v = explode('||', $v);
                }
            }
        }
        unset($v);
        if (!empty($options['additional_delimiters'])) {
            if (!is_array($options['additional_delimiters'])) {
                $options['additional_delimiters'] = array($options['additional_delimiters']);
            }
            foreach ($data as $k => $v) {
                $found = false;
                foreach ($options['additional_delimiters'] as $delim) {
                    if (str_contains($v, $delim)) {
                        $found = true;
                        break;
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

    protected function _checkAuthUser($authkey)
    {
        if (Configure::read('Security.api_key_quick_lookup')) {
            $redis = RedisTool::init();
            if (file_exists(APP . 'Config/hmac_key.php')) {
                include(APP . 'Config/hmac_key.php');
                $hashed_authkey = hash_hmac('sha512', $authkey, $hmac_key);
                if ($redis && $redis->exists('misp:fast_authkey_lookup:' . $hashed_authkey)) {
                    $user = RedisTool::deserialize($redis->get('misp:fast_authkey_lookup:' . $hashed_authkey));
                    if ($user) {
                        return $user;
                    }
                }
            } else {
                App::uses('RandomTool', 'Tools');
                $hmac_key = RandomTool::random_str(true, 40);
                file_put_contents(APP . 'Config/hmac_key.php', sprintf('<?php%s$hmac_key = \'%s\';', PHP_EOL, $hmac_key));
            }
        }
        if (Configure::read('Security.advanced_authkeys')) {
            $user = $this->User->AuthKey->getAuthUserByAuthKey($authkey);
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
        if (Configure::read('Security.api_key_quick_lookup') && !empty($hmac_key) && $redis) {
            $expiration = Configure::read('Security.api_key_quick_lookup_expiration') ? Configure::read('Security.api_key_quick_lookup_expiration') : 180;
            if ($redis) {
                $hashed_authkey = hash_hmac('sha512', $authkey, $hmac_key);
                $redis->setex('misp:fast_authkey_lookup:' . $hashed_authkey, $expiration, RedisTool::serialize($user));
            }
        }
        return $user;
    }

    private function _checkExternalAuthUser($authkey)
    {
        $user = $this->User->getAuthUserByExternalAuth($authkey);
        if (empty($user)) {
            return false;
        }
        return $user;
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
            $header = Configure::read('Plugin.CustomAuth_header') ? Configure::read('Plugin.CustomAuth_header') : 'AUTHORIZATION';
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
                if (Configure::read('Plugin.CustomAuth_only_allow_source') && Configure::read('Plugin.CustomAuth_only_allow_source') !== $this->User->_remoteIp()) {
                    $this->Log = ClassRegistry::init('Log');
                    $this->Log->createLogEntry(
                        'SYSTEM',
                        'auth_fail',
                        'User',
                        0,
                        'Failed authentication using external key (' . trim($server[$headerNamespace . $header]) . ') - the user has not arrived from the expected address. Instead the request came from: ' . $this->User->_remoteIp(),
                        null);
                    $this->__preAuthException($authName . ' authentication failed. Contact your MISP support for additional information at: ' . Configure::read('MISP.contact'));
                }
                $user = $this->_checkExternalAuthUser($server[$headerNamespace . $header]);
                if ($user) {
                    $this->User->updateLoginTimes($user);
                    //$this->Session->renew();
                    $this->Session->write(AuthComponent::$sessionKey, $user);
                    if (Configure::read('MISP.log_auth')) {
                        $this->Log = ClassRegistry::init('Log');
                        $change = $this->User->UserLoginProfile->_getUserProfile();
                        $change['http_method'] = $_SERVER['REQUEST_METHOD'];
                        $change['target'] = $this->request->here;
                        $this->Log->createLogEntry(
                            $user,
                            'auth',
                            'User',
                            $user['id'],
                            'Successful authentication using ' . $authName . ' key',
                            json_encode($change));
                    }
                    $result = true;
                } else {
                    // User not authenticated correctly
                    // reset the session information
                    $this->Log = ClassRegistry::init('Log');
                    $change = $this->User->UserLoginProfile->_getUserProfile();
                    $this->Log->createLogEntry(
                        'SYSTEM',
                        'auth_fail',
                        'User',
                        0,
                        'Failed authentication using external key (' . trim($server[$headerNamespace . $header]) . ')',
                        json_encode($change));
                    if (Configure::read('CustomAuth_required')) {
                        $this->Session->destroy();
                        $this->__preAuthException($authName . ' authentication failed. Contact your MISP support for additional information at: ' . Configure::read('MISP.contact'));
                    }
                }
            }
        }
        return $result;
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

    private function _redirectToLogin()
    {
        $targetRoute = Configure::read('MISP.baseurl') . '/users/login';
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
        if ($scope === 'MispAttribute') {
            $scope = 'Attribute';
        }
        if (!isset($this->RestSearch->paramArray[$scope])) {
            throw new NotFoundException(__('RestSearch is not implemented (yet) for this scope.'));
        }
        if ($scope === 'Object') {
            $modelName = 'MispObject';
        } else if ($scope === 'Attribute') {
            $modelName = 'MispAttribute';
        }else {
            $modelName = $scope;
        }
        if (!isset($this->$modelName)) {
            $this->loadModel($modelName);
        }
        /** @var AppModel $model */
        $model = $this->$modelName;

        $filterData = array(
            'request' => $this->request,
            'named_params' => $this->request->params['named'],
            'paramArray' => $this->RestSearch->paramArray[$scope],
            'ordered_url_params' => func_get_args()
        );
        $exception = false;
        $filters = $this->_harvestParameters($filterData, $exception, $this->_legacyParams);
        if (empty($filters) && $this->request->is('get')) {
            throw new BadRequestException(__('Restsearch queries using GET and no parameters are not allowed. If you have passed parameters via a JSON body, make sure you use POST requests.'));
        }
        if (empty($filters['returnFormat'])) {
            $filters['returnFormat'] = 'json';
        }
        unset($filterData);
        if ($filters === false) {
            return $exception;
        }

        $user = $this->_closeSession();

        if (isset($filters['returnFormat'])) {
            $returnFormat = $filters['returnFormat'];
            if ($returnFormat === 'download') {
                $returnFormat = 'json';
            } else if ($returnFormat === 'stix' && $this->IndexFilter->isJson()) {
                $returnFormat = 'stix-json';
            }
        } else {
            $returnFormat = 'json';
        }
        $elementCounter = 0;
        $renderView = false;
        $responseType = empty($model->validFormats[$returnFormat][0]) ? 'json' : $model->validFormats[$returnFormat][0];
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
        /** @var TmpFileTool $final */
        $skippedElementsCounter = 0;
        $final = $model->restSearch($user, $returnFormat, $filters, false, false, $elementCounter, $renderView, $skippedElementsCounter);
        if ($renderView) {
            $this->layout = false;
            $final = JsonTool::decode($final->intoString());
            $this->set($final);
            $this->render('/Events/module_views/' . $renderView);
        } else {
            $filename = $this->RestSearch->getFilename($filters, $scope, $responseType);
            $headers = ['X-Result-Count' => $elementCounter, 'X-Export-Module-Used' => $returnFormat, 'X-Response-Format' => $responseType, 'X-Skipped-Elements-Count' => $skippedElementsCounter];
            return $this->RestResponse->viewData($final, $responseType, false, true, $filename, $headers);
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
     * @param array|null $user If empty, currently logged user will be used
     * @return bool
     */
    protected function __canModifyEvent(array $event, $user = null)
    {
        $user = $user ?: $this->Auth->user();
        return $this->ACL->canModifyEvent($user, $event);
    }

    /**
     * Returns true if user can publish the given event.
     *
     * @param array $event
     * @param array|null $user If empty, currently logged user will be used
     * @return bool
     */
    protected function __canPublishEvent(array $event, $user = null)
    {
        $user = $user ?: $this->Auth->user();
        return $this->ACL->canPublishEvent($user, $event);
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
        return $this->ACL->canModifyTag($this->Auth->user(), $event, $isTagLocal);
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
            $user = $this->User->AuthKey->updateUserData($user, $sessionUser['authkey_id']);
        }
        if (isset($sessionUser['logged_by_authkey'])) {
            $user['logged_by_authkey'] = $sessionUser['logged_by_authkey'];
        }
        $this->Auth->login($user);
        return $user;
    }

    /**
     * @return string|null
     * @deprecated Use User::_remoteIp() instead
     */
    protected function _remoteIp()
    {
        return $this->User->_remoteIp();
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

    /**
     * @return bool True if MISP instance is live
     */
    protected function _isLive()
    {
        if (!Configure::read('MISP.live')) {
            return false;
        }

        try {
            return RedisTool::init()->get('misp:live') !== '0';
        } catch (Exception $e) {
            return true;
        }
    }

    /**
     * Override default View class
     * @return View
     */
    protected function _getViewObject()
    {
        if ($this->viewClass === 'View') {
            App::uses('AppView', 'View');
            return new AppView($this);
        }
        return parent::_getViewObject();
    }

    public function getEventManager()
    {
        if (empty($this->_eventManager)) {
            $this->_eventManager = new BetterCakeEventManager();
            $this->_eventManager->attach($this->Components);
            $this->_eventManager->attach($this);
        }
        return $this->_eventManager;
    }

    /**
     * Close session without writing changes to them and return current user.
     * @return array
     */
    protected function _closeSession($saveSession = false)
    {
        $user = $this->Auth->user();

        // Hack to store user info in static AuthComponent::$_user variable to avoid starting session again by calling
        // $this->Auth->user()
        AuthComponent::$sessionKey = null;
        $this->Auth->login($user);

        if ($saveSession) {
            @session_write_close();
        } else {
            session_abort();
        }
        return $user;
    }

    /**
     * Decode JSON with proper error handling.
     * @param string $dataToDecode
     * @return mixed
     */
    protected function _jsonDecode($dataToDecode)
    {
        try {
            return JsonTool::decode($dataToDecode);
        } catch (Exception $e) {
            throw new HttpException('Invalid JSON input. Make sure that the JSON input is a correctly formatted JSON string. This request has been blocked to avoid an unfiltered request.', 405, $e);
        }
    }

    /**
     * Mimics what PaginateComponent::paginate() would do, when Model::paginate() is not called
     *
     * @param integer $page
     * @param integer $limit
     * @param integer $current
     * @param string $type
     * @return void
     */
    protected function __setPagingParams(int $page, int $limit, int $current, string $type = 'named')
    {
        $this->request->params['paging'] = [
            $this->modelClass => [
                'page' => $page,
                'limit' => $limit,
                'current' => $current,
                'pageCount' => 0,
                'prevPage' => $page > 1,
                'nextPage' => $current >= $limit,
                'options' => [],
                'paramType' => $type
            ]
        ];
    }
}
