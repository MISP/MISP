<?php

declare(strict_types=1);

/**
 * CakePHP(tm) : Rapid Development Framework (https://cakephp.org)
 * Copyright (c) Cake Software Foundation, Inc. (https://cakefoundation.org)
 *
 * Licensed under The MIT License
 * For full copyright and license information, please see the LICENSE.txt
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright Copyright (c) Cake Software Foundation, Inc. (https://cakefoundation.org)
 * @link      https://cakephp.org CakePHP(tm) Project
 * @since     0.2.9
 * @license   https://opensource.org/licenses/mit-license.php MIT License
 */

namespace App\Controller;

use App\Lib\Tools\JsonTool;
use App\Lib\Tools\RedisTool;
use App\Model\Entity\Event;
use Cake\Controller\Controller;
use Cake\Core\Configure;
use Cake\Event\EventInterface;
use Cake\Http\Exception\BadRequestException;
use Cake\Http\Exception\HttpException;
use Cake\Http\Exception\MethodNotAllowedException;
use Cake\Http\Exception\NotFoundException;
use Cake\ORM\Locator\LocatorAwareTrait;
use Cake\Utility\Inflector;
use Cake\Utility\Text;
use Exception;

/**
 * Application Controller
 *
 * Add your application-wide methods in the class below, your controllers
 * will inherit them.
 *
 * @link https://book.cakephp.org/4/en/controllers.html#the-app-controller
 */
class AppController extends Controller
{
    use LocatorAwareTrait;

    public $isRest = null;
    public $restResponsePayload = null;
    public $user = null;
    public $breadcrumb = [];
    public $request_ip = null;

    public $MetaFields = null;
    public $MetaTemplates = null;
    public $Users = null;

    /**
     * @var \Model\Entity\AuditLog|null
     */
    protected $AuditLogs = null;

    private $__queryVersion = '0';
    public $pyMispVersion = '3.0.0';
    public $phpmin = '8.0';
    public $phprec = '8.4';
    public $phptoonew = null;
    private $isApiAuthed = false;

    /**
     * Initialization hook method.
     *
     * Use this method to add common initialization code like loading components.
     *
     * e.g. `$this->loadComponent('FormProtection');`
     *
     * @return void
     */
    public function initialize(): void
    {
        parent::initialize();
        $this->loadComponent('RequestHandler');
        $this->loadComponent('Flash');
        $this->loadComponent('RestResponse');
        $this->loadComponent('Security');
        $this->loadComponent(
            'ParamHandler',
            [
                'request' => $this->request,
            ]
        );
        $this->loadModel('MetaFields');
        $this->loadModel('MetaTemplates');
        $table = $this->getTableLocator()->get($this->modelClass);
        $this->loadComponent(
            'CRUD',
            [
                'request' => $this->request,
                'table' => $table,
                'MetaFields' => $this->MetaFields,
                'MetaTemplates' => $this->MetaTemplates,
            ]
        );
        $this->loadComponent('Authentication.Authentication');
        $this->loadComponent(
            'ACL',
            [
                'request' => $this->request,
                'Authentication' => $this->Authentication,
            ]
        );
        $this->loadComponent(
            'Navigation',
            [
                'request' => $this->request,
            ]
        );
        $this->loadComponent(
            'Notification',
            [
                'request' => $this->request,
            ]
        );
        if (Configure::read('debug')) {
            Configure::write('DebugKit.panels', ['DebugKit.Packages' => true]);
            Configure::write('DebugKit.forceEnable', true);
        }
        $this->loadComponent('CustomPagination');

        $this->AuditLogs = $this->fetchTable('AuditLogs');
        // $this->loadComponent('FloodProtection'); // TODO: enable after flood protection table exists
        /*
         * Enable the following component for recommended CakePHP form protection settings.
         * see https://book.cakephp.org/4/en/controllers/components/form-protection.html
         */
        //$this->loadComponent('FormProtection');
    }

    /**
     * beforeFilter
     *
     * @param  \Cake\Event\EventInterface $event the event
     * @return void
     */
    public function beforeFilter(EventInterface $event)
    {
        $this->loadModel('Users');
        //$this->Users->checkForNewInstance();
        if ($this->ParamHandler->isRest()) {
            $this->authApiUser();
            $this->Security->setConfig('unlockedActions', [$this->request->getParam('action')]);
            $this->response = $this->setResponseType();
        }
        $this->ACL->setPublicInterfaces();
        if (!empty($this->request->getAttribute('identity'))) {
            $user = $this->Users->get(
                $this->request->getAttribute('identity')->getIdentifier(),
                [
                    'contain' => ['Roles', 'Organisations' /*'UserSettings'*/],
                ]
            );
            $this->__accessMonitor($user->toArray());
            if (empty($user) || !empty($user['disabled'])) {
                $this->Authentication->logout();
                $this->Flash->error(__('The user account is disabled.'));

                return $this->redirect(\Cake\Routing\Router::url('/users/login'));
            }
            unset($user['password']);
            $this->ACL->setUser($user);
            $this->request->getSession()->write('authUser', $user);
            $this->isAdmin = $user['Role']['perm_admin'];
            $this->set('isAdmin', $user['Role']['perm_admin']);
            $this->set('isSiteAdmin', $user['Role']['perm_site_admin']);
            if (!$this->ParamHandler->isRest()) {
                $this->set('menu', $this->ACL->getMenu());
                $this->set('loggedUser', $this->ACL->getUser());
                $this->set('roleAccess', $this->ACL->getRoleAccess(false, false));
            }
        } elseif ($this->ParamHandler->isRest()) {
            throw new MethodNotAllowedException(__('Invalid user credentials.'));
        }

        if ($this->request->getParam('action') === 'index') {
            $this->Security->setConfig('validatePost', false);
        }
        $this->Security->setConfig('unlockedActions', ['index']);
        if ($this->ParamHandler->isRest()) {
            $this->Security->setConfig('unlockedActions', [$this->request->getParam('action')]);
            $this->Security->setConfig('validatePost', false);
        }

        $this->ACL->checkAccess();
        $this->set('default_memory_limit', ini_get('memory_limit'));
        if (!empty($user) && isset($user['Role']['memory_limit']) && $user['Role']['memory_limit'] !== '') {
            ini_set('memory_limit', $user['Role']['memory_limit']);
        }
        $this->set('default_max_execution_time', ini_get('max_execution_time'));
        if (!empty($user) && isset($user['Role']['max_execution_time']) && $user['Role']['max_execution_time'] !== '') {
            ini_set('max_execution_time', $user['Role']['max_execution_time']);
        }
        if (!$this->ParamHandler->isRest()) {
            $this->set('ajax', $this->request->is('ajax'));
            $this->request->getParam('prefix');
            $this->set('baseurl', Configure::read('App.fullBaseUrl'));
            if (!empty($user) && !empty($user->user_settings_by_name['ui.bsTheme']['value'])) {
                $this->set('bsTheme', $user->user_settings_by_name['ui.bsTheme']['value']);
            } else {
                $this->set('bsTheme', Configure::check('ui.bsTheme') ? Configure::read('ui.bsTheme') : 'default');
            }

            if ($this->modelClass == 'Tags.Tags') {
                $this->set('metaGroup', !empty($this->isAdmin) ? 'Administration' : 'Cerebrate');
            }
            $this->response = $this->response->withHeader('X-Frame-Options', 'DENY');
        }
        if (mt_rand(1, 50) === 1) {
            // $this->FloodProtection->cleanup(); // TODO: enable after flood protection table exists
        }
    }

    /**
     * beforeRender
     *
     * @param  \Cake\Event\EventInterface $event the event
     * @return void
     */
    public function beforeRender(EventInterface $event)
    {
        if (!empty($this->request->getAttribute('identity'))) {
            if (!$this->ParamHandler->isRest()) {
                $this->set('breadcrumb', $this->Navigation->getBreadcrumb());
                $this->set('notifications', $this->Notification->getNotifications());
                $this->set('iconToTableMapping', $this->Navigation->getIconToTableMapping());
            }
        }
    }

    /**
     * authApiUser
     *
     * @return void
     */
    private function authApiUser(): void
    {
        if (!empty($_SERVER['HTTP_AUTHORIZATION']) && strlen($_SERVER['HTTP_AUTHORIZATION'])) {
            $AuthKeysTable = $this->fetchTable('AuthKeys');
            $logModel = $this->Users->auditLogs();
            $authKey = $AuthKeysTable->checkKey($_SERVER['HTTP_AUTHORIZATION']);
            if (!empty($authKey)) {
                $UsersTable = $this->fetchTable('Users');
                $user = $UsersTable->get($authKey['user_id']);
                $logModel->insert(
                    [
                        'request_action' => 'login',
                        'model' => 'Users',
                        'model_id' => $user['id'],
                        'model_title' => $user['username'],
                        'changed' => [],
                    ]
                );
                if (!empty($user)) {
                    $this->Authentication->setIdentity($user);
                }
            } else {
                $user = $logModel->userInfo();
                $logModel->insert(
                    [
                        'request_action' => 'login',
                        'model' => 'Users',
                        'model_id' => $user['id'],
                        'model_title' => $user['name'],
                        'changed' => [],
                    ]
                );
            }
        }
    }

    /**
     * generateUUID
     *
     * @return void
     */
    public function generateUUID()
    {
        $uuid = Text::uuid();

        return $this->RestResponse->viewData(['uuid' => $uuid], 'json');
    }

    /**
     * queryACL
     *
     * @return void
     */
    public function queryACL()
    {
        return $this->RestResponse->viewData($this->ACL->findMissingFunctionNames());
    }

    /**
     * getRoleAccess
     *
     * @return void
     */
    public function getRoleAccess()
    {
        return $this->RestResponse->viewData($this->ACL->getRoleAccess(false, false));
    }

    /**
     * arrayToValuesIndexArray - Convert an array to the same array but with the values also as index instead of an interface_exists
     *
     * @param  array $oldArray the original array
     * @return array
     */
    protected function arrayToValuesIndexArray(array $oldArray): array
    {
        $newArray = [];
        foreach ($oldArray as $value) {
            $newArray[$value] = $value;
        }

        return $newArray;
    }

    /**
     * isSiteAdmin
     * checks if the currently logged user is a site administrator (an admin that can manage any user or event on the instance and create / edit the roles).
     *
     * @return bool
     */
    protected function isSiteAdmin(): bool
    {
        $user = $this->ACL->getUser();

        if (empty($user)) {
            return false;
        }

        return $user->Role->perm_site_admin;
    }

    /**
     * Close session without writing changes to them and return current user.
     *
     * @return array
     */
    protected function closeSession()
    {
        $user = $this->ACL->getUser();
        session_abort();

        return $user->toArray();
    }

    /**
     * generic function to standardise on the collection of parameters. Accepts posted request objects, url params, named url params
     *
     * @param array $options options
     * @param mixed $exception exception
     * @param array $data data
     * @return array|false
     */
    protected function harvestParameters($options, &$exception = null, $data = [])
    {
        $request = $options['request'] ?? $this->request;
        if ($request->is('post')) {
            if (!empty($request->data)) {
                if (isset($request->data['request'])) {
                    $temp = $request->data['request'];
                } else {
                    $temp = $request->data;
                }
                if (empty($options['paramArray'])) {
                    foreach ($options['paramArray'] as $param => $value) {
                        $data = $this->captureParam($data, $param, $value);
                    }
                    $data = array_merge($data, $temp);
                } else {
                    foreach ($options['paramArray'] as $param) {
                        if (isset($temp[$param])) {
                            $data[$param] = $temp[$param];
                        }
                    }
                }
            } elseif (empty($request->data) && !$this->ParamHandler->isRest()) {
                $exception = $this->RestResponse->throwException(
                    400,
                    __('Either specify the search terms in the url, or POST a json with the filter parameters.'),
                    '/' . $request->params['controller'] . '/' . $request->action
                );

                return false;
            }
        }
        /*
         * If we simply capture ordered URL params with func_get_args(), reassociate them.
         * We can easily detect this by having ordered_url_params passed as a list instead of a dict.
         */
        if (isset($options['ordered_url_params'][0])) {
            $temp = [];
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
                    (!in_array(strtolower((string)$options['ordered_url_params'][$p]), ['null', '0', false, 'false', null]))
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
                $options['additional_delimiters'] = [$options['additional_delimiters']];
            }
            foreach ($data as $k => $v) {
                $found = false;
                foreach ($options['additional_delimiters'] as $delim) {
                    if (strpos($v, $delim) !== false) {
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

    /**
     * captureParam
     *
     * @param  mixed $data data
     * @param  mixed $param param
     * @param  mixed $value value
     * @return mixed
     */
    private function captureParam($data, $param, $value)
    {
        $table = $this->getTableLocator()->get($this->defaultModel);
        if ($table->checkParam($param)) {
            $data[$param] = $value;
        }

        return $data;
    }

    /**
     * Decode JSON with proper error handling.
     *
     * @param string $dataToDecode data to decode
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
     * setResponseType
     *
     * @return static|void
     */
    private function setResponseType()
    {
        foreach ($this->request->getHeader('Accept') as $accept) {
            if (strpos($accept, 'application/json') !== false) {
                return $this->response->withType('json');
            }
        }
    }

    /**
     * @return string|null
     */
    protected function _remoteIp()
    {
        $ipHeader = Configure::read('MISP.log_client_ip_header') ?: 'REMOTE_ADDR';

        return isset($_SERVER[$ipHeader]) ? trim($_SERVER[$ipHeader]) : $_SERVER['REMOTE_ADDR'];
    }

    /**
     * @param array $user affected user
     * @throws \Exception
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
            (Configure::read('MISP.log_paranoid_api') && isset($user['logged_by_authkey']) && $user['logged_by_authkey']);

        if ($shouldBeLogged) {
            $includeRequestBody = !empty(Configure::read('MISP.log_paranoid_include_post_body')) || $userMonitoringEnabled;
            /** @var \App\Model\Entity\AccessLog $accessLog */
            $accessLogsTable = $this->fetchTable('AccessLogs');
            $accessLogsTable->logRequest($user, $this->_remoteIp(), $this->request, $includeRequestBody);
        }

        if (
            empty(Configure::read('MISP.log_skip_access_logs_in_application_logs')) &&
            $shouldBeLogged
        ) {
            $change = 'HTTP method: ' . $_SERVER['REQUEST_METHOD'] . PHP_EOL . 'Target: ' . $this->request->getAttribute('here');

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
                $payload = $this->request->getBody();
                $change .= PHP_EOL . 'Request body: ' . $payload;
            }
            $logsTable = $this->fetchTable('Logs');
            $logsTable->createLogEntry($user, 'request', 'User', $user['id'], 'Paranoid log entry', $change);
        }
    }

    /**
     * Convert an array to the same array but with the values also as index instead of an interface_exists
     */
    protected function _arrayToValuesIndexArray($oldArray)
    {
        $newArray = [];
        foreach ($oldArray as $value) {
            $newArray[$value] = $value;
        }
        return $newArray;
    }

    protected function _legacyAPIRemap($options = [])
    {
        $ordered_url_params = [];
        foreach ($options['paramArray'] as $k => $param) {
            if (isset($options['ordered_url_params'][$k])) {
                $ordered_url_params[$param] = $options['ordered_url_params'][$k];
            } else {
                $ordered_url_params[$param] = false;
            }
        }
        $filterData = [
            'request' => $options['request'],
            'named_params' => $options['named_params'],
            'paramArray' => $options['paramArray'],
            'ordered_url_params' => $ordered_url_params
        ];
        $exception = false;
        $filters = $this->harvestParameters($filterData, $exception);
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
        if (!isset($this->RestSearch->paramArray[$scope])) {
            throw new NotFoundException(__('RestSearch is not implemented (yet) for this scope.'));
        }

        $modelName = $scope === 'Object' ? 'MispObject' : $scope;
        if (!isset($this->$modelName)) {
            $this->loadModel($modelName);
        }
        /** @var AppModel $model */
        $model = $this->$modelName;

        $filterData = [
            'request' => $this->request,
            'named_params' => $this->request->getParam('named'),
            'paramArray' => $this->RestSearch->paramArray[$scope],
            'ordered_url_params' => func_get_args()
        ];
        $exception = false;
        $filters = $this->harvestParameters($filterData, $exception, $this->_legacyParams);
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
        $key = empty($filters['key']) ? $filters['returnFormat'] : $filters['key'];
        $user = $this->_getApiAuthUser($key, $exception);
        if ($user === false) {
            return $exception;
        }

        session_write_close(); // Rest search can be longer, so close session to allow concurrent requests

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
                return $this->RestResponse->viewData(
                    '',
                    $responseType,
                    false,
                    true,
                    $filename,
                    [
                        'X-Result-Count' => 0,
                        'X-Export-Module-Used' => $returnFormat,
                        'X-Response-Format' => $responseType
                    ]
                );
            }
        }
        /** @var TmpFileTool $final */
        $final = $model->restSearch($user, $returnFormat, $filters, false, false, $elementCounter, $renderView);
        if ($renderView) {
            $this->layout = false;
            $final = JsonTool::decode($final->intoString());
            $this->set($final);
            $this->render('/Events/module_views/' . $renderView);
        } else {
            $filename = $this->RestSearch->getFilename($filters, $scope, $responseType);
            $headers = ['X-Result-Count' => $elementCounter, 'X-Export-Module-Used' => $returnFormat, 'X-Response-Format' => $responseType];
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

    protected function _getApiAuthUser($key, &$exception)
    {
        if (strlen($key) === 40) {
            // check if the key is valid -> search for users based on key
            $user = $this->_checkAuthUser($key);
            if (!$user) {
                $exception = $this->RestResponse->throwException(
                    401,
                    __('This authentication key is not authorized to be used for exports. Contact your administrator.')
                );
                return false;
            }
        } else {
            $user = $this->Auth->user();
            if (!$user) {
                $exception = $this->RestResponse->throwException(
                    401,
                    __('You have to be logged in to do that.')
                );
                return false;
            }
        }
        return $user;
    }

    protected function _checkAuthUser($authkey)
    {
        $UsersTable = $this->fetchTable('Users');
        if (Configure::read('Security.advanced_authkeys')) {
            $user = $UsersTable->AuthKeys->getAuthUserByAuthKey($authkey);
        } else {
            $user = $UsersTable->getAuthUserByAuthKey($authkey);
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

    /**
     * Returns true if user can publish the given event.
     *
     * @param Event $event
     * @param array|null $user If empty, currently logged user will be used
     * @return bool
     */
    protected function canPublishEvent(Event $event, $user = null)
    {
        $user = $user ?: $this->ACL->getUser();
        return $this->ACL->canPublishEvent($user, $event->toArray());
    }

    /**
     * Returns true if user can modify given event.
     *
     * @param Event $event
     * @param array|null $user If empty, currently logged user will be used
     * @return bool
     */
    protected function canModifyEvent(Event $event, $user = null)
    {
        $user = $user ?: $this->ACL->getUser();
        return $this->ACL->canModifyEvent($user, $event->toArray());
    }
}
