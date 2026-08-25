<?php
App::uses('AppController', 'Controller');

class TaxiiServersController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public function beforeFilter()
    {
        // No need for CSRF tokens for a search
        if ('getRoot' == $this->request->params['action'] || 'getCollections' == $this->request->params['action']) {
            $this->Security->csrfCheck = false;
        }
        if ($this->request->params['action'] === 'add' || $this->request->params['action'] === 'edit') {
            $this->Security->unlockedFields = ['api_root', 'collection'];
        }
        parent::beforeFilter();
    }

    public $paginate = array(
            'limit' => 60,
            'maxLimit' => 9999
    );

    public function index()
    {
        $params = [
            'filters' => ['name', 'url', 'uuid'],
            'quickFilters' => ['name']
        ];
        $this->CRUD->index($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('menuData', array('menuList' => 'sync', 'menuItem' => 'list_taxii'));
    }

    public function add()
    {
        $params = [];
        $this->CRUD->add($params);
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }
        $dropdownData = [];
        if($this->theme === "Overmind"){
            $this->layout = false;
        }
        $this->set(compact('dropdownData'));
        $this->set('menuData', array('menuList' => 'sync', 'menuItem' => 'add_taxii'));
    }

    public function edit($id)
    {
        $this->set('menuData', array('menuList' => 'sync', 'menuItem' => 'edit_taxii'));
        $this->set('id', $id);
        $params = [];
        $this->CRUD->edit($id, $params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $dropdownData = [];
        if($this->theme === "Overmind"){
            $this->layout = false;
        }
        $this->set(compact('dropdownData'));
        $this->render('add');
    }

    public function delete($id)
    {
        $this->CRUD->delete($id);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }

    public function deleteSelection($id = null)
    {
        return $this->CRUD->deleteSelection($id, [
            'modelName' => 'TaxiiServer',
            'restName' => 'TaxiiServers',
            'itemName' => 'TaxiiServer',
            'view' => 'ajax/taxiiServerDeleteConfirmationForm',
            'checkModifyCallback' => function($itemId) {
                return $this->userRole['perm_site_admin'];
            },
            'multiSuccessMessageCallback' => function($count) {
                return __n('%s taxiiServer deleted.', '%s taxiiServers deleted.', $count, $count);
            }
        ]);
    }

    public function view($id)
    {
        $this->set('menuData', ['menuList' => 'sync', 'menuItem' => 'view_taxii']);
        $this->CRUD->view($id);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('id', $id);
    }

    public function push($id)
    {
        $this->set('menuData', ['menuList' => 'sync', 'menuItem' => 'push_taxii']);
        $taxii_server = $this->TaxiiServer->find('first', [
            'recursive' => -1,
            'conditions' => ['TaxiiServer.id' => $id]
        ]);
        if (empty($taxii_server)) {
            throw new NotFoundException(__('Invalid Taxii Server ID provided.'));
        }
        if (empty($taxii_server['TaxiiServer']['enabled'])) {
            throw new MethodNotAllowedException(__('TAXII server is disabled.'));
        }

        if ($this->request->is('post')) {
            $result = $this->TaxiiServer->pushRouter($taxii_server['TaxiiServer']['id'], $this->Auth->user());
            $message = __('Taxii push initiated.');
            if ($this->_isRest()) {
                return $this->RestResponse->saveSuccessResponse('TaxiiServers', 'push', $id, false, $message);
            } else {
                $this->Flash->success($message);
                $this->redirect($this->referer());
            }
        } else {
            $this->set('id', $taxii_server['TaxiiServer']['id']);
            $this->set('title', __('Push data to TAXII server'));
            $this->set('question', __('Are you sure you want to Push data as configured in the filters to the TAXII server?'));
            $this->set('actionName', __('Push'));
            $this->layout = 'ajax';
            if($this->theme === "Overmind"){
                $this->render('ajax/taxiiServerPushConfirmationForm');
            } else {
                $this->render('/genericTemplates/confirm');
            }
        }
    }

    public function getRoot()
    {
        if (empty($this->request->data['discovery_url'])) {
            return $this->RestResponse->saveFailResponse(
                'TaxiiServers', 'getRoot', null, __('No discovery url set.'), $this->response->type()
            );
        } else {
            $discovery_url = $this->request->data['discovery_url'];

            // 1. Strict Protocol Validation
            if (!preg_match('/^https?:\/\//i', $discovery_url)) {
                return $this->RestResponse->saveFailResponse(
                    'TaxiiServers', 'getRoot', null, __('Invalid URL scheme. Only HTTP and HTTPS are supported.'), $this->response->type()
                );
            }

            // 2. Host Resolution and Banned IP Checking (Loopback & Metadata)
            $host = parse_url($discovery_url, PHP_URL_HOST);
            if ($host) {
                $resolvedIp = gethostbyname($host);
                if (strpos($resolvedIp, '127.') === 0 || $resolvedIp === '169.254.169.254' || $resolvedIp === '0.0.0.0') {
                    throw new ForbiddenException(__('The provided discovery URL points to a restricted network block.'));
                }
            }

            App::uses('HttpSocket', 'Network/Http');
            $HttpSocket = new HttpSocket();
            $caPath = Configure::read('MISP.ca_path');
            if (!empty($caPath)) {
                $HttpSocket->config['ssl_cafile'] = $caPath;
            }
            if (!$this->request->data['skip_proxy']) {
                $proxy = Configure::read('Proxy');
                if (isset($proxy['host']) && !empty($proxy['host'])) {
                    $HttpSocket->configProxy($proxy['host'], $proxy['port'], $proxy['method'], $proxy['user'], $proxy['password']);
                }
            }
            $request = [
                'header' => [
                    'Accept' => 'application/taxii+json;version=2.1',
                    'Content-type' => 'application/taxii+json;version=2.1'
                ]
            ];
            $caPath = Configure::read('MISP.ca_path');
            if (!empty($caPath)) {
                $request['ssl_cafile'] = $caPath;
            }
            if (!empty($this->request->data['api_key']) || (!empty($this->request->data['auth_type']) && $this->request->data['auth_type'] === 'basic' && !empty($this->request->data['username']))) {
                $authMethod = 'Basic ';
                if (isset($this->request->data['auth_type']) && $this->request->data['auth_type'] === 'bearer') {
                    $authMethod = 'Bearer ';
                }

                $apiKey = $this->request->data['api_key'];
                if ($authMethod === 'Basic ' && !empty($this->request->data['username']) && !empty($this->request->data['password'])) {
                    $apiKey = base64_encode($this->request->data['username'] . ':' . $this->request->data['password']);
                }
                $request['header']['Authorization'] = $authMethod . $apiKey;
            }
            
            // 3. Unified Error Handling to prevent differential responses
            $genericError = __('TAXII connection failed or returned invalid data. Please verify the URL.');

            try {
                $response = $HttpSocket->get($this->request->data['discovery_url'], null, $request);
            } catch (SocketException $e) {
                // Log the real connection error internally, return generic error to user
                $this->log("TAXII connection error to " . $this->request->data['discovery_url'] . ": " . $e->getMessage(), 'error');
                return $this->RestResponse->saveFailResponse('TaxiiServers', 'getRoot', null, $genericError, $this->response->type());
            }

            if (!($response->isOk())) {
                $this->log("TAXII HTTP error to " . $this->request->data['discovery_url'] . ": Code " . $response->code, 'error');
                return $this->RestResponse->saveFailResponse('TaxiiServers', 'getRoot', null, $genericError, $this->response->type());
            }

            $result = json_decode($response->body, true);
            
            // Ensure valid JSON was parsed before proceeding
            if (is_array($result) && isset($result['api_roots'])) {
                $results = [];
                $discovery_host = parse_url($this->request->data['discovery_url'], PHP_URL_HOST);
                $discovery_port = parse_url($this->request->data['discovery_url'], PHP_URL_PORT);
                if (empty($discovery_port)) {
                    $discovery_host = 'https://' . $discovery_host;
                } else {
                    $discovery_root = 'https://' . $discovery_host . ':' . $discovery_port;
                }
                foreach ($result['api_roots'] as $api_root) {
                    if (str_starts_with($api_root, '/')) {
                        $api_root = $discovery_root . $api_root;
                    }
                    $results[$api_root] = $api_root;
                }
                return $this->RestResponse->viewData($results, 'json');
            } else {
                // Catch cases where an open port returns non-JSON data (e.g., HTML directory listings)
                $this->log("TAXII JSON parsing error from " . $this->request->data['discovery_url'], 'error');
                return $this->RestResponse->saveFailResponse('TaxiiServers', 'getRoot', null, $genericError, $this->response->type());
            }
        }
    }

    public function getCollections()
    {
        if (empty($this->request->data['api_root'])) {
            return $this->RestResponse->saveFailResponse(
                'TaxiiServers', 'getCollections', null, __('No api_root set.'), $this->response->type()
            );
        }
        $this->request->data['path'] = '/collections/';
        $result = $this->TaxiiServer->queryInstance(
            [
                'TaxiiServer' => $this->request->data,
                'type' => 'get'
            ]
        );
        if (is_array($result)) {
            $results = [];
            foreach ($result['collections'] as $collection) {
                if (!empty($collection['can_write'])) {
                    $versions = '';
                    if (!empty($collection['media_types'])) {
                        if (!is_array(($collection['media_types']))) {
                            $collection['media_types'] = [$collection['media_types']];
                        }
                        $versions = [];
                        foreach ($collection['media_types'] as $media_type) {
                            $media_type = explode('=', $media_type);
                            $media_type = end($media_type);
                            $versions[$media_type] = true;
                        }
                        $versions = implode(', ', array_keys($versions));
                    }
                    $text = (empty($versions) ? '' : '[' . $versions . '] ') . $collection['title'];
                    $results[$collection['id']] = $text;
                }
            }
            return $this->RestResponse->viewData($results, 'json');
        } else {
            return $this->RestResponse->saveFailResponse(
                'TaxiiServers', 'getCollections', null, $result, $this->response->type()
            );
        }
    }

    public function collectionsIndex($id)
    {
        $result = $this->TaxiiServer->getCollections($id);
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($result, $this->response->type());
        } else {
            App::uses('CustomPaginationTool', 'Tools');
            $customPagination = new CustomPaginationTool();
            $customPagination->truncateAndPaginate($result, $this->params, false, true);
            $this->set('data', $result);
            $this->set('id', $id);
            $this->set('menuData', array('menuList' => 'sync', 'menuItem' => 'list_taxii_collections'));
        }

    }

    public function objectsIndex($id, $collection_id, $next = null)
    {
        $result = $this->TaxiiServer->getObjects($id, $collection_id, $next);
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($result, $this->response->type());
        } else {
            $this->set('data', $result['objects']);
            $this->set('more', $result['more']);
            $this->set('next', isset($result['next']) ? $result['next'] : null);
            $this->set('id', $id);
            $this->set('collection_id', $collection_id);
            $this->set('menuData', array('menuList' => 'sync', 'menuItem' => 'list_taxii_collection_objects'));
        }
    }

    public function objectView($server_id, $collection_id, $id)
    {
        $result = $this->TaxiiServer->getObject($id, $server_id, $collection_id);
        $result = json_encode($result, JSON_PRETTY_PRINT);
        $this->layout = false;
        $this->set('title', h($id));
        $this->set('json', $result);
        if ($this->theme === "Overmind") {
            $this->render('object_view');
        } else {
            $this->render('/genericTemplates/display');
        }
    }
}
