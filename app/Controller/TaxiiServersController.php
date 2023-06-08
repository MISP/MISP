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

        if ($this->request->is('post')) {
            $result = $this->TaxiiServer->pushRouter($taxii_server['TaxiiServer']['id'],  $this->Auth->user());
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
            $this->render('/genericTemplates/confirm');
        }
    }

    public function getRoot()
    {
        if (empty($this->request->data['baseurl'])) {
            return $this->RestResponse->saveFailResponse(
                'TaxiiServers', 'getRoot', null, __('No baseurl set.'), $this->response->type()
            );
        } else {
            $this->request->data['uri'] = '/taxii2/';
            $result = $this->TaxiiServer->queryInstance(
                [
                    'TaxiiServer' => $this->request->data,
                    'type' => 'get'
                ]
            );
            if (is_array($result)) {
                $results = [];
                foreach ($result['api_roots'] as $api_root) {
                    $api_root = explode('/', trim($api_root, '/'));
                    $api_root = end($api_root);
                    $results[$api_root] = $this->request->data['baseurl'] . '/' . $api_root . '/';
                }
                return $this->RestResponse->viewData($results, 'json');
            } else {
                return $this->RestResponse->saveFailResponse(
                    'TaxiiServers', 'getRoot', null, $result, $this->response->type()
                );  
            }
        }
    }

    public function getCollections()
    {
        if (empty($this->request->data['baseurl'])) {
            return $this->RestResponse->saveFailResponse(
                'TaxiiServers', 'getCollections', null, __('No baseurl set.'), $this->response->type()
            );
        }
        if (empty($this->request->data['api_root'])) {
            return $this->RestResponse->saveFailResponse(
                'TaxiiServers', 'getCollections', null, __('No api_root set.'), $this->response->type()
            );
        }
        $this->request->data['uri'] = '/' . $this->request->data['api_root'] . '/collections/';
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
                'TaxiiServers', 'getRoot', null, $result, $this->response->type()
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
        $this->render('/genericTemplates/display');
    }
}
