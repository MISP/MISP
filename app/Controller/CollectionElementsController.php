<?php

use PHPUnit\Framework\MockObject\InvalidMethodNameException;

App::uses('AppController', 'Controller');

class CollectionElementsController extends AppController
{

    public $components = ['Session', 'RequestHandler'];

    public $paginate = [
        'limit' => 60,
        'order' => []
    ];

    public $uses = [
    ];
    
    public function add($collection_id)
    {   
        $this->CollectionElement->Collection->current_user = $this->Auth->user();
        if (!$this->CollectionElement->Collection->mayModify($this->Auth->user('id'), intval($collection_id))) {
            throw new MethodNotAllowedException(__('Invalid Collection or insuficient privileges'));
        }
        $this->CRUD->add([
            'beforeSave' => function (array $collectionElement) use ($collection_id) {
                $collectionElement['CollectionElement']['collection_id'] = intval($collection_id);
                return $collectionElement;
            }
        ]);
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }
        $dropdownData = [
            'types' => array_combine($this->CollectionElement->valid_types, $this->CollectionElement->valid_types)
        ];
        $this->set(compact('dropdownData'));
        $this->set('menuData', array('menuList' => 'collections', 'menuItem' => 'add_element'));
    }

    public function delete($element_id)
    {
        $collectionElement = $this->CollectionElement->find('first', [
            'recursive' => -1,
            'conditions' => [
                'CollectionElement.id' => $element_id
            ]
        ]);
        $collection_id = $collectionElement['CollectionElement']['collection_id'];
        if (!$this->CollectionElement->Collection->mayModify($this->Auth->user('id'), $collection_id)) {
            throw new MethodNotAllowedException(__('Invalid Collection or insuficient privileges'));
        }
        $this->CRUD->delete($element_id);
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }
    }

    public function index($collection_id)
    {
        $this->set('menuData', array('menuList' => 'collections', 'menuItem' => 'index'));
        if (!$this->CollectionElement->Collection->mayView($this->Auth->user('id'), intval($collection_id))) {
            throw new NotFoundException(__('Invalid collection or no access.'));
        }
        $params = [
            'filters' => ['uuid', 'type', 'name'],
            'quickFilters' => ['name'],
            'conditions' => ['collection_id' => $collection_id]
        ];
        $this->loadModel('Event');
        $this->set('distributionLevels', $this->Event->distributionLevels);
        $this->CRUD->index($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }

    public function addElementToCollection($element_type, $element_uuid)
    {
        if ($this->request->is('get')) {
            $validCollections = $this->CollectionElement->Collection->find('list', [
                'recursive' => -1,
                'fields' => ['Collection.id', 'Collection.name'],
                'conditions' => ['Collection.orgc_id' => $this->Auth->user('org_id')]
            ]);
            if (empty($validCollections)) {
                if ($this->request->is('ajax')) {
                    return $this->redirect(['controller' => 'collections', 'action' => 'add']);
                }
                throw new NotFoundException(__('You don\'t have any collections yet. Make sure you create one first before you can start adding elements.'));
            }
            $dropdownData = [
                'collections' => $validCollections
            ];
            $this->set(compact('dropdownData'));
        } else if ($this->request->is('post')) {
            if (!isset($this->request->data['CollectionElement'])) {
                $this->request->data = ['CollectionElement' => $this->request->data];
            }
            if (!isset($this->request->data['CollectionElement']['collection_id'])) {
                throw new NotFoundException(__('No collection_id specified.'));
            }
            $collection_id = intval($this->request->data['CollectionElement']['collection_id']);
            if (!$this->CollectionElement->Collection->mayModify($this->Auth->user('id'), $collection_id)) {
                throw new NotFoundException(__('Invalid collection or not authorized.'));
            }
            $description = empty($this->request->data['CollectionElement']['description']) ? '' : $this->request->data['CollectionElement']['description'];
            $dataToSave = [
                'CollectionElement' => [
                    'element_uuid' => $element_uuid,
                    'element_type' => $element_type,
                    'description' => $description,
                    'collection_id' => $collection_id
                ]
            ];
            $this->CollectionElement->create();
            $error = '';
            try {
                $result = $this->CollectionElement->save($dataToSave);
            } catch (PDOException $e) {
                if ($e->errorInfo[0] == 23000) {
                    $error = __(' Element already in Collection.');
                }
            }
            
            if ($result) {
                $message = __('Element added to the Collection.');
                if ($this->IndexFilter->isRest()) {
                    return $this->RestResponse->saveSuccessResponse('CollectionElements', 'addElementToCollection', false, $this->response->type(), $message);
                } else {
                    $this->Flash->success($message);
                    $this->redirect(Router::url($this->referer(), true));
                }
            } else {
                $message = __('Element could not be added to the Collection.%s', $error);
                if ($this->IndexFilter->isRest()) {
                    return $this->RestResponse->saveFailResponse('CollectionElements', 'addElementToCollection', false, $message, $this->response->type());
                } else {
                    $this->Flash->error($message);
                    $this->redirect(Router::url($this->referer(), true));
                }
            }
        }
    }
}
