<?php

use PHPUnit\Framework\MockObject\InvalidMethodNameException;

App::uses('AppController', 'Controller');

class CollectionElementsController extends AppController
{

    public $components = ['Session', 'RequestHandler'];

    public function beforeFilter()
    {
        parent::beforeFilter();
        // Posted by hand-built AJAX from the collection pickers, which sends the
        // CSRF token as the X-CSRF-Token header instead of _Token fields.
        $this->_csrfTokenHeaderOnly(['addElementToCollection']);
    }

    public $paginate = [
        'limit' => 60,
        'order' => []
    ];

    public $uses = [
    ];

    private function __normaliseElementUuids($elementUuid)
    {
        if (is_array($elementUuid)) {
            $rawUuids = $elementUuid;
        } else {
            $rawUuids = [$elementUuid];
        }

        $uuids = [];
        foreach ($rawUuids as $uuid) {
            if (!is_scalar($uuid)) {
                continue;
            }
            $uuid = trim((string)$uuid);
            if ($uuid !== '') {
                $uuids[] = $uuid;
            }
        }

        return array_values(array_unique($uuids));
    }
    
    public function add($collection_id)
    {   
        $this->CollectionElement->Collection->current_user = $this->Auth->user();
        if (!$this->CollectionElement->Collection->mayModify($this->Auth->user('id'), intval($collection_id))) {
            throw new MethodNotAllowedException(__('Invalid Collection or insufficient privileges'));
        }
        $this->CRUD->add([
            'redirect' => ['controller' => 'collections', 'action' => 'view', $collection_id],
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
        if($this->theme === "Overmind"){
            $this->layout = false;
        }
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
            throw new MethodNotAllowedException(__('Invalid Collection or insufficient privileges'));
        }
        $this->CRUD->delete($element_id, [
            'redirect' => ['controller' => 'collections', 'action' => 'view', $collection_id]
        ]);
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }
    }

    public function deleteSelection($id = null)
    {
        return $this->CRUD->deleteSelection($id, [
            'modelName' => 'CollectionElement',
            'restName' => 'CollectionElements',
            'itemName' => 'element',
            'view' => 'ajax/collectionElementsDeleteConfirmationForm',
            'checkModifyCallback' => function($itemId, $item) {
                // DPT-3: authorise against the element's OWN collection,
                // not a collection whose id happens to equal the element
                // id. mayModify() expects a collection_id, but $itemId is
                // the element id - the bare call gated on the wrong entity,
                // allowing cross-collection / cross-org element deletion.
                // Mirror the single delete() action, using the loaded row.
                $collectionId = $item['CollectionElement']['collection_id'];
                return $this->CollectionElement->Collection->mayModify($this->Auth->user('id'), $collectionId);
            },
            'multiSuccessMessageCallback' => function($count) {
                return __n('%s element deleted.', '%s elements deleted.', $count, $count);
            }
        ]);
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
            $elementUuids = $this->__normaliseElementUuids($this->request->data['CollectionElement']['element_uuid'] ?? $element_uuid);
            if (empty($elementUuids)) {
                throw new NotFoundException(__('No element UUID specified.'));
            }
            if ($element_type === 'Event') {
                $this->loadModel('Event');
                foreach ($elementUuids as $currentElementUuid) {
                    $event = $this->Event->fetchSimpleEvent($this->Auth->user(), $currentElementUuid, [
                        'fields' => ['Event.id']
                    ]);
                    if (empty($event)) {
                        throw new NotFoundException(__('Invalid event or not authorized.'));
                    }
                }
            }

            $result = true;
            $duplicateCount = 0;
            $error = '';
            foreach ($elementUuids as $currentElementUuid) {
                $dataToSave = [
                    'CollectionElement' => [
                        'element_uuid' => $currentElementUuid,
                        'element_type' => $element_type,
                        'description' => $description,
                        'collection_id' => $collection_id
                    ]
                ];
                $this->CollectionElement->create();
                try {
                    $saveResult = $this->CollectionElement->save($dataToSave);
                    if (!$saveResult) {
                        $result = false;
                        break;
                    }
                } catch (PDOException $e) {
                    if (!empty($e->errorInfo[0]) && $e->errorInfo[0] == 23000) {
                        $duplicateCount++;
                    } else {
                        throw $e;
                    }
                }
            }
            if ($duplicateCount > 0) {
                $error = ' ' . __n('%s selected event was already in the Collection.', '%s selected events were already in the Collection.', $duplicateCount, $duplicateCount);
            }
            
            if ($result) {
                $message = count($elementUuids) > 1
                    ? __n('%s event added to the Collection.', '%s events added to the Collection.', count($elementUuids), count($elementUuids))
                    : __('Element added to the Collection.');
                if ($duplicateCount > 0) {
                    $message .= $error;
                }
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
