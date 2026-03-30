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

    public function delete2($id = null)
    {
        if ($this->request->is(['post', 'put', 'delete'])) {
            if (isset($this->request->data['id'])) {
                $this->request->data['CollectionElement'] = $this->request->data;
            }
            if (!isset($id) && isset($this->request->data['CollectionElement']['id'])) {
                $idList = $this->request->data['CollectionElement']['id'];

                if (!is_array($idList)) {
                    if (is_numeric($idList) || Validation::uuid($idList)) {
                        $idList = array($idList);
                    } else {
                        $idList = $this->_jsonDecode($idList);
                    }
                }

                if (empty($idList)) {
                    throw new NotFoundException(__('Invalid input.'));
                }
            } else {
                $idList = array($id);
            }

            $successes = [];
            $fails = [];
            foreach ($idList as $cid) {
                $element = $this->CollectionElement->find('first', [
                    'conditions' => Validation::uuid($cid)
                        ? ['CollectionElement.uuid' => $cid]
                        : ['CollectionElement.id' => $cid],
                    'recursive' => -1,
                ]);
                if (empty($element)) {
                    $fails[] = $cid;
                    continue;
                }
                $elementId = $element['CollectionElement']['id'];
                $collectionId = $element['CollectionElement']['collection_id'];
                if (!$this->CollectionElement->Collection->mayModify($this->Auth->user('id'), $collectionId)) {
                    $fails[] = $cid;
                    continue;
                }
                if ($this->CollectionElement->delete($elementId)) {
                    $successes[] = $cid;
                } else {
                    $fails[] = $cid;
                }
            }
            if (count($idList) === 1) {
                $message = empty($successes)
                    ? __('Element was not deleted.')
                    : __('Element deleted.');
            } else {
                $message = '';
                if (!empty($successes)) {
                    $message .= __n(
                        '%s element deleted.',
                        '%s elements deleted.',
                        count($successes),
                        count($successes)
                    );
                }
                if (!empty($fails)) {
                    $message .= ' ' . count($fails) . ' element(s) could not be deleted due to insufficient privileges or not found.';
                }
            }
            if ($this->_isRest()) {
                if (!empty($successes)) {
                    return $this->RestResponse->saveSuccessResponse(
                        'CollectionElement',
                        'delete',
                        $id,
                        $this->response->type(),
                        $message
                    );
                } else {
                    return $this->RestResponse->saveFailResponse(
                        'CollectionElement',
                        'delete',
                        false,
                        $message,
                        $this->response->type()
                    );
                }
            }
            if (!empty($successes)) {
                $this->Flash->success($message);
            } else {
                $this->Flash->error($message);
            }
            return $this->redirect(array('controller' => 'collections', 'action' => 'view', $collectionId));
        } else {
            $elementList = is_numeric($id) ? [$id] : $this->_jsonDecode($id);
            $this->request->data['CollectionElement']['id'] = json_encode($elementList);
            $this->set('idArray', $elementList);
            $this->layout = false;
            $this->render('ajax/collectionElementsDeleteConfirmationForm');
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
