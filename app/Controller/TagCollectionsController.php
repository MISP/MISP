<?php

App::uses('AppController', 'Controller');

class TagCollectionsController extends AppController
{
    public $components = array(
        'Security',
        'AdminCrud'
    );

    public $paginate = array(
            'limit' => 60,
            'order' => array(
                    'TagCollection.name' => 'ASC'
            ),
            'recursive' => -1,
            'contain' => array('TagCollectionTag' => array('Tag'))
    );

    public function add()
    {
        if ($this->request->is('post')) {
            $this->TagCollection->create();
            if (!isset($this->request->data['TagCollection'])) {
                $this->request->data = array('TagCollection' => $this->request->data);
            }
            $this->request->data['TagCollection']['org_id'] = $this->Auth->user('org_id');
            $this->request->data['TagCollection']['user_id'] = $this->Auth->user('id');
            if ($this->TagCollection->save($this->request->data)) {
                if ($this->_isRest()) {
                    $tagCollection = $this->TagCollection->find('first', array(
                        'recursive' => -1,
                        'conditions' => array('TagCollection.id' => $this->TagCollection->id)
                    ));
                    return $this->RestResponse->viewData($tagCollection, $this->response->type());
                } else {
                    $this->Flash->success(__('The tag collection has been saved'));
                    $this->redirect(array('action' => 'index'));
                }
            } else {
                $message = json_encode($this->TagCollection->validationErrors);
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('TagCollection', 'add', false, $message, $this->response->type());
                } else {
                    $this->Flash->error(__('The tag collection could not be added. Reason: ') . $message);
                }
            }
        } elseif ($this->_isRest()) {
            return $this->RestResponse->describe('TagCollection', 'add', false, $this->response->type());
        }
        $this->set('action', 'add');
    }

    public function view()
    {

    }

    public function edit($id)
    {
        $this->TagCollection->id = $id;
        if (!$this->TagCollection->exists()) {
            throw new NotFoundException(__('Invalid Tag Collection'));
        }
        $tagCollection = $this->TagCollection->find('first', array(
            'conditions' => array('TagCollection.id' => $id),
            'recursive' => -1
        ));
        if (!$this->_isSiteAdmin() && $tagCollection['TagCollection']['org_id'] !== $this->Auth->user('org_id')) {
            throw new MethodNotAllowedException(__('You don\'t have editing rights on this Tag Collection.'));
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            if (!isset($this->request->data['TagCollection'])) {
                $this->request->data = array('TagCollection' => $this->request->data);
            }
            $this->request->data['TagCollection']['id'] = $tagCollection['TagCollection']['id'];
            $this->request->data['TagCollection']['uuid'] = $tagCollection['TagCollection']['uuid'];
            if ($this->TagCollection->save($this->request->data)) {
                if ($this->_isRest()) {
                    $tagCollection = $this->TagCollection->find('first', array(
                        'recursive' => -1,
                        'conditions' => array('TagCollection.id' => $this->TagCollection->id)
                    ));
                    return $this->RestResponse->viewData($tagCollection, $this->response->type());
                } else {
                    $this->Flash->success(__('The tag collection has been saved'));
                    $this->redirect(array('action' => 'index'));
                }
            } else {
                $message = json_encode($this->TagCollection->validationErrors);
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('TagCollection', 'add', false, $message, $this->response->type());
                } else {
                    $this->Flash->error(__('The tag collection could not be added. Reason: ') . $message);
                }
            }
        } elseif ($this->_isRest()) {
            return $this->RestResponse->describe('TagCollection', 'add', false, $this->response->type());
        } else {
            $this->request->data = $tagCollection;
        }
        $this->set('action', 'edit');
        $this->render('add');
    }

    public function delete()
    {

    }

    public function addTag($id = false, $tag_id = false)
    {
        if (!$this->request->is('post')) {
            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'You don\'t have permission to do that.')), 'status'=>200, 'type' => 'json'));
        }
        $rearrangeRules = array(
                'request' => false,
                'TagCollection' => false,
                'tag_id' => 'tag',
                'tag_collection_id' => 'tag_collection',
                'id' => 'tag_collection'
        );
        $RearrangeTool = new RequestRearrangeTool();
        $this->request->data = $RearrangeTool->rearrangeArray($this->request->data, $rearrangeRules);
        if ($id === false) {
            $id = $this->request->data['tag_collection'];
        }
        if ($tag_id === false) {
            $tag_id = $this->request->data['tag'];
        }
        $conditions = array('LOWER(Tag.name) LIKE' => strtolower(trim($tag_id)));
        if (!$this->_isSiteAdmin()) {
            $conditions['Tag.org_id'] = array('0', $this->Auth->user('org_id'));
            $conditions['Tag.user_id'] = array('0', $this->Auth->user('id'));
        }
        if (!is_numeric($tag_id)) {
            $tag = $this->TagCollection->Tag->find('first', array('recursive' => -1, 'conditions' => $conditions));
            if (empty($tag)) {
                return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid Tag.')), 'status'=>200, 'type' => 'json'));
            }
            $tag_id = $tag['Tag']['id'];
        }
        $tagCollection = $this->TagCollection->find('first', array(
            'recursive' => -1,
            'conditions' => array('TagCollection.id' => $id)
        ));
        if (empty($tagCollection)) {
            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid tag collection.')), 'status'=>200, 'type' => 'json'));
        }
        if (!$this->_isSiteAdmin()) {
            if (!$this->userRole['perm_tagger'] || ($this->Auth->user('org_id') !== $tag_collection['TagCollection']['org_id'])) {
                return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'You don\'t have permission to do that.')), 'status'=>200, 'type' => 'json'));
            }
        }
        $this->TagCollection->TagCollectionTag->Tag->id = $tag_id;
        if (!$this->TagCollection->TagCollectionTag->Tag->exists()) {
            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid Tag.')), 'status'=>200, 'type' => 'json'));
        }
        $tag = $this->TagCollection->TagCollectionTag->Tag->find('first', array(
            'conditions' => array('Tag.id' => $tag_id),
            'recursive' => -1,
            'fields' => array('Tag.name')
        ));
        $found = $this->TagCollection->TagCollectionTag->find('first', array(
            'conditions' => array(
                'tag_collection_id' => $id,
                'tag_id' => $tag_id
            ),
            'recursive' => -1,
        ));
        $this->autoRender = false;
        if (!empty($found)) {
            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Tag is already attached to this collection.')), 'status'=>200, 'type' => 'json'));
        }
        $this->TagCollection->TagCollectionTag->create();
        if ($this->TagCollection->TagCollectionTag->save(array('tag_collection_id' => $id, 'tag_id' => $tag_id))) {
            $log = ClassRegistry::init('Log');
            $log->createLogEntry($this->Auth->user(), 'tag', 'TagCollection', $id, 'Attached tag (' . $tag_id . ') "' . $tag['Tag']['name'] . '" to collection (' . $id . ')', 'Event (' . $id . ') tagged as Tag (' . $tag_id . ')');
            return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Tag added.')), 'status'=>200, 'type' => 'json'));
        } else {
            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Tag could not be added.')), 'status'=>200, 'type' => 'json'));
        }
    }

    public function removeTag($id = false, $tag_id = false)
    {
        if (!$this->request->is('post')) {
            $this->set('id', $id);
            $this->set('tag_id', $tag_id);
            $this->set('model', 'tag_collection');
            $this->layout = 'ajax';
            $this->render('/Attributes/ajax/tagRemoveConfirmation');
        } else {
            $rearrangeRules = array(
                'request' => false,
                'TagCollection' => false,
                'tag_id' => 'tag',
                'tag_collection_id' => 'tag_collection',
                'id' => 'tag_collection'
            );
            $RearrangeTool = new RequestRearrangeTool();
            $this->request->data = $RearrangeTool->rearrangeArray($this->request->data, $rearrangeRules);
            if ($id === false) {
                $id = $this->request->data['tag_collection'];
            }
            if ($tag_id === false) {
                $tag_id = $this->request->data['tag'];
            }
            $tagCollection = $this->TagCollection->find('first', array(
                'recursive' => -1,
                'conditions' => array(
                    'TagCollection.id' => $id
                ),
                'contain' => array(
                    'TagCollectionTag' => array(
                        'Tag'
                    )
                )
            ));
            if (empty($tagCollection)) {
                return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => __('Invalid tag collection.'))), 'status' => 200, 'type' => 'json'));
            }
            $found = false;
            if (!$this->_isSiteAdmin() && $this->Auth->user('org_id') !== $tagCollection['TagCollection']['org_id']) {
                return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => __('Insufficient privileges to remove the tag from the collection.'))), 'status' => 200, 'type' => 'json'));
            }
            foreach ($tagCollection['TagCollectionTag'] as $TagCollectionTag) {
                if ((is_numeric($tag_id) && $TagCollectionTag['Tag']['id'] == $tag_id) || $TagCollectionTag['Tag']['name'] === $tag_id) {
                    $found = true;
                    $tag = $TagCollectionTag;
                    $result = $this->TagCollection->TagCollectionTag->delete($TagCollectionTag['id']);
                    break;
                }
            }
            if (!$found) {
                return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => __('Invalid tag or tag not associated with the collection.'))), 'status' => 200, 'type' => 'json'));
            }

            if (!$result) {
                return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => __('Failed to remove tag from the collection.'))), 'status' => 200, 'type' => 'json'));
            }
            $log = ClassRegistry::init('Log');
            $log->createLogEntry($this->Auth->user(), 'tag', 'TagCollection', $id, 'Removed tag (' . $tag['Tag']['id'] . ') "' . $tag['Tag']['name'] . '" from tag collection (' . $id . ')', 'Tag collection (' . $id . ') - untagged Tag (' . $tag_id . ')');
            return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Tag removed.')), 'status' => 200));
        }
    }

    public function index()
    {
        $list = $this->paginate();
        $this->loadModel('Event');
        foreach ($list as $k => $tag_collection) {
            $list[$k] = $this->Event->massageTags($tag_collection, $dataType = 'TagCollection');
        }

        $this->set('list', $list);
    }

    public function getRow($id)
    {
        $params = array(
            'recursive' => -1,
            'contain' => array('TagCollectionTag' => array('Tag')),
            'conditions' => array('TagCollection.id' => $id)
        );
        $item = $this->TagCollection->find('first', $params);
        if (empty($item)) {
            throw new NotFoundException('Invalid tag collection.');
        }
        $this->set('item', $item);
        $this->layout = false;
    }
}
