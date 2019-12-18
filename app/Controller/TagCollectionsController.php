<?php

App::uses('AppController', 'Controller');

class TagCollectionsController extends AppController
{
    public $components = array(
        'Security',
        'AdminCrud',
        'RequestHandler'
    );

    public $paginate = array(
            'limit' => 60,
            'order' => array(
                    'TagCollection.name' => 'ASC'
            ),
            'recursive' => -1,
            'contain' => array(
                'TagCollectionTag' => array(
                    'Tag'
                ),
                'Organisation' => array(
                    'fields' => array(
                        'Organisation.id',
                        'Organisation.name',
                        'Organisation.uuid'
                    )
                ),
                'User' => array(
                    'fields' => array(
                        'User.email',
                        'User.id'
                    )
                )
            )
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

    public function import()
    {
        if ($this->request->is('post')) {
            if (isset($this->request->data['TagCollection']['json'])) {
                $data = json_decode($this->request->data['TagCollection']['json'], true);
            } else {
                $data = $this->request->data;
            }
            $results = $this->TagCollection->import($data, $this->Auth->user());
            if ($results['successes'] > 0) {
                $flashType = 'success';
                $message = sprintf(
                    __('%s new tag collections added.'),
                    $results['successes']
                );
            } else {
                $flashType = 'info';
                $message = 'No new tag_collections to add.';
            }
            if ($results['fails']) {
                $message .= sprintf(
                    ' %s tag collections could not be added (possibly because they already exist)',
                    $results['fails']
                );
            }
            if ($this->_isRest()) {
                return $this->RestResponse->saveSuccessResponse('TagCollections', 'import', false, $this->response->type(), $message);
            } else {
                $this->Flash->{$flashType}($message);
                $this->redirect(array('action' => 'index'));
            }
        }
    }

    public function view($id)
    {
        $conditions = array();
        if (!$this->_isSiteAdmin()) {
            $conditions = array(
                'OR' => array(
                    'TagCollection.all_orgs' => 1,
                    'TagCollection.org_id' => $this->Auth->user('org_id')
                )
            );
            $this->paginate['conditions'] = $conditions;
        }
        $conditions['TagCollection.id'] = $id;
        $params = array(
            'recursive' => -1,
            'contain' => array('TagCollectionTag' => array('Tag'), 'Organisation' => array('fields' => array('id', 'name', 'uuid')), 'User' => array('fields' => array('User.id', 'User.email')))
        );
        if (!empty($conditions)) {
            $params['conditions'] = $conditions;
        }
        $collection = $this->TagCollection->find('first', $params);
        if (empty($collection)) {
            throw new NotFoundException('Invalid Tag Collection');
        }
        $collection = $this->TagCollection->cullBlockedTags($this->Auth->user(), $collection);
        $this->loadModel('Event');
        $collection = $this->Event->massageTags($collection, 'TagCollection', false, true);
        if (!$this->_isSiteAdmin() && $collection['TagCollection']['org_id'] !== $this->Auth->user('org_id')) {
            unset($collection['User']);
            unset($collection['TagCollection']['user_id']);
        }
        if (!empty($collection['TagCollectionTag'])) {
            foreach ($collection['TagCollectionTag'] as $k => $tct) {
                $collection['TagCollectionTag'][$k]['Tag'] = array(
                    'id' => $tct['Tag']['id'],
                    'name' => $tct['Tag']['name'],
                    'colour' => $tct['Tag']['colour']
                );
            }
        }
        return $this->RestResponse->viewData($collection, $this->response->type());
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

    public function delete($id)
    {
        $tagCollection = $this->TagCollection->fetchTagCollection($this->Auth->user(), array('conditions' => array('TagCollection.id' => $id)));
        if (empty($tagCollection)) {
            throw new NotFoundException(__('Invalid tag collection.'));
        }
        $tagCollection = $tagCollection[0];
        if ($this->TagCollection->checkAccess($this->Auth->user(), $tagCollection, 'write')) {
            $result = $this->TagCollection->delete($id);
            if ($result) {
                $message = __('Tag collection deleted.');
                if ($this->_isRest()) {
                    return $this->RestResponse->saveSuccessResponse('TagCollections', 'delete', false, $this->response->type(), $message);
                } else {
                    $this->Flash->success($message);
                    $this->redirect(array('action' => 'index'));
                }
            } else {
                $message = __('Tag collection could not be deleted.');
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('TagCollections', 'delete', false, $message, $this->response->type());
                } else {
                    $this->Flash->error($message);
                    $this->redirect(array('action' => 'index'));
                }
            }
        } else {
            throw new NotFoundException(__('You are not allowed to delete that.'));
        }
    }

    public function addTag($id = false, $tag_id = false)
    {
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
            if (!isset($this->request->data['tag_collection'])) {
                throw new NotFoundException(__('Invalid tag collection'));
            }
            $id = $this->request->data['tag_collection'];
        }
        if (!$this->request->is('post')) {
            $this->set('object_id', $id);
            $this->set('scope', 'TagCollection');
            $this->layout = false;
            $this->autoRender = false;
            $this->render('/Events/add_tag');
        } else {
            if ($tag_id === false) {
                if (!isset($this->request->data['tag'])) {
                    throw new NotFoundException(__('Invalid tag'));
                }
                $tag_id = $this->request->data['tag'];
            }
            $conditions = array();
            if (!$this->_isSiteAdmin()) {
                $conditions['Tag.org_id'] = array('0', $this->Auth->user('org_id'));
                $conditions['Tag.user_id'] = array('0', $this->Auth->user('id'));
            }
            if (!is_numeric($tag_id)) {
                $tag_ids = json_decode($tag_id);
                $tag_lookups = array();
                foreach ($tag_ids as $temp) {
                    if (is_numeric($temp)) {
                        $tag_lookups['OR']['Tag.id'][] = $temp;
                    } else {
                        $tag_lookups['OR']['LOWER(Tag.name) LIKE'][] = strtolower(trim($tag_id));
                    }
                }
                if ($tag_ids !== null && is_array($tag_ids)) { // can decode json
                    $tag_ids = $this->TagCollection->TagCollectionTag->Tag->find('list', array(
                        'conditions' => array(
                            'AND' => array(
                                $conditions,
                                $tag_lookups
                            )
                        ),
                        'fields' => array('Tag.id', 'Tag.id')
                    ));
                    $tag_id_list = array_values($tag_ids);
                    if (empty($tag_id_list)) {
                        return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid Tag(s).')), 'status'=>200, 'type' => 'json'));
                    }
                } else {
                    $tag = $this->TagCollection->TagCollectionTag->Tag->find('first', array('recursive' => -1, 'conditions' => $conditions));
                    if (empty($tag)) {
                        return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid Tag.')), 'status'=>200, 'type' => 'json'));
                    }
                    $tag_id = $tag['Tag']['id'];
                }
            }
            $tagCollection = $this->TagCollection->find('first', array(
                'recursive' => -1,
                'conditions' => array('TagCollection.id' => $id)
            ));
            if (empty($tagCollection)) {
                return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid tag collection.')), 'status'=>200, 'type' => 'json'));
            }
            if (!$this->_isSiteAdmin()) {
                if (!$this->userRole['perm_tagger'] || ($this->Auth->user('org_id') !== $tagCollection['TagCollection']['org_id'])) {
                    return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'You don\'t have permission to do that.')), 'status'=>200, 'type' => 'json'));
                }
            }
            $this->autoRender = false;
            $error = false;
            $success = false;
            if (empty($tag_id_list)) {
                $tag_id_list = array($tag_id);
            }

            foreach ($tag_id_list as $tag_id) {
                $this->TagCollection->TagCollectionTag->Tag->id = $tag_id;
                if (!$this->TagCollection->TagCollectionTag->Tag->exists()) {
                    $error = __('Invalid Tag.');
                    continue;
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
                if (!empty($found)) {
                    $error = __('Tag is already attached to this event.');
                    continue;
                }
                $this->TagCollection->TagCollectionTag->create();
                if ($this->TagCollection->TagCollectionTag->save(array('tag_collection_id' => $id, 'tag_id' => $tag_id))) {
                    $log = ClassRegistry::init('Log');
                    $log->createLogEntry($this->Auth->user(), 'tag', 'TagCollection', $id, 'Attached tag (' . $tag_id . ') "' . $tag['Tag']['name'] . '" to collection (' . $id . ')', 'Event (' . $id . ') tagged as Tag (' . $tag_id . ')');
                    $success = __('Tag(s) added.');
                } else {
                    $fail = __('Tag(s) could not be added.');
                }
            }
            if ($success) {
                return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => $success)), 'status'=>200, 'type' => 'json'));
            } elseif (empty($fail)) {
                return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => __('All tags are already present, nothing to add.'), 'check_publish' => true)), 'status'=>200, 'type' => 'json'));
            } else {
                return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => $fail)), 'status'=>200, 'type' => 'json'));
            }
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
        //$this->Auth->user('Role')['perm_site_admin']);
        $conditions = array();
        if (!$this->_isSiteAdmin()) {
            $conditions = array(
                'OR' => array(
                    'TagCollection.all_orgs' => 1,
                    'TagCollection.org_id' => $this->Auth->user('org_id')
                )
            );
            $this->paginate['conditions'] = $conditions;
        }
        if ($this->_isRest()) {
            $params = array(
                'recursive' => -1,
                'contain' => array(
                    'TagCollectionTag' => array(
                        'Tag'
                    ),
                    'Organisation' => array(
                        'fields' => array(
                            'Organisation.id',
                            'Organisation.name',
                            'Organisation.uuid'
                        )
                    ),
                    'User' => array(
                        'fields' => array(
                            'User.email',
                            'User.id'
                        )
                    )
                )
            );
            if (!empty($conditions)) {
                $params['conditions'] = $conditions;
            }
            $namedParams = array('limit', 'page');
            foreach ($namedParams as $namedParam) {
                if (!empty($this->params['named'][$namedParam])) {
                    $params['limit'] = $this->params['named'][$namedParam];
                }
            }
            $list = $this->TagCollection->find('all', $params);
        } else {
            $list = $this->paginate();
        }
        $this->loadModel('Event');
        foreach ($list as $k => $tag_collection) {
            $list[$k] = $this->TagCollection->cullBlockedTags($this->Auth->user(), $tag_collection);
            $list[$k] = $this->Event->massageTags($list[$k], 'TagCollection', false, true);
            if (!$this->_isSiteAdmin() && $list[$k]['TagCollection']['org_id'] !== $this->Auth->user('org_id')) {
                unset($list[$k]['User']);
                unset($list[$k]['TagCollection']['user_id']);
            }
            if (!empty($list[$k]['TagCollectionTag'])) {
                foreach ($list[$k]['TagCollectionTag'] as $k2 => $tct) {
                    $list[$k]['TagCollectionTag'][$k2]['Tag'] = array(
                        'id' => $tct['Tag']['id'],
                        'name' => $tct['Tag']['name'],
                        'colour' => $tct['Tag']['colour']
                    );
                }
            }
        }
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($list, $this->response->type());
        } else {
            $this->set('list', $list);
        }
    }

    public function getRow($id)
    {
        $params = array(
            'recursive' => -1,
            'contain' => array('TagCollectionTag' => array('Tag'), 'User', 'Organisation'),
            'conditions' => array('TagCollection.id' => $id)
        );
        $item = $this->TagCollection->find('first', $params);
        if (empty($item)) {
            throw new NotFoundException('Invalid tag collection.');
        }
        if (!$this->_isSiteAdmin() && $item['TagCollection']['org_id'] !== $this->Auth->user('org_id')) {
            unset($item['User']);
            unset($item['TagCollection']['user_id']);
        }
        $this->loadModel('Event');
        $item = $this->Event->massageTags($item, 'TagCollection', false, true);
        $this->layout = false;
        $this->set('item', $item);
    }
}
