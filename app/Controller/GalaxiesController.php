<?php
App::uses('AppController', 'Controller');

class GalaxiesController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public $paginate = array(
            'limit' => 60,
            'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
            'contain' => array(

            ),
            'order' => array(
                'Galaxy.id' => 'DESC'
            ),
    );

    public function index()
    {
        $aclConditions = array();
        $filters = $this->IndexFilter->harvestParameters(array('value', 'enabled'));
        $searchConditions = array();
        if (empty($filters['value'])) {
            $filters['value'] = '';
        } else {
            $searchall = '%' . strtolower($filters['value']) . '%';
            $searchConditions = array(
                'OR' => array(
                    'LOWER(Galaxy.name) LIKE' => $searchall,
                    'LOWER(Galaxy.namespace) LIKE' => $searchall,
                    'LOWER(Galaxy.description) LIKE' => $searchall,
                    'LOWER(Galaxy.kill_chain_order) LIKE' => $searchall,
                    'Galaxy.uuid LIKE' => $searchall
                )
            );
        }
        if (isset($filters['enabled'])) {
            $searchConditions[]['enabled'] = $filters['enabled'] ? 1 : 0;
        }
        if ($this->_isRest()) {
            $galaxies = $this->Galaxy->find(
                'all',
                array(
                    'recursive' => -1,
                    'conditions' => array(
                        'AND' => array($searchConditions, $aclConditions)
                    )
                )
            );
            return $this->RestResponse->viewData($galaxies, $this->response->type());
        } else {
            $this->paginate['conditions']['AND'][] = $searchConditions;
            $this->paginate['conditions']['AND'][] = $aclConditions;
            $galaxies = $this->paginate();
            $this->set('galaxyList', $galaxies);
            $this->set('passedArgsArray', $this->passedArgs);
            $this->set('searchall', $filters['value']);
        }
    }

    public function update()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException('This action is only accessible via POST requests.');
        }
        if (!empty($this->params['named']['force'])) {
            $force = 1;
        } else {
            $force = 0;
        }
        $result = $this->Galaxy->update($force);
        $message = __('Galaxies updated.');
        if ($this->_isRest()) {
            return $this->RestResponse->saveSuccessResponse('Galaxy', 'update', false, $this->response->type(), $message);
        } else {
            $this->Flash->success($message);
            $this->redirect(array('controller' => 'galaxies', 'action' => 'index'));
        }
    }

    public function wipe_default()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException('This action is only accessible via POST requests.');
        }
        $result = $this->Galaxy->GalaxyCluster->wipe_default();
        $message = __('Default galaxy clusters dropped.');
        if ($this->_isRest()) {
            return $this->RestResponse->saveSuccessResponse('Galaxy', 'wipe_default', false, $this->response->type(), $message);
        } else {
            $this->Flash->success($message);
            $this->redirect(array('controller' => 'galaxies', 'action' => 'index'));
        }
    }

    public function view($id)
    {
        $id = $this->Toolbox->findIdByUuid($this->Galaxy, $id);
        $passedArgsArray = array(
            'context' => isset($this->params['named']['context']) ? $this->params['named']['context'] : 'all'
        );
        if (isset($this->params['named']['searchall']) && strlen($this->params['named']['searchall']) > 0) {
            $passedArgsArray['searchall'] = $this->params['named']['searchall'];
        }
        $this->set('passedArgsArray', $passedArgsArray);
        if ($this->_isRest()) {
            $galaxy = $this->Galaxy->find('first', array(
                    'contain' => array('GalaxyCluster' => array('GalaxyElement'/*, 'GalaxyReference'*/)),
                    'recursive' => -1,
                    'conditions' => array('Galaxy.id' => $id)
            ));
            if (empty($galaxy)) {
                throw new NotFoundException('Galaxy not found.');
            }
            return $this->RestResponse->viewData($galaxy, $this->response->type());
        } else {
            $galaxy = $this->Galaxy->find('first', array(
                    'recursive' => -1,
                    'conditions' => array('Galaxy.id' => $id)
            ));
            if (empty($galaxy)) {
                throw new NotFoundException('Galaxy not found.');
            }
            $this->set('galaxy', $galaxy);
        }
    }

    public function delete($id)
    {
        if (Validation::uuid($id)) {
            $id = $this->Toolbox->findIdByUuid($this->Galaxy, $id);
        } elseif (!is_numeric($id)) {
            throw new NotFoundException('Invalid galaxy.');
        }

        $galaxy = $this->Galaxy->find('first', array(
                'recursive' => -1,
                'conditions' => array('Galaxy.id' => $id)
        ));
        if (empty($galaxy)) {
            throw new NotFoundException('Invalid galaxy.');
        }
        $result = $this->Galaxy->delete($id);
        if ($result) {
            $message = __('Galaxy deleted');
            if ($this->_isRest()) {
                return $this->RestResponse->saveSuccessResponse('Galaxy', 'delete', false, $this->response->type(), $message);
            } else {
                $this->Flash->success($message);
                $this->redirect(array('controller' => 'galaxies', 'action' => 'index'));
            }
        } else {
            $message = __('Could not delete Galaxy.');
            if ($this->_isRest()) {
                return $this->RestResponse->saveFailResponse('Galaxy', 'delete', false, $message);
            } else {
                $this->Flash->success($message);
                $this->redirect($this->referer());
            }
        }
    }

    public function enable($id) {
        return $this->toggle($id, true);
    }

    public function disable($id) {
        return $this->toggle($id, false);
    }

    public function toggle($id, $enabled=null)
    {
        if (Validation::uuid($id)) {
            $id = $this->Toolbox->findIdByUuid($this->Galaxy, $id);
        } elseif (!is_numeric($id)) {
            throw new NotFoundException('Invalid galaxy.');
        }

        $galaxy = $this->Galaxy->find('first', array(
                'recursive' => -1,
                'conditions' => array('Galaxy.id' => $id)
        ));
        if (empty($galaxy)) {
            throw new NotFoundException('Invalid galaxy.');
        }
        if (is_null($enabled)) {
            $galaxy['Galaxy']['enabled'] = !$galaxy['Galaxy']['enabled'];
        } else {
            $galaxy['Galaxy']['enabled'] = $enabled;
        }
        $result = $this->Galaxy->save($galaxy);
        if ($result) {
            $message = __('Galaxy enabled');
            if ($this->_isRest()) {
                return $this->RestResponse->saveSuccessResponse('Galaxy', 'toggle', false, $this->response->type(), $message);
            } else {
                $this->Flash->success($message);
                $this->redirect(array('controller' => 'galaxies', 'action' => 'index'));
            }
        } else {
            $message = __('Could not enable Galaxy.');
            if ($this->_isRest()) {
                return $this->RestResponse->saveFailResponse('Galaxy', 'toggle', false, $message);
            } else {
                $this->Flash->success($message);
                $this->redirect($this->referer());
            }
        }
    }

    public function import()
    {
        if ($this->request->is('post') || $this->request->is('put')) {
            if ($this->_isRest()) {
                $clusters = $this->request->data;
            } else {
                $data = $this->request->data['Galaxy'];
                if ($data['submittedjson']['name'] != '' && $data['json'] != '') {
                    throw new MethodNotAllowedException(__('Only one import field can be used at a time'));
                }
                if ($data['submittedjson']['size'] > 0) {
                    $filename = basename($data['submittedjson']['name']);
                    $file_content = file_get_contents($data['submittedjson']['tmp_name']);
                    if ((isset($data['submittedjson']['error']) && $data['submittedjson']['error'] == 0) ||
                        (!empty($data['submittedjson']['tmp_name']) && $data['submittedjson']['tmp_name'] != '')
                    ) {
                        if (!$file_content) {
                            throw new InternalErrorException(__('PHP says file was not uploaded. Are you attacking me?'));
                        }
                    }
                    $text = $file_content;
                } else {
                    $text = $data['json'];
                }
                $clusters = json_decode($text, true);
                if ($clusters === null) {
                    throw new MethodNotAllowedException(__('Error while decoding JSON'));
                }
            }
            $saveResult = $this->Galaxy->importGalaxyAndClusters($this->Auth->user(), $clusters);
            if ($saveResult['success']) {
                $message = sprintf(__('Galaxy clusters imported. %s imported, %s ignored, %s failed. %s'), $saveResult['imported'], $saveResult['ignored'], $saveResult['failed'], !empty($saveResult['errors']) ? implode(', ', $saveResult['errors']) : '');
                if ($this->_isRest()) {
                    return $this->RestResponse->saveSuccessResponse('Galaxy', 'import', false, $this->response->type(), $message);
                } else {
                    $this->Flash->success($message);
                    $this->redirect(array('controller' => 'galaxies', 'action' => 'index'));
                }
            } else {
                $message = sprintf(__('Could not import galaxy clusters. %s imported, %s ignored, %s failed. %s'), $saveResult['imported'], $saveResult['ignored'], $saveResult['failed'], !empty($saveResult['errors']) ? implode(', ', $saveResult['errors']) : '');
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('Galaxy', 'import', false, $message);
                } else {
                    $this->Flash->error($message);
                }
            }
        }
        $this->set('action', 'import');
    }

    // Ingests clusters coming from a sync request
    public function pushCluster()
    {
        if (!$this->Auth->user()['Role']['perm_sync'] || !$this->Auth->user()['Role']['perm_galaxy_editor']) {
            throw new MethodNotAllowedException(__('You do not have the permission to do that.'));
        }
        if (!$this->_isRest()) {
            throw new MethodNotAllowedException(__('This action is only accessible via a REST request.'));
        }
        if ($this->request->is('post')) {
            $clusters = $this->request->data;
            $saveResult = $this->Galaxy->importGalaxyAndClusters($this->Auth->user(), $clusters);
            $messageInfo = __('%s imported, %s ignored, %s failed. %s', $saveResult['imported'], $saveResult['ignored'], $saveResult['failed'], !empty($saveResult['errors']) ? implode(', ', $saveResult['errors']) : '');
            if ($saveResult['success']) {
                $message = __('Galaxy clusters imported. ') . $messageInfo;
                return $this->RestResponse->saveSuccessResponse('Galaxy', 'pushCluster', false, $this->response->type(), $message);
            } else {
                $message = __('Could not import galaxy clusters. ') . $messageInfo;
                return $this->RestResponse->saveFailResponse('Galaxy', 'pushCluster', false, $message);
            }
        }
    }

    public function export($galaxyId)
    {
        $galaxy = $this->Galaxy->find('first', array(
            'recursive' => -1,
            'conditions' => array('Galaxy.id' => $galaxyId)
        ));
        if (empty($galaxy) && $galaxyId !== null) {
            throw new NotFoundException('Galaxy not found.');
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            $this->request->data = $this->request->data['Galaxy'];
            $clusterType = array();
            if ($this->request->data['default']) {
                $clusterType[] = true;
            }
            if ($this->request->data['custom']) {
                $clusterType[] = false;
            }
            $options = array(
                'conditions' => array(
                    'GalaxyCluster.galaxy_id' => $galaxyId,
                    'GalaxyCluster.distribution' => $this->request->data['distribution'],
                    'GalaxyCluster.default' => $clusterType
                )
            );
            $clusters = $this->Galaxy->GalaxyCluster->fetchGalaxyClusters($this->Auth->user(), $options, $full=true);
            $clusters = $this->Galaxy->GalaxyCluster->unsetFieldsForExport($clusters);
            if ($this->request->data['format'] == 'misp-galaxy') {
                $clusters = $this->Galaxy->convertToMISPGalaxyFormat($galaxy, $clusters);
            }
            $content = json_encode($clusters, JSON_PRETTY_PRINT);
            $this->response->body($content);
            $this->response->type('json');
            if ($this->request->data['download'] == 'download') {
                $this->response->download(sprintf('galaxy_%s_%s.json', $galaxy['Galaxy']['uuid'], time()));
            }
            return $this->response;
        } else {
            $this->set('galaxy', $galaxy);
            $this->loadModel('Attribute');
            $distributionLevels = $this->Attribute->distributionLevels;
            unset($distributionLevels[5]);
            $distributionLevels[4] = __('All sharing groups');
            $this->set('distributionLevels', $distributionLevels);
            $this->set('action', 'export');
        }
    }

    public function selectGalaxy($target_id, $target_type='event', $namespace='misp', $noGalaxyMatrix = false)
    {
        $mitreAttackGalaxyId = $this->Galaxy->getMitreAttackGalaxyId();
        $local = !empty($this->params['named']['local']) ? $this->params['named']['local'] : '0';
        $eventid = !empty($this->params['named']['eventid']) ? $this->params['named']['eventid'] : '0';
        $conditions = $namespace === '0' ? array() : array('namespace' => $namespace);
        $conditions[] = [
            'enabled' => true
        ];
        $galaxies = $this->Galaxy->find('all', array(
            'recursive' => -1,
            'fields' => array('MAX(Galaxy.version) as latest_version', 'id', 'kill_chain_order', 'name', 'icon', 'description'),
            'conditions' => $conditions,
            'group' => array('name', 'id', 'kill_chain_order', 'icon', 'description'),
            'order' => array('name asc')
        ));
        $items = array(
            array(
                'name' => __('All clusters'),
                'value' => $this->baseurl . "/galaxies/selectCluster/" . h($target_id) . '/' . h($target_type) . '/0'. '/local:' . $local . '/eventid:' . $eventid
            )
        );
        foreach ($galaxies as $galaxy) {
            if (!isset($galaxy['Galaxy']['kill_chain_order']) || $noGalaxyMatrix) {
                $items[] = array(
                    'name' => h($galaxy['Galaxy']['name']),
                    'value' => $this->baseurl . "/galaxies/selectCluster/" . $target_id . '/' . $target_type . '/' . $galaxy['Galaxy']['id'] . '/local:' . $local . '/eventid:' . $eventid,
                    'template' => array(
                        'preIcon' => 'fa-' . $galaxy['Galaxy']['icon'],
                        'name' => $galaxy['Galaxy']['name'],
                        'infoExtra' => $galaxy['Galaxy']['description'],
                    )
                );
            } else { // should use matrix instead
                $param = array(
                    'name' => $galaxy['Galaxy']['name'],
                    'value' => $this->baseurl . "/galaxies/selectCluster/" . $target_id . '/' . $target_type . '/' . $galaxy['Galaxy']['id'] . '/local:' . $local . '/eventid:' . $eventid,
                    'functionName' => sprintf(
                        "getMatrixPopup('%s', '%s', '%s/local:%s/eventid:%s')",
                        $target_type,
                        $target_id,
                        $galaxy['Galaxy']['id'],
                        $local,
                        $eventid
                    ),
                    'isPill' => true,
                    'isMatrix' => true
                );
                if ($galaxy['Galaxy']['id'] == $mitreAttackGalaxyId) {
                    $param['img'] = $this->baseurl . "/img/mitre-attack-icon.ico";
                }
                $items[] = $param;
            }
        }

        $this->set('items', $items);
        $this->render('/Elements/generic_picker');
    }

    public function selectGalaxyNamespace($target_id, $target_type='event', $noGalaxyMatrix = false)
    {
        $namespaces = $this->Galaxy->find('list', array(
            'recursive' => -1,
            'fields' => array('namespace', 'namespace'),
            'conditions' => array('enabled' => 1),
            'group' => array('namespace'),
            'order' => array('namespace asc')
        ));
        $local = !empty($this->params['named']['local']) ? '1' : '0';
        $eventid = !empty($this->params['named']['eventid']) ? $this->params['named']['eventid'] : '0';
        $items = array();
        $noGalaxyMatrix = $noGalaxyMatrix ? '1' : '0';
        $items[] = array(
            'name' => __('All namespaces'),
            'value' => $this->baseurl . "/galaxies/selectGalaxy/" . $target_id . '/' . $target_type . '/0' . '/' . $noGalaxyMatrix . '/local:' . $local . '/eventid:' . $eventid
        );
        foreach ($namespaces as $namespace) {
            $items[] = array(
                'name' => $namespace,
                'value' => $this->baseurl . "/galaxies/selectGalaxy/" . $target_id . '/' . $target_type . '/' . $namespace . '/' . $noGalaxyMatrix . '/local:' . $local . '/eventid:' . $eventid
            );
        }

        $this->set('items', $items);
        $this->set('options', array( // set chosen (select picker) options
            'multiple' => 0,
        ));
        $this->render('/Elements/generic_picker');
    }

    public function selectCluster($target_id, $target_type = 'event', $selectGalaxy = false)
    {
        $conditions = array();
        $conditions = array(
            'OR' => array(
                'GalaxyCluster.published' => true,
                'GalaxyCluster.default' => true,
            ),
            'AND' => array(
                'GalaxyCluster.deleted' => false,
            )
        );
        if ($target_type == 'galaxyClusterRelation') {
            $conditions['OR']['GalaxyCluster.published'] = [true, false];
        }
        if ($selectGalaxy) {
            $conditions['GalaxyCluster.galaxy_id'] = $selectGalaxy;
        }
        $local = !empty($this->params['named']['local']) ? $this->params['named']['local'] : '0';
        $data = $this->Galaxy->GalaxyCluster->fetchGalaxyClusters($this->Auth->user(), array(
                'conditions' => $conditions,
                'fields' => array('value', 'description', 'source', 'type', 'id', 'uuid'),
                'order' => array('value asc'),
        ), false);
        $clusters = array();
        $cluster_ids = array();
        foreach ($data as $k => $cluster) {
            $cluster_ids[] = $cluster['GalaxyCluster']['id'];
        }
        $synonyms = $this->Galaxy->GalaxyCluster->GalaxyElement->find('all', array(
            'conditions' => array(
                'GalaxyElement.galaxy_cluster_id' => $cluster_ids,
                'GalaxyElement.key' => 'synonyms'
            ),
            'recursive' => -1
        ));
        $sorted_synonyms = array();
        foreach ($synonyms as $synonym) {
            $sorted_synonyms[$synonym['GalaxyElement']['galaxy_cluster_id']][] = $synonym;
        }
        foreach ($data as $k => $cluster) {
            $cluster['GalaxyCluster']['synonyms_string'] = array();
            if (!empty($sorted_synonyms[$cluster['GalaxyCluster']['id']])) {
                foreach ($sorted_synonyms[$cluster['GalaxyCluster']['id']] as $element) {
                    $cluster['GalaxyCluster']['synonyms_string'][] = $element['GalaxyElement']['value'];
                    $cluster['GalaxyElement'][] = $element['GalaxyElement'];
                }
                unset($sorted_synonyms[$cluster['GalaxyCluster']['id']]);
            }
            $cluster['GalaxyCluster']['synonyms_string'] = implode(', ', $cluster['GalaxyCluster']['synonyms_string']);
            unset($cluster['GalaxyElement']);
            $clusters[$cluster['GalaxyCluster']['type']][$cluster['GalaxyCluster']['uuid']] = $cluster['GalaxyCluster'];
        }
        ksort($clusters);
        $this->set('target_id', $target_id);
        $this->set('target_type', $target_type);

        $items = array();
        foreach ($clusters as $namespace => $cluster_data) {
            foreach ($cluster_data as $k => $cluster) {
                $name = $cluster['value'];
                $optionName = $cluster['value'];
                if ($cluster['synonyms_string'] !== '') {
                    $synom = __('Synonyms: ') . $cluster['synonyms_string'];
                    $optionName .= $cluster['synonyms_string'] !== '' ? ' (' . $cluster['synonyms_string'] . ')' : '';
                } else {
                    $synom = '';
                }
                $itemParam = array(
                    'name' => $optionName,
                    'value' => $cluster['id'],
                    'template' => array(
                        'name' => $name,
                        'infoExtra' => $cluster['description'],
                    ),
                    'additionalData' => array(
                        'uuid' => $cluster['uuid']
                    )
                );
                if ($cluster['synonyms_string'] !== '') {
                    $itemParam['template']['infoContextual'] = $synom;
                }
                $items[] = $itemParam;
                unset($cluster_data[$k]);
            }
        }
        $onClickForm = 'quickSubmitGalaxyForm';
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($items, $this->response->type());
        } else {
            $this->set('items', $items);
            $this->set('options', array( // set chosen (select picker) options
                'functionName' => $onClickForm,
                'multiple' => $target_type == 'galaxyClusterRelation' ? 0 : '-1',
                'select_options' => array(
                    'additionalData' => array(
                        'target_id' => $target_id,
                        'target_type' => $target_type,
                        'local' => $local
                    )
                ),
            ));
            $this->render('ajax/cluster_choice');
        }
    }

    public function attachCluster($target_id, $target_type = 'event')
    {
        $cluster_id = $this->request->data['Galaxy']['target_id'];
        $result = $this->Galaxy->attachCluster($this->Auth->user(), $target_type, $target_id, $cluster_id);
        return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => $result, 'check_publish' => true)), 'status'=>200, 'type' => 'json'));
    }

    public function attachMultipleClusters($target_id, $target_type = 'event')
    {
        $local = !empty($this->params['named']['local']);
        $this->set('local', $local);
        if ($this->request->is('post')) {
            if ($target_id === 'selected') {
                $target_id_list = json_decode($this->request->data['Galaxy']['attribute_ids']);
            } else {
                $target_id_list = array($target_id);
            }
            $cluster_ids = $this->request->data['Galaxy']['target_ids'];
            if (strlen($cluster_ids) > 0) {
                $cluster_ids = json_decode($cluster_ids, true);
                if ($cluster_ids === null || empty($cluster_ids)) {
                    return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => __('Failed to parse request or no clusters picked.'))), 'status'=>200, 'type' => 'json'));
                }
            } else {
                return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => __('Failed to parse request.'))), 'status'=>200, 'type' => 'json'));
            }
            $result = "";
            if (!is_array($cluster_ids)) { // in case we only want to attach 1
                $cluster_ids = array($cluster_ids);
            }
            foreach ($cluster_ids as $cluster_id) {
                foreach ($target_id_list as $target_id) {
                    $result = $this->Galaxy->attachCluster($this->Auth->user(), $target_type, $target_id, $cluster_id, $local);
                }
            }
            if ($this->request->is('ajax')) {
                return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => $result, 'check_publish' => true)), 'status'=>200, 'type' => 'json'));
            } else {
                $this->Flash->info($result);
                $this->redirect($this->referer());
            }
        } else {
            $this->set('target_id', $target_id);
            $this->set('target_type', $target_type);
            $this->layout = false;
            $this->autoRender = false;
            $this->render('/Galaxies/ajax/attach_multiple_clusters');
        }
    }

    public function viewGraph($id)
    {
        $cluster = $this->Galaxy->GalaxyCluster->find('first', array(
            'conditions' => array('GalaxyCluster.id' => $id),
            'contain' => array('Galaxy'),
            'recursive' => -1
        ));
        if (empty($cluster)) {
            throw new MethodNotAllowedException('Invalid Galaxy.');
        }
        $this->set('cluster', $cluster);
        $this->set('defaultCluster', $cluster['GalaxyCluster']['default']);
        $this->set('scope', 'galaxy');
        $this->set('id', $id);
        $this->set('galaxy_id', $cluster['Galaxy']['id']);
        $this->render('/Events/view_graph');
    }

    public function showGalaxies($id, $scope = 'event')
    {
        $this->layout = 'ajax';
        $this->set('scope', $scope);
        if ($scope == 'event') {
            $this->loadModel('Event');
            $object = $this->Event->fetchEvent($this->Auth->user(), array('eventid' => $id, 'metadata' => 1));
            if (empty($object)) {
                throw new MethodNotAllowedException('Invalid event.');
            }
            $this->set('object', $object[0]);
        } elseif ($scope == 'attribute') {
            $this->loadModel('Attribute');
            $object = $this->Attribute->fetchAttributes($this->Auth->user(), array('conditions' => array('Attribute.id' => $id), 'flatten' => 1));
            if (empty($object)) {
                throw new MethodNotAllowedException('Invalid attribute.');
            }
            $object[0] = $this->Attribute->Event->massageTags($this->Auth->user(), $object[0], 'Attribute');
        } elseif ($scope == 'tag_collection') {
            $this->loadModel('TagCollection');
            $object = $this->TagCollection->fetchTagCollection($this->Auth->user(), array('conditions' => array('TagCollection.id' => $id)));
            if (empty($object)) {
                throw new MethodNotAllowedException('Invalid Tag Collection.');
            }
        }
        $this->set('object', $object[0]);
        $this->render('/Events/ajax/ajaxGalaxies');
    }

    public function forkTree($galaxyId, $pruneRootLeaves=true)
    {
        $clusters = $this->Galaxy->GalaxyCluster->fetchGalaxyClusters($this->Auth->user(), array('conditions' => array('GalaxyCluster.galaxy_id' => $galaxyId)), $full=true);
        if (empty($clusters)) {
            throw new MethodNotAllowedException('Invalid Galaxy.');
        }
        $this->Galaxy->GalaxyCluster->attachExtendByInfo($this->Auth->user(), $clusters);
        foreach ($clusters as $k => $cluster) {
            $clusters[$k] = $this->Galaxy->GalaxyCluster->attachExtendFromInfo($this->Auth->user(), $clusters[$k]);
        }
        $galaxy = $this->Galaxy->find('first', array(
            'recursive' => -1,
            'conditions' => array('Galaxy.id' => $galaxyId)
        ));
        $tree = $this->Galaxy->generateForkTree($clusters, $galaxy, $pruneRootLeaves=$pruneRootLeaves);
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($tree, $this->response->type());
        }
        $this->set('tree', $tree);
        $this->set('galaxy', $galaxy);
        $this->set('galaxy_id', $galaxyId);
    }

    public function relationsGraph($galaxyId)
    {
        $clusters = $this->Galaxy->GalaxyCluster->fetchGalaxyClusters($this->Auth->user(), array('conditions' => array('GalaxyCluster.galaxy_id' => $galaxyId)), $full=true);
        if (empty($clusters)) {
            throw new MethodNotAllowedException('Invalid Galaxy.');
        }
        $galaxy = $this->Galaxy->find('first', array(
            'recursive' => -1,
            'conditions' => array('Galaxy.id' => $galaxyId)
        ));
        App::uses('ClusterRelationsGraphTool', 'Tools');
        $grapher = new ClusterRelationsGraphTool($this->Auth->user(), $this->Galaxy->GalaxyCluster);
        $relations = $grapher->getNetwork($clusters);
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($relations, $this->response->type());
        }
        $this->set('relations', $relations);
        $this->set('galaxy', $galaxy);
        $this->set('galaxy_id', $galaxyId);
        $this->loadModel('Attribute');
        $distributionLevels = $this->Attribute->distributionLevels;
        $this->set('distributionLevels', $distributionLevels);
    }
}
