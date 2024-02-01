<?php
App::uses('AppController', 'Controller');

class AnalystDataController extends AppController
{

    public $components = ['Session', 'RequestHandler'];

    public $paginate = [
        'limit' => 60,
        'order' => []
    ];

    public $uses = [
        'Opinion',
        'Note',
        'Relationship'
    ];

    private $__valid_types = [
        'Opinion',
        'Note',
        'Relationship'
    ];

    // public $modelSelection = 'Note';

    private function _setViewElements()
    {
        $dropdownData = [];
        $this->loadModel('Event');
        $dropdownData['distributionLevels'] = $this->Event->distributionLevels;
        $this->set('initialDistribution', Configure::read('MISP.default_event_distribution'));
        $dropdownData['sgs'] = $this->Event->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', 1);
        $dropdownData['valid_targets'] = array_combine($this->AnalystData->valid_targets, $this->AnalystData->valid_targets);
        $this->set(compact('dropdownData'));
        $this->set('modelSelection', $this->modelSelection);
        $this->set('distributionLevels', $this->Event->distributionLevels);
    }
    
    public function add($type = 'Note', $object_uuid = null, $object_type = null)
    {
        $this->__typeSelector($type);
        if (!empty($object_uuid)) {
            $this->request->data[$this->modelSelection]['object_uuid'] = $object_uuid;
        }
        if (!empty($object_type)) {
            $this->request->data[$this->modelSelection]['object_type'] = $object_type;
        }
        
        if (empty($this->request->data[$this->modelSelection]['object_type']) && !empty($this->request->data[$this->modelSelection]['object_uuid'])) {
            $this->request->data[$this->modelSelection]['object_type'] = $this->AnalystData->deduceType($object_uuid);
        }
        $params = [];
        $this->CRUD->add($params);
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }
        $this->_setViewElements();
        if ($type == 'Relationship') {
            $this->set('existingRelations', $this->AnalystData->getExistingRelationships());
        }
        $this->set('menuData', array('menuList' => 'analyst_data', 'menuItem' => 'add_' . strtolower($type)));
        $this->render('add');
    }

    public function edit($type = 'Note', $id)
    {
        $this->__typeSelector($type);
        $this->set('id', $id);
        $conditions = $this->AnalystData->buildConditions($this->Auth->user());
        $params = [
            'conditions' => $conditions,
            'afterFind' => function(array $analystData) {
                $canEdit = $this->ACL->canEditAnalystData($this->Auth->user(), $analystData, $this->modelSelection);
                if (!$canEdit) {
                    throw new MethodNotAllowedException(__('You are not authorised to do that.'));
                }
                return $analystData;
            }
        ];
        $this->CRUD->edit($id, $params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->_setViewElements();
        if ($type == 'Relationship') {
            $this->set('existingRelations', $this->AnalystData->getExistingRelationships());
        }
        $this->set('menuData', array('menuList' => 'analyst_data', 'menuItem' => 'edit'));
        $this->render('add');
    }

    public function delete($type = 'Note', $id, $hard=false)
    {
        $this->__typeSelector($type);
        $params = [
            'afterFind' => function(array $analystData) {
                $canEdit = $this->ACL->canEditAnalystData($this->Auth->user(), $analystData, $this->modelSelection);
                if (!$canEdit) {
                    throw new MethodNotAllowedException(__('You are not authorised to do that.'));
                }
                return $analystData;
            },
            'afterDelete' => function($deletedAnalystData) use ($hard) {
                if (empty($hard)) {
                    return;
                }
                $type = $this->AnalystData->deduceAnalystDataType($deletedAnalystData);
                $info = '- Unsupported analyst type -';
                if ($type === 'Note') {
                    $info = $deletedAnalystData[$type]['note'];
                } else if ($type === 'Opinion') {
                    $info = sprintf('%s/100 :: %s', $deletedAnalystData[$type]['opinion'], $deletedAnalystData[$type]['comment']);
                } else if ($type === 'Relationship') {
                    $info = sprintf('-- %s --> %s :: %s', $deletedAnalystData[$type]['relationship_type'] ?? '[undefined]', $deletedAnalystData[$type]['related_object_type'], $deletedAnalystData[$type]['related_object_uuid']);
                }
                $this->AnalystDataBlocklist = ClassRegistry::init('AnalystDataBlocklist');
                $this->AnalystDataBlocklist->create();
                if (!empty($deletedAnalystData[$type]['orgc_uuid'])) {
                    if (!empty($deletedAnalystData[$type]['Orgc'])) {
                        $orgc = $deletedAnalystData[$type];
                    } else {
                        $orgc = $this->Orgc->find('first', array(
                            'conditions' => ['Orgc.uuid' => $deletedAnalystData[$type]['orgc_uuid']],
                            'recursive' => -1,
                            'fields' => ['Orgc.name'],
                        ));
                    }
                } else {
                    $orgc = ['Orgc' => ['name' => 'MISP']];
                }
                $this->AnalystDataBlocklist->save(['analyst_data_uuid' => $deletedAnalystData[$type]['uuid'], 'analyst_data_info' => $info, 'analyst_data_orgc' => $orgc['Orgc']['name']]);
            }
        ];
        $this->CRUD->delete($id, $params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        
    }

    public function view($type = 'Note', $id)
    {
        $this->__typeSelector($type);

        $this->AnalystData->fetchRecursive = true;
        $conditions = $this->AnalystData->buildConditions($this->Auth->user());
        $this->CRUD->view($id, [
            'conditions' => $conditions,
            'contain' => ['Org', 'Orgc'],
            'afterFind' => function(array $analystData) {
                $canEdit = $this->ACL->canEditAnalystData($this->Auth->user(), $analystData, $this->modelSelection);
                if (!$this->IndexFilter->isRest()) {
                    $analystData[$this->modelSelection]['_canEdit'] = $canEdit;
                }
                return $analystData;
            }
        ]);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('id', $id);
        $this->loadModel('Event');
        $this->_setViewElements();
        $this->set('distributionLevels', $this->Event->distributionLevels);
        $this->set('shortDist', $this->Event->shortDist);
        $this->set('menuData', array('menuList' => 'analyst_data', 'menuItem' => 'view'));
        $this->render('view');
    }

    public function index($type = 'Note')
    {
        $this->__typeSelector($type);

        $conditions = $this->AnalystData->buildConditions($this->Auth->user());
        $params = [
            'filters' => ['uuid', 'target_object', 'uuid'],
            'quickFilters' => ['name'],
            'conditions' => $conditions,
            'afterFind' => function(array $data) {
                foreach ($data as $i => $analystData) {
                    $canEdit = $this->ACL->canEditAnalystData($this->Auth->user(), $analystData, $this->modelSelection);
                    if (!$this->IndexFilter->isRest()) {
                        $data[$i][$this->modelSelection]['_canEdit'] = $canEdit;
                    }
                }
                return $data;
            }
        ];
        $this->CRUD->index($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->_setViewElements();
        $this->set('menuData', array('menuList' => 'analyst_data', 'menuItem' => 'index'));
    }

    public function getRelatedElement($type, $uuid)
    {
        $this->__typeSelector('Relationship');
        $data = $this->AnalystData->getRelatedElement($this->Auth->user(), $type, $uuid);
        return $this->RestResponse->viewData($data, 'json');
    }

    public function filterAnalystDataForPush()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__('This function is only accessible via POST requests.'));
        }

        $this->loadModel('AnalystData');

        $allIncomingAnalystData = $this->request->data;
        $allData = $this->AnalystData->filterAnalystDataForPush($allIncomingAnalystData);

        return $this->RestResponse->viewData($allData, $this->response->type());
    }

    public function pushAnalystData()
    {
        if (!$this->Auth->user()['Role']['perm_sync'] || !$this->Auth->user()['Role']['perm_analyst_data']) {
            throw new MethodNotAllowedException(__('You do not have the permission to do that.'));
        }
        if (!$this->_isRest()) {
            throw new MethodNotAllowedException(__('This action is only accessible via a REST request.'));
        }
        if ($this->request->is('post')) {
            $this->loadModel('AnalystData');
            $analystData = $this->request->data;
            $saveResult = $this->AnalystData->captureAnalystData($this->Auth->user(), $analystData);
            $messageInfo = __('%s imported, %s ignored, %s failed. %s', $saveResult['imported'], $saveResult['ignored'], $saveResult['failed'], !empty($saveResult['errors']) ? implode(', ', $saveResult['errors']) : '');
            if ($saveResult['success']) {
                $message = __('Analyst Data imported. ') . $messageInfo;
                return $this->RestResponse->saveSuccessResponse('AnalystData', 'pushAnalystData', false, $this->response->type(), $message);
            } else {
                $message = __('Could not import analyst data. ') . $messageInfo;
                return $this->RestResponse->saveFailResponse('AnalystData', 'pushAnalystData', false, $message);
            }
        }
    }

    private function __typeSelector($type) {
        foreach ($this->__valid_types as $vt) {
            if ($type === $vt) {
                $this->modelSelection = $vt;
                $this->loadModel($vt);
                $this->AnalystData = $this->{$vt};
                $this->modelClass = $vt;
                $this->{$vt}->current_user = $this->Auth->user();
                return $vt;
            }
        }
        throw new MethodNotAllowedException(__('Invalid type.'));
    }
}
