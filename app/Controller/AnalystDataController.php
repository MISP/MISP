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
        App::uses('LanguageRFC5646Tool', 'Tools');
        $this->set('languageRFC5646', ['' => __('- No language -'), LanguageRFC5646Tool::getLanguages()]);
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
        $this->loadModel('Event');
        $currentUser = $this->Auth->user();
        $params = [
            'afterSave' => function (array $analystData) use ($currentUser) {
                $this->Event->captureAnalystData($currentUser, $this->request->data[$this->modelSelection], $this->modelSelection, $analystData[$this->modelSelection]['uuid']);
            }
        ];
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
        if ($type === 'all' && Validation::uuid($id)) {
            $this->loadModel('AnalystData');
            $type = $this->AnalystData->deduceType($id);
        }
        $this->__typeSelector($type);
        if (!is_numeric($id) && Validation::uuid($id)) {
            $id = $this->AnalystData->getIDFromUUID($type, $id);
        }

        $this->set('id', $id);
        $conditions = $this->AnalystData->buildConditions($this->Auth->user());
        $this->loadModel('Event');
        $currentUser = $this->Auth->user();
        $params = [
            'fields' => $this->AnalystData->getEditableFields(),
            'conditions' => $conditions,
            'afterFind' => function(array $analystData): array {
                $canEdit = $this->ACL->canEditAnalystData($this->Auth->user(), $analystData, $this->modelSelection);
                if (!$canEdit) {
                    throw new MethodNotAllowedException(__('You are not authorised to do that.'));
                }
                return $analystData;
            },
            'beforeSave' => function(array $analystData): array {
                $analystData[$this->modelSelection]['modified'] = date('Y-m-d H:i:s');
                return $analystData;
            },
            'afterSave' => function (array $analystData) use ($currentUser) {
                $this->Event->captureAnalystData($currentUser, $this->request->data[$this->modelSelection], $this->modelSelection, $analystData[$this->modelSelection]['uuid']);
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

    public function delete($type = 'Note', $id, $hard=true)
    {
        if ($type === 'all' && Validation::uuid($id)) {
            $this->loadModel('AnalystData');
            $type = $this->AnalystData->deduceType($id);
        }
        $this->__typeSelector($type);
        if (!is_numeric($id) && Validation::uuid($id)) {
            $id = $this->AnalystData->getIDFromUUID($type, $id);
        }

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
        if ($type === 'all' && Validation::uuid($id)) {
            $this->loadModel('AnalystData');
            $type = $this->AnalystData->getAnalystDataTypeFromUUID($id);
        }
        $this->__typeSelector($type);
        if (!is_numeric($id) && Validation::uuid($id)) {
            $id = $this->AnalystData->getIDFromUUID($type, $id);
        }

        $this->AnalystData->fetchRecursive = true;
        $conditions = $this->AnalystData->buildConditions($this->Auth->user());
        $this->CRUD->view($id, [
            'conditions' => $conditions,
            'contain' => ['Org', 'Orgc'],
            'afterFind' => function(array $analystData) {
                if (!$this->request->is('ajax')) {
                    unset($analystData[$this->modelSelection]['_canEdit']);
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
            'filters' => ['uuid', 'target_object'],
            'quickFilters' => ['name'],
            'conditions' => $conditions,
            'afterFind' => function(array $data) {
                foreach ($data as $i => $analystData) {
                    if (!$this->request->is('ajax')) {
                        unset($analystData[$this->modelSelection]['_canEdit']);
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

    public function getChildren($type = 'Note', $uuid, $depth=2)
    {
        $this->__typeSelector($type);
        $data = $this->AnalystData->getChildren($this->Auth->user(), $uuid, $depth);
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

    public function indexMinimal()
    {
        $this->loadModel('AnalystData');
        $filters = [];
        if ($this->request->is('post')) {
            $filters = $this->request->data;
        }
        $options = [];
        if (!empty($filters['orgc_name'])) {
            $orgcNames = $filters['orgc_name'];
            if (!is_array($orgcNames)) {
                $orgcName = [$orgcNames];
            }
            $filterName = 'orgc_uuid';
            foreach ($orgcNames as $orgcName) {
                if ($orgcName[0] === '!') {
                    $orgc = $this->AnalystData->Orgc->fetchOrg(substr($orgcName, 1));
                    if ($orgc === false) {
                        continue;
                    }
                    $options[]['AND'][] = ["{$filterName} !=" => $orgc['uuid']];
                } else {
                    $orgc = $this->AnalystData->Orgc->fetchOrg($orgcName);
                    if ($orgc === false) {
                        continue;
                    }
                    $options['OR'][] = [$filterName => $orgc['uuid']];
                }
            }
        }
        $allData = $this->AnalystData->indexMinimal($this->Auth->user(), $options);

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
                if (!empty($this->request->data)) {
                    if (!isset($this->request->data[$type])) {
                        $this->request->data = [$type => $this->request->data];
                    }
                }
                return $vt;
            }
        }
        throw new MethodNotAllowedException(__('Invalid type.'));
    }
}
