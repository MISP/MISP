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

    public function delete($type = 'Note', $id)
    {
        $this->__typeSelector($type);
        $params = [
            'afterFind' => function(array $analystData) {
                $canEdit = $this->ACL->canEditAnalystData($this->Auth->user(), $analystData, $this->modelSelection);
                if (!$canEdit) {
                    throw new MethodNotAllowedException(__('You are not authorised to do that.'));
                }
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

        $conditions = $this->AnalystData->buildConditions($this->Auth->user());
        $this->CRUD->view($id, [
            'conditions' => $conditions,
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
