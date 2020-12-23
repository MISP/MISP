<?php
App::uses('AppController', 'Controller');

class CerebratesController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public function beforeFilter()
    {
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
        $this->set('menuData', array('menuList' => 'sync', 'menuItem' => 'list_cerebrates'));
    }

    public function add()
    {
        $params = [];
        $this->CRUD->add($params);
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }

        $this->loadModel('Organisation');
        $orgs = $this->Organisation->find('list', [
            'recursive' => -1,
            'fields' => ['id', 'name'],
            'order' => ['lower(name)' => 'ASC']
        ]);
        $dropdownData = [
            'org_id' => $orgs
        ];
        $this->set(compact('dropdownData'));
        $this->set('menuData', array('menuList' => 'sync', 'menuItem' => 'add_cerebrate'));
    }

    public function edit($id)
    {
        $this->set('menuData', array('menuList' => 'sync', 'menuItem' => 'edit_cerebrate'));
        $this->set('id', $id);
        $params = [];
        $this->CRUD->edit($id, $params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }

        $this->loadModel('Organisation');
        $orgs = $this->Organisation->find('list', [
            'recursive' => -1,
            'fields' => ['id', 'name'],
            'order' => ['lower(name)' => 'ASC']
        ]);
        $dropdownData = [
            'org_id' => $orgs
        ];
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
        $this->set('menuData', ['menuList' => 'sync', 'menuItem' => 'view_cerebrate']);
        $this->CRUD->view($id, ['contain' => ['Organisation.name', 'Organisation.uuid', 'Organisation.id']]);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('id', $id);
    }

    public function pull_orgs($id)
    {
        $this->set('menuData', ['menuList' => 'sync', 'menuItem' => 'previewCerebrateOrgs']);
        $cerebrate = $this->Cerebrate->find('first', [
            'recursive' => -1,
            'conditions' => ['Cerebrate.id' => $id]
        ]);
        if (empty($cerebrate)) {
            throw new NotFoundException(__('Invalid Cerebrate instance ID provided.'));
        }

        if ($this->request->is('post')) {
            $result = $this->Cerebrate->queryInstance([
                'cerebrate' => $cerebrate,
                'path' => '/organisations/index',
                'params' => $this->IndexFilter->harvestParameters([
                    'name',
                    'uuid',
                    'quickFilter'
                ]),
                'type' => 'GET'
            ]);
            $result = $this->Cerebrate->saveRemoteOrgs($result);
            $message = __('Added %s new organisations, updated %s existing organisations, %s failures.', $result['add'], $result['edit'], $result['fails']);
            if ($this->_isRest()) {
                return $this->RestResponse->saveSuccessResponse('Cerebrates', 'pull_orgs', $cerebrate_id . '/' . $org_id, false, $message);
            } else {
                $this->Flash->success($message);
                $this->redirect($this->referer());
            }
        } else {
            $this->set('id', $cerebrate['Cerebrate']['id']);
            $this->set('title', __('Sync organisation information'));
            $this->set('question', __('Are you sure you want to download and add / update the remote organisations from the Cerebrate node?'));
            $this->set('actionName', __('Pull all'));
            $this->layout = 'ajax';
            $this->render('/genericTemplates/confirm');
        }




    }

    public function preview_orgs($id)
    {
        $this->set('menuData', ['menuList' => 'sync', 'menuItem' => 'previewCerebrateOrgs']);
        $cerebrate = $this->Cerebrate->find('first', [
            'recursive' => -1,
            'conditions' => ['Cerebrate.id' => $id]
        ]);
        if (empty($cerebrate)) {
            throw new NotFoundException(__('Invalid Cerebrate instance ID provided.'));
        }
        $result = $this->Cerebrate->queryInstance([
            'cerebrate' => $cerebrate,
            'path' => '/organisations/index',
            'params' => $this->IndexFilter->harvestParameters([
                'name',
                'uuid',
                'quickFilter'
            ]),
            'type' => 'GET'
        ]);
        $result = $this->Cerebrate->checkRemoteOrgs($result);
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($result, $this->response->type());
        } else {
            App::uses('CustomPaginationTool', 'Tools');
            $customPagination = new CustomPaginationTool();
            $customPagination->truncateAndPaginate($result, $this->params, false, true);
            $this->set('data', $result);
            $this->set('cerebrate', $cerebrate);
        }
    }

    public function download_org($cerebrate_id, $org_id)
    {
        if ($this->request->is('post')) {
            $cerebrate = $this->Cerebrate->find('first', [
                'recursive' => -1,
                'conditions' => ['Cerebrate.id' => $cerebrate_id]
            ]);
            if (empty($cerebrate)) {
                throw new NotFoundException(__('Invalid Cerebrate instance ID provided.'));
            }
            $result = $this->Cerebrate->queryInstance([
                'cerebrate' => $cerebrate,
                'path' => '/organisations/view/' . $org_id,
                'type' => 'GET'
            ]);
            $saveResult = $this->Cerebrate->captureOrg($result);
            if ($this->_isRest()) {
                if (is_array($saveResult)) {
                    return $this->RestResponse->viewData($saveResult, $this->response->type());
                } else {
                    return $this->RestResponse->saveFailResponse('Cerebrates', 'download_org', $cerebrate_id . '/' . $org_id, $aveResult);
                }
            } else {
                if (is_array($saveResult)) {
                    $this->Flash->success(__('Organisation downloaded.'));
                } else {
                    $this->Flash->error($saveResult);
                }
                $this->redirect($this->referer());
            }
        } else {
            $this->set('id', $data[$modelName]['id']);
            $this->set('title', __('Download organisation information'));
            $this->set('question', __('Are you sure you want to download and add / update the remote organisation?'));
            $this->set('actionName', __('Download'));
            $this->layout = 'ajax';
            $this->render('/genericTemplates/confirm');
        }
    }
}
