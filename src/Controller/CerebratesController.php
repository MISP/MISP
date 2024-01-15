<?php

namespace App\Controller;

use App\Controller\AppController;
use Cake\Core\Configure;
use Cake\Core\Exception\CakeException;
use Cake\Http\Exception\NotFoundException;
use App\Lib\Tools\CustomPaginationTool;

/**
 * Cerebrates Controller
 *
 * @property \App\Model\Table\CerebratesTable $Cerebrates
 * @method \App\Model\Entity\Cerebrate[]|\Cake\Datasource\ResultSetInterface paginate($object = null, array $settings = [])
 */
class CerebratesController extends AppController
{
    /**
     * Index method
     *
     * @return \Cake\Http\Response|null|void Renders view
     */
    public function index()
    {
        $params = [
            'contain' => ['Organisations'],
            'filters' => ['name', 'url', 'uuid'],
            'quickFilters' => ['name']
        ];
        $this->CRUD->index($params);

        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
    }

    /**
     * View method
     *
     * @param string|null $id Cerebrate id.
     * @return \Cake\Http\Response|null|void Renders view
     * @throws \Cake\Datasource\Exception\RecordNotFoundException When record not found.
     */
    public function view($id = null)
    {
        $this->CRUD->view($id, 
            ['contain' => ['Organisations']]
        );
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }

        $this->set('id', $id);
    }

    /**
     * Add method
     *
     * @return \Cake\Http\Response|null|void Redirects on successful add, renders view otherwise.
     */
    public function add()
    {
        $params = [];
        $this->CRUD->add($params);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }

        $orgs = $this->Cerebrates->Organisations->find('list', [
            'recursive' => -1,
            'fields' => ['id', 'name'],
            'order' => ['lower(name)' => 'ASC']
        ]);
        $dropdownData = [
            'org_id' => $orgs
        ];
        $this->set(compact('dropdownData'));
    }

    /**
     * Edit method
     *
     * @param string|null $id Cerebrate id.
     * @return \Cake\Http\Response|null|void Redirects on successful edit, renders view otherwise.
     * @throws \Cake\Datasource\Exception\RecordNotFoundException When record not found.
     */
    public function edit($id = null)
    {
        $params = [];
        $this->CRUD->edit($id, $params);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }

        $orgs = $this->Cerebrates->Organisations->find('list', [
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

    /**
     * Delete method
     *
     * @param string|null $id Cerebrate id.
     * @return \Cake\Http\Response|null|void Redirects to index.
     * @throws \Cake\Datasource\Exception\RecordNotFoundException When record not found.
     */
    public function delete($id = null)
    {
        $this->CRUD->delete($id);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
    }



    public function pullOrgs($id)
    {
        // FIXME chri - $this->set('menuData', ['menuList' => 'sync', 'menuItem' => 'previewCerebrateOrgs']);
        /** @var \App\Model\Entity\Cerebrate $cerebrate */
        $cerebrate = $this->Cerebrates->findById($id)->first();
        if (empty($cerebrate)) {
            throw new NotFoundException(__('Invalid Cerebrate instance ID provided.'));
        }
        
        if ($this->request->is('post')) {
            $orgs = $cerebrate->queryInstance([
                'path' => '/organisations/index',
                'params' => $this->harvestParameters([
                    'name',
                    'uuid',
                    'quickFilter'
                ]),
                'type' => 'GET'
            ]);
            $result = $cerebrate->saveRemoteOrgs($orgs);
            $message = __('Added {0} new organisations, updated {1} existing organisations, {2} failures.', $result['add'], $result['edit'], $result['fails']);
            if ($this->ParamHandler->isRest()) {
                return $this->RestResponse->saveSuccessResponse('Cerebrates', 'pull_orgs', $id, false, $message);
            } else {
                $this->Flash->success($message);
                $this->redirect($this->referer());
            }
        } else {
            // FIXME chri - this does not seem to work, onClick nothing happens
            $this->set('id', $id);
            $this->set('title', __('Sync organisation information'));
            $this->set('question', __('Are you sure you want to download and add / update the remote organisations from the Cerebrate node?'));
            $this->set('actionName', __('Pull all'));
            $this->layout = false;
            $this->render('/genericTemplates/confirm');
        }
    }

    public function pullSgs($id)
    {
        // FIXME chri - test this - throw new CakeException('Not implemented');
        // $this->set('menuData', ['menuList' => 'sync', 'menuItem' => 'previewCerebrateSgs']);
        /** @var \App\Model\Entity\Cerebrate $cerebrate */
        $cerebrate = $this->Cerebrates->findById($id)->first();
        if (empty($cerebrate)) {
            throw new NotFoundException(__('Invalid Cerebrate instance ID provided.'));
        }

        if ($this->request->is('post')) {
            $sgs = $cerebrate->queryInstance([
                'path' => '/sharingGroups/index',
                'params' => $this->harvestParameters([
                    'name',
                    'uuid',
                    'quickFilter'
                ]),
                'type' => 'GET'
            ]);
            $result = $cerebrate->saveRemoteSgs($sgs, $this->ACL->getUser());
            $message = __('Added {0} new sharing groups, updated {1} existing sharing groups, {2} failures.', $result['add'], $result['edit'], $result['fails']);
            if ($this->ParamHandler->isRest()) {
                return $this->RestResponse->saveSuccessResponse('Cerebrates', 'pull_sgs', $id, false, $message);
            } else {
                $this->Flash->success($message);
                $this->redirect($this->referer());
            }
        } else {
            // FIXME chri - this does not seem to work, onClick nothing happens
            $this->set('id', $id);
            $this->set('title', __('Sync sharing group information'));
            $this->set('question', __('Are you sure you want to download and add / update the remote sharing group from the Cerebrate node?'));
            $this->set('actionName', __('Pull all'));
            $this->layout = false;
            $this->render('/genericTemplates/confirm');
        }
    }

    public function previewOrgs($id = null)
    {
        // FIXME chri - $this->set('menuData', ['menuList' => 'sync', 'menuItem' => 'previewCerebrateOrgs']);
        /** @var \App\Model\Entity\Cerebrate $cerebrate */
        $cerebrate = $this->Cerebrates->findById($id)->first();
        if (empty($cerebrate)) {
            throw new NotFoundException(__('Invalid Cerebrate instance ID provided.'));
        }

        $orgs = $cerebrate->queryInstance([
            'path' => '/organisations/index',
            'params' => $this->harvestParameters([
                'name',
                'uuid',
                'quickFilter'
            ]),
            'type' => 'GET'
        ]);
        $result = $cerebrate->checkRemoteOrgs($orgs);
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData($result, $this->response->getType());
        } else {
            $customPagination = new CustomPaginationTool();
            $passedParams = $this->request->getQueryParams();
            $customPagination->truncateAndPaginate($result, $passedParams, 'Organisations', true);
            $this->set('passedParams', $passedParams);
            $this->set('data', $result);
            $this->set('cerebrate', $cerebrate->toArray());
        }
    }

    public function downloadOrg($cerebrate_id, $org_id)
    {
        if ($this->request->is('post')) {
            /** @var \App\Model\Entity\Cerebrate $cerebrate */
            $cerebrate = $this->Cerebrates->findById($cerebrate_id)->first();
            if (empty($cerebrate)) {
                throw new NotFoundException(__('Invalid Cerebrate instance ID provided.'));
            }
            $result = $cerebrate->queryInstance([
                'path' => '/organisations/view/' . $org_id,
                'type' => 'GET'
            ]);
            $saveResult = $cerebrate->captureOrg($result);
            if ($this->ParamHandler->isRest()) {
                if (is_array($saveResult)) {
                    return $this->RestResponse->viewData($saveResult, $this->response->getType());
                } else {
                    return $this->RestResponse->saveFailResponse('Cerebrates', 'download_org', $cerebrate_id . '/' . $org_id, $saveResult);
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
            // FIXME chri - this does not seem to work, onClick nothing happens
            $this->set('id', $data[$modelName]['id']);
            $this->set('title', __('Download organisation information'));
            $this->set('question', __('Are you sure you want to download and add / update the remote organisation?'));
            $this->set('actionName', __('Download'));
            $this->layout = false;
            $this->render('/genericTemplates/confirm');
        }
    }

    public function previewSharingGroups($id)
    {
        // $this->set('menuData', ['menuList' => 'sync', 'menuItem' => 'previewCerebrateSGs']);
        /** @var \App\Model\Entity\Cerebrate $cerebrate */
        $cerebrate = $this->Cerebrates->findById($id)->first();
        if (empty($cerebrate)) {
            throw new NotFoundException(__('Invalid Cerebrate instance ID provided.'));
        }
        $sgs = $cerebrate->queryInstance([
            'path' => '/sharingGroups/index',
            'params' => $this->harvestParameters([
                'name',
                'uuid',
                'quickFilter'
            ]),
            'type' => 'GET'
        ]);
        if (!empty($sgs))
            $result = $cerebrate->checkRemoteSharingGroups($sgs);
        else $result = [];
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData($result, $this->response->getType());
        } else {
            $customPagination = new CustomPaginationTool();
            $passedParams = $this->request->getQueryParams();
            $customPagination->truncateAndPaginate($result, $passedParams, 'SharingGroups', true);
            $this->set('passedParams', $passedParams);
            $this->set('data', $result);
            $this->set('cerebrate', $cerebrate);
        }
    }

    public function downloadSg($cerebrate_id, $sg_id)
    {
        if ($this->request->is('post')) {
            /** @var \App\Model\Entity\Cerebrate $cerebrate */
            $cerebrate = $this->Cerebrates->findById($cerebrate_id)->first();
            if (empty($cerebrate)) {
                throw new NotFoundException(__('Invalid Cerebrate instance ID provided.'));
            }
            $result = $cerebrate->queryInstance([
                'path' => '/sharingGroups/view/' . $sg_id,
                'type' => 'GET'
            ]);
            $saveResult = $cerebrate->captureSg($result, $this->ACL->getUser());
            if ($this->ParamHandler->isRest()) {
                if (is_array($saveResult)) {
                    return $this->RestResponse->viewData($saveResult, $this->response->getType());
                } else {
                    return $this->RestResponse->saveFailResponse('Cerebrates', 'download_sg', $cerebrate_id . '/' . $sg_id, $saveResult);
                }
            } else {
                if (is_array($saveResult)) {
                    $this->Flash->success(__('Sharing Group downloaded.'));
                } else {
                    $this->Flash->error($saveResult);
                }
                $this->redirect($this->referer());
            }
        } else {
            // FIXME chri - this does not seem to work, onClick nothing happens
            $this->set('id', $cerebrate_id);
            $this->set('title', __('Download sharing group information'));
            $this->set('question', __('Are you sure you want to download and add / update the remote sharing group?'));
            $this->set('actionName', __('Download'));
            $this->layout = false;
            $this->render('/genericTemplates/confirm');
        }
    }
}
