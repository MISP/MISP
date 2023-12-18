<?php

namespace App\Controller;

use App\Controller\AppController;
use Cake\Core\Configure;
use Cake\Core\Exception\CakeException;


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



    public function pull_orgs($id)
    {
        throw new CakeException('Not implemented');

        // $this->set('menuData', ['menuList' => 'sync', 'menuItem' => 'previewCerebrateOrgs']);
        // $cerebrate = $this->Cerebrate->find('first', [
        //     'recursive' => -1,
        //     'conditions' => ['Cerebrate.id' => $id]
        // ]);
        // if (empty($cerebrate)) {
        //     throw new NotFoundException(__('Invalid Cerebrate instance ID provided.'));
        // }

        // if ($this->request->is('post')) {
        //     $result = $this->Cerebrate->queryInstance([
        //         'cerebrate' => $cerebrate,
        //         'path' => '/organisations/index',
        //         'params' => $this->IndexFilter->harvestParameters([
        //             'name',
        //             'uuid',
        //             'quickFilter'
        //         ]),
        //         'type' => 'GET'
        //     ]);
        //     $result = $this->Cerebrate->saveRemoteOrgs($result);
        //     $message = __('Added %s new organisations, updated %s existing organisations, %s failures.', $result['add'], $result['edit'], $result['fails']);
        //     if ($this->_isRest()) {
        //         return $this->RestResponse->saveSuccessResponse('Cerebrates', 'pull_orgs', $cerebrate_id, false, $message);
        //     } else {
        //         $this->Flash->success($message);
        //         $this->redirect($this->referer());
        //     }
        // } else {
        //     $this->set('id', $cerebrate['Cerebrate']['id']);
        //     $this->set('title', __('Sync organisation information'));
        //     $this->set('question', __('Are you sure you want to download and add / update the remote organisations from the Cerebrate node?'));
        //     $this->set('actionName', __('Pull all'));
        //     $this->layout = false;
        //     $this->render('/genericTemplates/confirm');
        // }
    }

    public function pull_sgs($id)
    {
        throw new CakeException('Not implemented');

        // $this->set('menuData', ['menuList' => 'sync', 'menuItem' => 'previewCerebrateSgs']);
        // $cerebrate = $this->Cerebrate->find('first', [
        //     'recursive' => -1,
        //     'conditions' => ['Cerebrate.id' => $id]
        // ]);
        // if (empty($cerebrate)) {
        //     throw new NotFoundException(__('Invalid Cerebrate instance ID provided.'));
        // }

        // if ($this->request->is('post')) {
        //     $result = $this->Cerebrate->queryInstance([
        //         'cerebrate' => $cerebrate,
        //         'path' => '/sharingGroups/index',
        //         'params' => $this->IndexFilter->harvestParameters([
        //             'name',
        //             'uuid',
        //             'quickFilter'
        //         ]),
        //         'type' => 'GET'
        //     ]);
        //     $result = $this->Cerebrate->saveRemoteSgs($result, $this->Auth->user());
        //     $message = __('Added %s new sharing groups, updated %s existing sharing groups, %s failures.', $result['add'], $result['edit'], $result['fails']);
        //     if ($this->_isRest()) {
        //         return $this->RestResponse->saveSuccessResponse('Cerebrates', 'pull_sgs', $cerebrate_id, false, $message);
        //     } else {
        //         $this->Flash->success($message);
        //         $this->redirect($this->referer());
        //     }
        // } else {
        //     $this->set('id', $cerebrate['Cerebrate']['id']);
        //     $this->set('title', __('Sync sharing group information'));
        //     $this->set('question', __('Are you sure you want to download and add / update the remote sharing group from the Cerebrate node?'));
        //     $this->set('actionName', __('Pull all'));
        //     $this->layout = false;
        //     $this->render('/genericTemplates/confirm');
        // }
    }

    public function previewOrgs($id = null)
    {
        throw new CakeException('Not implemented');

        // // FIXME chri - $this->set('menuData', ['menuList' => 'sync', 'menuItem' => 'previewCerebrateOrgs']);
        // /** @var Cerebrate $cerebrate */
        // $cerebrate = $this->Cerebrates->findById($id)->first();
        // if (empty($cerebrate)) {
        //     throw new NotFoundException(__('Invalid Cerebrate instance ID provided.'));
        // }

        // $result = $cerebrate->queryInstance([
        //     'path' => '/organisations/index',
        //     'params' => $this->harvestParameters([
        //         'name',
        //         'uuid',
        //         'quickFilter'
        //     ]),
        //     'type' => 'GET'
        // ]);
        // $result = $this->Cerebrates->checkRemoteOrgs($result);
        // if ($this->_isRest()) {
        //     return $this->RestResponse->viewData($result, $this->response->type());
        // } else {
        //     App::uses('CustomPaginationTool', 'Tools');
        //     $customPagination = new CustomPaginationTool();
        //     $customPagination->truncateAndPaginate($result, $this->params, false, true);
        //     $this->set('data', $result);
        //     $this->set('cerebrate', $cerebrate);
        // }
    }

    public function download_org($cerebrate_id, $org_id)
    {
        throw new CakeException('Not implemented');

        // if ($this->request->is('post')) {
        //     $cerebrate = $this->Cerebrate->find('first', [
        //         'recursive' => -1,
        //         'conditions' => ['Cerebrate.id' => $cerebrate_id]
        //     ]);
        //     if (empty($cerebrate)) {
        //         throw new NotFoundException(__('Invalid Cerebrate instance ID provided.'));
        //     }
        //     $result = $this->Cerebrate->queryInstance([
        //         'cerebrate' => $cerebrate,
        //         'path' => '/organisations/view/' . $org_id,
        //         'type' => 'GET'
        //     ]);
        //     $saveResult = $this->Cerebrate->captureOrg($result);
        //     if ($this->_isRest()) {
        //         if (is_array($saveResult)) {
        //             return $this->RestResponse->viewData($saveResult, $this->response->type());
        //         } else {
        //             return $this->RestResponse->saveFailResponse('Cerebrates', 'download_org', $cerebrate_id . '/' . $org_id, $saveResult);
        //         }
        //     } else {
        //         if (is_array($saveResult)) {
        //             $this->Flash->success(__('Organisation downloaded.'));
        //         } else {
        //             $this->Flash->error($saveResult);
        //         }
        //         $this->redirect($this->referer());
        //     }
        // } else {
        //     $this->set('id', $data[$modelName]['id']);
        //     $this->set('title', __('Download organisation information'));
        //     $this->set('question', __('Are you sure you want to download and add / update the remote organisation?'));
        //     $this->set('actionName', __('Download'));
        //     $this->layout = false;
        //     $this->render('/genericTemplates/confirm');
        // }
    }

    public function preview_sharing_groups($id)
    {
        throw new CakeException('Not implemented');
        // $this->set('menuData', ['menuList' => 'sync', 'menuItem' => 'previewCerebrateSGs']);
        // $cerebrate = $this->Cerebrate->find('first', [
        //     'recursive' => -1,
        //     'conditions' => ['Cerebrate.id' => $id]
        // ]);
        // if (empty($cerebrate)) {
        //     throw new NotFoundException(__('Invalid Cerebrate instance ID provided.'));
        // }
        // $result = $this->Cerebrate->queryInstance([
        //     'cerebrate' => $cerebrate,
        //     'path' => '/sharingGroups/index',
        //     'params' => $this->IndexFilter->harvestParameters([
        //         'name',
        //         'uuid',
        //         'quickFilter'
        //     ]),
        //     'type' => 'GET'
        // ]);
        // $result = $this->Cerebrate->checkRemoteSharingGroups($result);
        // if ($this->_isRest()) {
        //     return $this->RestResponse->viewData($result, $this->response->type());
        // } else {
        //     App::uses('CustomPaginationTool', 'Tools');
        //     $customPagination = new CustomPaginationTool();
        //     $customPagination->truncateAndPaginate($result, $this->params, false, true);
        //     $this->set('data', $result);
        //     $this->set('cerebrate', $cerebrate);
        // }
    }

    public function download_sg($cerebrate_id, $sg_id)
    {
        throw new CakeException('Not implemented');

        // if ($this->request->is('post')) {
        //     $cerebrate = $this->Cerebrate->find('first', [
        //         'recursive' => -1,
        //         'conditions' => ['Cerebrate.id' => $cerebrate_id]
        //     ]);
        //     if (empty($cerebrate)) {
        //         throw new NotFoundException(__('Invalid Cerebrate instance ID provided.'));
        //     }
        //     $result = $this->Cerebrate->queryInstance([
        //         'cerebrate' => $cerebrate,
        //         'path' => '/sharingGroups/view/' . $sg_id,
        //         'type' => 'GET'
        //     ]);
        //     $saveResult = $this->Cerebrate->captureSg($result, $this->Auth->user());
        //     if ($this->_isRest()) {
        //         if (is_array($saveResult)) {
        //             return $this->RestResponse->viewData($saveResult, $this->response->type());
        //         } else {
        //             return $this->RestResponse->saveFailResponse('Cerebrates', 'download_sg', $cerebrate_id . '/' . $sg_id, $saveResult);
        //         }
        //     } else {
        //         if (is_array($saveResult)) {
        //             $this->Flash->success(__('Sharing Group downloaded.'));
        //         } else {
        //             $this->Flash->error($saveResult);
        //         }
        //         $this->redirect($this->referer());
        //     }
        // } else {
        //     $this->set('id', $cerebrate_id);
        //     $this->set('title', __('Download sharing group information'));
        //     $this->set('question', __('Are you sure you want to download and add / update the remote sharing group?'));
        //     $this->set('actionName', __('Download'));
        //     $this->layout = false;
        //     $this->render('/genericTemplates/confirm');
        // }
    }
}
