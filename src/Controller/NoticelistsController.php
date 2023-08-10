<?php

namespace App\Controller;

use App\Controller\AppController;
use App\Lib\Tools\CustomPaginationTool;
use Cake\Http\Exception\MethodNotAllowedException;
use Cake\Http\Exception\NotFoundException;
use Cake\Http\Response;
use Cake\ORM\Locator\LocatorAwareTrait;

class NoticelistsController extends AppController
{
    use LocatorAwareTrait;

    public $paginate = [
        'limit' => 60,
        'maxLimit' => 9999,
        'order' => [
            'Noticelist.id' => 'DESC'
        ],
    ];

    public function index()
    {
        $this->CRUD->index(
            [
            'quickFilters' => ['name', 'expanded_name'],
            ]
        );
        if ($this->ParamHandler->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('menuData', ['menuList' => 'noticelist', 'menuItem' => 'list_noticelists']);
    }

    public function update()
    {
        $this->Log = $this->fetchTable('Logs');
        //if (!$this->request->is('post')) throw new MethodNotAllowedException('This action is only accessible via POST requests.');
        $result = $this->Noticelists->update();
        $fails = 0;
        $successes = 0;
        if (!empty($result)) {
            if (isset($result['success'])) {
                foreach ($result['success'] as $id => $success) {
                    if (isset($success['old'])) {
                        $change = $success['name'] . ': updated from v' . $success['old'] . ' to v' . $success['new'];
                    } else {
                        $change = $success['name'] . ' v' . $success['new'] . ' installed';
                    }
                    $log = $this->Log->newEntity(
                        [
                        'org' => $this->ACL->getUser()->Organisation->name,
                        'model' => 'Noticelist',
                        'model_id' => $id,
                        'email' => $this->ACL->getUser()->email,
                        'action' => 'update',
                        'user_id' => $this->ACL->getUser()->id,
                        'title' => 'Notice list updated',
                        'changes' => $change,
                        ]
                    );

                    $this->Log->save($log);
                    $successes++;
                }
            }
            if (isset($result['fails'])) {
                foreach ($result['fails'] as $id => $fail) {
                    $log = $this->Log->newEntity(
                        [
                        'org' => $this->ACL->getUser()->Organisation->name,
                        'model' => 'Noticelist',
                        'model_id' => $id,
                        'email' => $this->ACL->getUser()->email,
                        'action' => 'update',
                        'user_id' => $this->ACL->getUser()->id,
                        'title' => 'Notice list failed to update',
                        'changes' => $fail['name'] . ' could not be installed/updated. Error: ' . $fail['fail'],
                        ]
                    );

                    $this->Log->save($log);
                    $fails++;
                }
            }
        } else {
            $log = $this->Log->newEntity(
                [
                'org' => $this->ACL->getUser()->Organisation->name,
                'model' => 'Noticelist',
                'email' => $this->ACL->getUser()->email,
                'action' => 'update',
                'user_id' => $this->ACL->getUser()->id,
                'title' => 'Noticelist update (nothing to update)',
                'changes' => 'Executed an update of the notice lists, but there was nothing to update.',
                ]
            );
            $this->Log->save($log);
        }
        if ($successes == 0 && $fails == 0) {
            $flashType = 'success';
            $message = 'All noticelists are up to date already.';
        } elseif ($successes == 0) {
            $flashType = 'error';
            $message = 'Could not update any of the notice lists';
        } else {
            $flashType = 'success';
            $message = 'Successfully updated ' . $successes . ' noticelists.';
            if ($fails != 0) {
                $message . ' However, could not update ' . $fails . ' notice list.';
            }
        }
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->saveSuccessResponse('Noticelist', 'update', false, false, $message);
        } else {
            $this->Flash->{$flashType}($message);
            $this->redirect(['controller' => 'noticelists', 'action' => 'index']);
        }
    }

    public function toggleEnable($noticelist_id = false)
    {
        if ($this->request->is('post')) {
            $noticelist = $this->Noticelists->find(
                'all',
                [
                'conditions' => ['id' => $noticelist_id],
                'recursive' => -1,
                'fields' => ['id', 'enabled']
                ]
            )->first();

            if ($noticelist === null) {
                $message = __('Noticelist not found.');
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->saveFailResponse('Noticelists', 'toggleEnable', $noticelist_id, $message);
                } else {
                    return new Response(['body' => json_encode(['saved' => false, 'errors' => $message]), 'status' => 200, 'type' => 'json']);
                }
            }

            $enable = (int)!$noticelist['enabled'];

            $noticelist['enabled'] = $enable;
            $result = $this->Noticelists->save($noticelist);

            $message = $enable ? __('Noticelist enabled.') : __('Noticelist disabled.');
            if ($this->ParamHandler->isRest()) {
                return $this->RestResponse->saveSuccessResponse('Noticelists', 'toggleEnable', $noticelist_id, false, $message);
            } else {
                return new Response(['body' => json_encode(['saved' => true, 'success' => $message]), 'status' => 200, 'type' => 'json']);
            }
        } else {
            if ($this->ParamHandler->isRest()) {
                return $this->RestResponse->saveFailResponse('Noticelists', 'toggleEnable', false, __('This endpoint expects a POST request.'), $this->response->getType());
            } else {
                $this->layout = false;
            }
        }
    }

    public function enableNoticelist($id, $enable = false)
    {
        $this->Noticelists->id = $id;
        if (!$this->Noticelists->exists()) {
            throw new NotFoundException(__('Noticelist not found.'));
        }
        // DBMS interoperability: convert boolean false to integer 0 so cakephp doesn't try to insert an empty string into the database
        if ($enable === false) {
            $enable = 0;
        }
        $this->Noticelists->saveField('enabled', $enable);
        $this->Flash->info('Noticelist enabled');
        $this->redirect(['controller' => 'noticelists', 'action' => 'view', $id]);
    }

    public function getToggleField()
    {
        if (!$this->request->is('ajax')) {
            throw new MethodNotAllowedException('This action is available via AJAX only.');
        }
        $this->layout = false;
        $this->render('ajax/getToggleField');
    }

    public function view($id)
    {
        $this->CRUD->view(
            $id,
            [
                'contain' => ['NoticelistEntries']
            ]
        );
        if ($this->ParamHandler->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('id', $id);
        $this->set('menuData', ['menuList' => 'noticelist', 'menuItem' => 'view_noticelist']);
    }

    public function delete($id)
    {
        if ($this->request->is('post')) {
            $id = intval($id);
            $result = $this->Noticelists->quickDelete($id);
            if ($result) {
                $this->Flash->success('Noticelist successfuly deleted.');
                $this->redirect(['controller' => 'noticelists', 'action' => 'index']);
            } else {
                $this->Flash->error('Noticelists could not be deleted.');
                $this->redirect(['controller' => 'noticelists', 'action' => 'index']);
            }
        } else {
            if ($this->request->is('ajax')) {
                $this->set('id', $id);
                $this->render('ajax/delete_confirmation');
            } else {
                throw new MethodNotAllowedException('This function can only be reached via AJAX.');
            }
        }
    }

    public function previewEntries($id)
    {
        $this->set('menuData', ['menuList' => 'sync', 'menuItem' => 'previewNoticelistEntries']);

        $noticelist = $this->Noticelists->find('all', ['contain' => ['NoticelistEntries'], 'conditions' => ['id' => $id]])->first();
        if (empty($noticelist)) {
            throw new NotFoundException(__('Noticelist not found.'));
        }
        $noticelistEntries = $noticelist['noticelist_entries'];

        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData($noticelistEntries);
        } else {
            $customPagination = new CustomPaginationTool();
            $params = $this->request->getQueryParams();
            $customPagination->truncateAndPaginate($noticelistEntries, $params, 'NoticelistEntry', true);
            $this->set('data', $noticelistEntries);
            $this->set('noticelist', $noticelist);
        }
    }
}
