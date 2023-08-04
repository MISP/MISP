<?php

namespace App\Controller;

use App\Controller\AppController;
use Cake\Http\Exception\MethodNotAllowedException;
use Cake\Http\Exception\NotFoundException;
use Cake\Http\Response;
use App\Lib\Tools\CustomPaginationTool;
use Cake\ORM\Locator\LocatorAwareTrait;
use App\Model\Entity\Log;

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

    public $quickFilterFields = [['name' => true], ['expanded_name' => true], ['geographical_area' => true],];
    public $filterFields = [
        'name', 'expanded_name', 'geographical_area', 'version', 'enabled',
    ];
    public $containFields = [
        'NoticelistEntries'
    ];
    public $statisticsFields = ['enabled',];


    public function index()
    {
        $this->CRUD->index([
            'filters' => $this->filterFields,
            'quickFilters' => $this->quickFilterFields,
            'quickFilterForMetaField' => ['enabled' => true, 'wildcard_search' => true],
            'contain' => $this->containFields,
            'statisticsFields' => $this->statisticsFields,
        ]);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
    }


    public function filtering()
    {
        $this->CRUD->filtering();
    }

    public function update()
    {
        $this->Log = $this->fetchTable('Logs');
        if (!$this->request->is('post')) throw new MethodNotAllowedException('This action is only accessible via POST requests.');
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
                    $log = new Log([
                        'org' => $this->ACL->getUser()->Organisation->name,
                        'model' => 'Noticelist',
                        'model_id' => $id,
                        'email' => $this->ACL->getUser()->email,
                        'action' => 'update',
                        'user_id' => $this->ACL->getUser()->id,
                        'title' => 'Notice list updated',
                        'changes' => $change,
                        'created' => date('Y-m-d H:i:s')
                    ]);

                    $this->Log->save($log);
                    $successes++;
                }
            }
            if (isset($result['fails'])) {
                foreach ($result['fails'] as $id => $fail) {
                    $log = new Log([
                        'org' => $this->ACL->getUser()->Organisation->name,
                        'model' => 'Noticelist',
                        'model_id' => $id,
                        'email' => $this->ACL->getUser()->email,
                        'action' => 'update',
                        'user_id' => $this->ACL->getUser()->id,
                        'title' => 'Notice list failed to update',
                        'changes' => $fail['name'] . ' could not be installed/updated. Error: ' . $fail['fail'],
                        'created' => date('Y-m-d H:i:s')
                    ]);

                    $this->Log->save($log);
                    $fails++;
                }
            }
        } else {
            $log = new Log([
                'org' => $this->ACL->getUser()->Organisation->name,
                'model' => 'Noticelist',
                'email' => $this->ACL->getUser()->email,
                'action' => 'update',
                'user_id' => $this->ACL->getUser()->id,
                'title' => 'Noticelist update (nothing to update)',
                'changes' => 'Executed an update of the notice lists, but there was nothing to update.',
                'created' => date('Y-m-d H:i:s')
            ]);
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
            $this->redirect(array('controller' => 'noticelists', 'action' => 'index'));
        }
    }

    public function toggleEnable($noticelist_id = false)
    {
        if ($this->request->is('post')) {
            $noticelist = $this->Noticelists->find('all', array(
                'conditions' => array('id' => $noticelist_id),
                'recursive' => -1,
                'fields' => array('id', 'enabled')
            ))->first();

            if ($noticelist === null) {
                $message = __('Noticelist not found.');
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->saveFailResponse('Noticelists', 'toggleEnable', $noticelist_id, $message);
                } else {
                    return new Response(array('body' => json_encode(array('saved' => false, 'errors' => $message)), 'status' => 200, 'type' => 'json'));
                }
            }

            $enable = (int)!$noticelist['enabled'];

            $noticelist['enabled'] = $enable;
            $result = $this->Noticelists->save($noticelist);

            $message = $enable ? __('Noticelist enabled.') : __('Noticelist disabled.');
            if ($this->ParamHandler->isRest()) {
                return $this->RestResponse->saveSuccessResponse('Noticelists', 'toggleEnable', $noticelist_id, false, $message);
            } else {
                return new Response(array('body' => json_encode(array('saved' => true, 'success' => $message)), 'status' => 200, 'type' => 'json'));
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
        $this->redirect(array('controller' => 'noticelists', 'action' => 'view', $id));
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
        $params = [
        ];
        $this->CRUD->view($id, $params);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
    }

    public function delete($id)
    {
        if ($this->request->is('post')) {
            $id = intval($id);
            $result = $this->Noticelists->quickDelete($id);
            if ($result) {
                $this->Flash->success('Noticelist successfuly deleted.');
                $this->redirect(array('controller' => 'noticelists', 'action' => 'index'));
            } else {
                $this->Flash->error('Noticelists could not be deleted.');
                $this->redirect(array('controller' => 'noticelists', 'action' => 'index'));
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
        $noticelist = $this->Noticelists->find()
            ->contain(['NoticelistEntries'])
            ->where(['id' => $id])
            ->disableHydration(true)
            ->first();
        if (empty($noticelist)) {
            throw new NotFoundException(__('Noticelist not found.'));
        }
        $noticelistEntries = $noticelist['NoticelistEntry'];

        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData($noticelistEntries);
        } else {
            $customPagination = new CustomPaginationTool();
            $passedParams = $this->request->getQueryParams();
            $customPagination->truncateAndPaginate($noticelistEntries, $passedParams, 'NoticelistEntry', true);
            $this->set('passedParams', $passedParams);
            $this->set('data', $noticelistEntries);
            $this->set('noticelist', $noticelist);
        }
    }
}
