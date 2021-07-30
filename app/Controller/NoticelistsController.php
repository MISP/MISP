<?php
App::uses('AppController', 'Controller');

class NoticelistsController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public $paginate = array(
        'limit' => 60,
        'maxLimit' => 9999,
        'order' => array(
            'Noticelist.id' => 'DESC'
        ),
    );

    public function index()
    {
        $this->CRUD->index([
            'quickFilters' => ['name', 'expanded_name'],
            'afterFind' => function (array $noticelists) {
                foreach ($noticelists as &$noticelist) {
                    $noticelist['Noticelist']['ref'] = json_decode($noticelist['Noticelist']['ref']);
                    $noticelist['Noticelist']['geographical_area'] = json_decode($noticelist['Noticelist']['geographical_area']);
                }
                return $noticelists;
            }
        ]);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('menuData', array('menuList' => 'noticelist', 'menuItem' => 'list_noticelists'));
    }

    public function update()
    {
        //if (!$this->request->is('post')) throw new MethodNotAllowedException('This action is only accessible via POST requests.');
        $result = $this->Noticelist->update();
        $this->Log = ClassRegistry::init('Log');
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
                    $this->Log->create();
                    $this->Log->save(array(
                        'org' => $this->Auth->user('Organisation')['name'],
                        'model' => 'Noticelist',
                        'model_id' => $id,
                        'email' => $this->Auth->user('email'),
                        'action' => 'update',
                        'user_id' => $this->Auth->user('id'),
                        'title' => 'Notice list updated',
                        'change' => $change,
                    ));
                    $successes++;
                }
            }
            if (isset($result['fails'])) {
                foreach ($result['fails'] as $id => $fail) {
                    $this->Log->create();
                    $this->Log->save(array(
                        'org' => $this->Auth->user('Organisation')['name'],
                        'model' => 'Noticelist',
                        'model_id' => $id,
                        'email' => $this->Auth->user('email'),
                        'action' => 'update',
                        'user_id' => $this->Auth->user('id'),
                        'title' => 'Notice list failed to update',
                        'change' => $fail['name'] . ' could not be installed/updated. Error: ' . $fail['fail'],
                    ));
                    $fails++;
                }
            }
        } else {
            $this->Log->create();
            $this->Log->save(array(
                'org' => $this->Auth->user('Organisation')['name'],
                'model' => 'Noticelist',
                'model_id' => 0,
                'email' => $this->Auth->user('email'),
                'action' => 'update',
                'user_id' => $this->Auth->user('id'),
                'title' => 'Noticelist update (nothing to update)',
                'change' => 'Executed an update of the notice lists, but there was nothing to update.',
            ));
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
        if ($this->_isRest()) {
            return $this->RestResponse->saveSuccessResponse('Noticelist', 'update', false, $this->response->type(), $message);
        } else {
            $this->Flash->{$flashType}($message);
            $this->redirect(array('controller' => 'noticelists', 'action' => 'index'));
        }
    }

    public function toggleEnable($noticelist_id = false)
    {
        if ($this->request->is('post')) {
            $noticelist = $this->Noticelist->find('first', array(
                'conditions' => array('id' => $noticelist_id),
                'recursive' => -1,
                'fields' => array('Noticelist.id', 'Noticelist.enabled')
            ));

            if ($noticelist === null) {
                $message = __('Noticelist not found.');
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('Noticelists', 'toggleEnable', $noticelist_id, $message, $this->response->type());
                } else {
                    return new CakeResponse(array('body' => json_encode(array('saved' => false, 'errors' => $message)), 'status' => 200, 'type' => 'json'));
                }
            }

            $enable = (int)!$noticelist['Noticelist']['enabled'];

            $noticelist['Noticelist']['enabled'] = $enable;
            $result = $this->Noticelist->save($noticelist);

            $message = $enable ? __('Noticelist enabled.') : __('Noticelist disabled.');
            if ($this->_isRest()) {
                return $this->RestResponse->saveSuccessResponse('Noticelists', 'toggleEnable', $noticelist_id, $this->response->type(), $message);
            } else {
                return new CakeResponse(array('body' => json_encode(array('saved' => true, 'success' => $message)), 'status' => 200, 'type' => 'json'));
            }
        } else {
            if ($this->_isRest()) {
                return $this->RestResponse->saveFailResponse('Noticelists', 'toggleEnable', false, __('This endpoint expects a POST request.'), $this->response->type());
            } else {
                $this->layout = false;
            }
        }
    }

    public function enableNoticelist($id, $enable = false)
    {
        $this->Noticelist->id = $id;
        if (!$this->Noticelist->exists()) {
            throw new NotFoundException(__('Noticelist not found.'));
        }
        // DBMS interoperability: convert boolean false to integer 0 so cakephp doesn't try to insert an empty string into the database
        if ($enable === false) {
            $enable = 0;
        }
        $this->Noticelist->saveField('enabled', $enable);
        $this->Flash->info('Noticelist enabled');
        $this->redirect(array('controller' => 'noticelists', 'action' => 'view', $id));
    }

    public function getToggleField()
    {
        if (!$this->request->is('ajax')) {
            throw new MethodNotAllowedException('This action is available via AJAX only.');
        }
        $this->layout = 'ajax';
        $this->render('ajax/getToggleField');
    }

    public function view($id)
    {
        $this->CRUD->view(
            $id,
            [
                'contain' => ['NoticelistEntry'],
                'afterFind' => function (array $noticelist) {
                    $noticelist['Noticelist']['ref'] = json_decode($noticelist['Noticelist']['ref']);
                    $noticelist['Noticelist']['geographical_area'] = json_decode($noticelist['Noticelist']['geographical_area']);
                    $noticelist['Noticelist']['NoticelistEntry'] = $noticelist['NoticelistEntry'] ? $noticelist['NoticelistEntry'] : [];
                    unset($noticelist['NoticelistEntry']);

                    return $noticelist;
                }
            ]
        );
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('id', $id);
        $this->set('menuData', array('menuList' => 'noticelist', 'menuItem' => 'view_noticelist'));
    }

    public function delete($id)
    {
        if ($this->request->is('post')) {
            $id = intval($id);
            $result = $this->Noticelist->quickDelete($id);
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

    public function preview_entries($id)
    {
        $this->set('menuData', ['menuList' => 'sync', 'menuItem' => 'previewNoticelistEntries']);

        $noticelist = $this->Noticelist->find('first', array('contain' => array('NoticelistEntry'), 'conditions' => array('id' => $id)));
        if (empty($noticelist)) {
            throw new NotFoundException(__('Noticelist not found.'));
        }
        $noticelistEntries = $noticelist['NoticelistEntry'];

        if ($this->_isRest()) {
            return $this->RestResponse->viewData($noticelistEntries, $this->response->type());
        } else {
            App::uses('CustomPaginationTool', 'Tools');
            $customPagination = new CustomPaginationTool();
            $customPagination->truncateAndPaginate($noticelistEntries, $this->params, false, true);
            $this->set('data', $noticelistEntries);
            $this->set('noticelist', $noticelist);
        }
    }
}
