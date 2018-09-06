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
        $this->paginate['recursive'] = -1;
        if ($this->_isRest()) {
            $noticelists = $this->Noticelist->find('all', $this->paginate);
            foreach ($noticelists as $k => $v) {
                $noticelists[$k]['Noticelist']['ref'] = json_decode($noticelists[$k]['Noticelist']['ref']);
                $noticelists[$k]['Noticelist']['geographical_area'] = json_decode($noticelists[$k]['Noticelist']['geographical_area']);
            }
            return $this->RestResponse->viewData($noticelists, $this->response->type());
        } else {
            $noticelists = $this->paginate();
            foreach ($noticelists as $k => $v) {
                $noticelists[$k]['Noticelist']['ref'] = json_decode($noticelists[$k]['Noticelist']['ref']);
                $noticelists[$k]['Noticelist']['geographical_area'] = json_decode($noticelists[$k]['Noticelist']['geographical_area']);
            }
            $this->set('noticelists', $noticelists);
        }
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

    public function toggleEnable()
    {
        $id = $this->request->data['Noticelist']['data'];
        if (!is_numeric($id)) {
            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Noticelist not found.')), 'status' => 200, 'type' => 'json'));
        }
        $currentState = $this->Noticelist->find('first', array('conditions' => array('id' => $id), 'recursive' => -1));
        if (empty($currentState)) {
            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Noticelist not found.')), 'status' => 200, 'type' => 'json'));
        }
        $currentState['Noticelist']['ref'] = json_decode($currentState['Noticelist']['ref']);
        $currentState['Noticelist']['geographical_area'] = json_decode($currentState['Noticelist']['geographical_area']);
        if ($currentState['Noticelist']['enabled']) {
            $currentState['Noticelist']['enabled'] = 0;
            $message = 'disabled';
        } else {
            $currentState['Noticelist']['enabled'] = 1;
            $message = 'enabled';
        }
        if ($this->Noticelist->save($currentState)) {
            return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Noticelist ' . $message)), 'status' => 200, 'type' => 'json'));
        } else {
            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Noticelist could not be enabled.')), 'status' => 200, 'type' => 'json'));
        }
    }

    public function enableNoticelist($id, $enable = false)
    {
        $this->Noticelist->id = $id;
        if (!$this->Noticelist->exists()) {
            throw new NotFoundException('Invalid Noticelist.');
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
        if (!is_numeric($id)) {
            throw new NotFoundException('Invalid ID.');
        }
        $noticelist = $this->Noticelist->find('first', array('contain' => array('NoticelistEntry'), 'conditions' => array('id' => $id)));
        if (empty($noticelist)) {
            throw new NotFoundException('Noticelist not found.');
        }
        if ($this->_isRest()) {
            $noticelist['Noticelist']['NoticelistEntry'] = $noticelist['NoticelistEntry'];
            return $this->RestResponse->viewData($noticelist, $this->response->type());
        } else {
            $this->set('noticelist', $noticelist);
        }
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
}
