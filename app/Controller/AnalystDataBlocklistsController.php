<?php
App::uses('AppController', 'Controller');

class AnalystDataBlocklistsController extends AppController
{
    public $components = array('Session', 'RequestHandler', 'BlockList');

    public $paginate = array(
            'limit' => 60,
            'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 entries <- no we won't, this is the max a user van view/page.
            'order' => array(
                'AnalystDataBlocklist.created' => 'DESC'
            ),
    );

    public function index()
    {
        $passedArgsArray = array();
        $passedArgs = $this->passedArgs;
        $params = array();
        $validParams = array('analyst_data_uuid', 'comment', 'analyst_data_info', 'analyst_data_orgc');
        foreach ($validParams as $validParam) {
            if (!empty($this->params['named'][$validParam])) {
                $params[$validParam] = $this->params['named'][$validParam];
            }
        }
        if (!empty($this->params['named']['searchall'])) {
            $params['AND']['OR'] = array(
                'analyst_data_uuid' => $this->params['named']['searchall'],
                'comment' => $this->params['named']['searchall'],
                'analyst_data_info' => $this->params['named']['searchall'],
                'analyst_data_orgc' => $this->params['named']['searchall']
            );
        }
        $this->set('passedArgs', json_encode($passedArgs));
        $this->set('passedArgsArray', $passedArgsArray);
        return $this->BlockList->index($this->_isRest(), $params);
    }

    public function add()
    {
        $this->set('action', 'add');
        return $this->BlockList->add($this->_isRest());
    }

    public function edit($id)
    {
        $this->set('action', 'edit');
        return $this->BlockList->edit($this->_isRest(), $id);
    }

    public function delete($id)
    {
        if (Validation::uuid($id)) {
            $entry = $this->AnalystDataBlocklist->find('first', array(
                'conditions' => array('analyst_data_uuid' => $id)
            ));
            if (empty($entry)) {
                throw new NotFoundException(__('Invalid blocklist entry'));
            }
            $id = $entry['AnalystDataBlocklist']['id'];
        }
        return $this->BlockList->delete($this->_isRest(), $id);
    }

    public function massDelete()
    {
        if ($this->request->is('post') || $this->request->is('put')) {
            if (!isset($this->request->data['AnalystDataBlocklist'])) {
                $this->request->data = array('AnalystDataBlocklist' => $this->request->data);
            }
            $ids = $this->request->data['AnalystDataBlocklist']['ids'];
            $analyst_data_ids = json_decode($ids, true);
            if (empty($analyst_data_ids)) {
                throw new NotFoundException(__('Invalid Analyst Data IDs.'));
            }
            $result = $this->AnalystDataBlocklist->deleteAll(array('AnalystDataBlocklist.id' => $analyst_data_ids));
            if ($result) {
                if ($this->_isRest()) {
                    return $this->RestResponse->saveSuccessResponse('AnalystDataBlocklist', 'Deleted', $ids, $this->response->type());
                } else {
                    $this->Flash->success('Blocklist entry removed');
                    $this->redirect(array('controller' => 'AnalystDataBlocklist', 'action' => 'index'));
                }
            } else {
                $error = __('Failed to delete Analyst Data from AnalystDataBlocklist. Error: ') . PHP_EOL . h($result);
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('AnalystDataBlocklist', 'Deleted', false, $error, $this->response->type());
                } else {
                    $this->Flash->error($error);
                    $this->redirect(array('controller' => 'AnalystDataBlocklists', 'action' => 'index'));
                }
            }
        } else {
            $ids = json_decode($this->request->query('ids'), true);
            if (empty($ids)) {
                throw new NotFoundException(__('Invalid analyst data IDs.'));

            }
            $this->set('analyst_data_ids', $ids);
        }
    }
}
