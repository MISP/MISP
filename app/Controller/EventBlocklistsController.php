<?php
App::uses('AppController', 'Controller');

class EventBlocklistsController extends AppController
{
    public $components = array('Session', 'RequestHandler', 'BlockList');

    public function beforeFilter()
    {
        parent::beforeFilter();
        if (false === Configure::read('MISP.enableEventBlocklisting')) {
            $this->Flash->info(__('Event Blocklisting is not currently enabled on this instance.'));
            $this->redirect('/');
        }
    }

    public $paginate = array(
            'limit' => 60,
            'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
            'order' => array(
                    'EventBlocklist.created' => 'DESC'
            ),
    );

    public function index()
    {
        $passedArgsArray = array();
        $passedArgs = $this->passedArgs;
        $params = array();
        $validParams = array('event_uuid', 'comment', 'event_info', 'event_orgc');
        foreach ($validParams as $validParam) {
            if (!empty($this->params['named'][$validParam])) {
                $params[$validParam] = $this->params['named'][$validParam];
            }
        }
        if (!empty($this->params['named']['searchall'])) {
            $params['AND']['OR'] = array(
                'event_uuid' => $this->params['named']['searchall'],
                'comment' => $this->params['named']['searchall'],
                'event_info' => $this->params['named']['searchall'],
                'event_orgc' => $this->params['named']['searchall']
            );
        }
        $this->set('passedArgs', json_encode($passedArgs));
        $this->set('passedArgsArray', $passedArgsArray);
        return $this->BlockList->index($this->_isRest(), $params);
    }

    public function add()
    {
        return $this->BlockList->add($this->_isRest());
    }

    public function edit($id)
    {
        return $this->BlockList->edit($this->_isRest(), $id);
    }

    public function delete($id)
    {
        return $this->BlockList->delete($this->_isRest(), $id);
    }

    public function massDelete()
    {
        if ($this->request->is('post') || $this->request->is('put')) {
            if (!isset($this->request->data['EventBlocklist'])) {
                $this->request->data = array('EventBlocklist' => $this->request->data);
            }
            $ids = $this->request->data['EventBlocklist']['ids'];
            $event_ids = json_decode($ids, true);
            if (empty($event_ids)) {
                throw new NotFoundException(__('Invalid event IDs.'));
            }
            $result = $this->EventBlocklist->deleteAll(array('EventBlocklist.id' => $event_ids));
            if ($result) {
                if ($this->_isRest()) {
                    return $this->RestResponse->saveSuccessResponse('EventBlocklist', 'Deleted', $ids, $this->response->type());
                } else {
                    $this->Flash->success('Blocklist entry removed');
                    $this->redirect(array('controller' => 'eventBlocklists', 'action' => 'index'));
                }
            } else {
                $error = __('Failed to delete Event from EventBlocklist. Error: ') . PHP_EOL . h($result);
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('EventBlocklist', 'Deleted', false, $error, $this->response->type());
                } else {
                    $this->Flash->error($error);
                    $this->redirect(array('controller' => 'eventBlocklists', 'action' => 'index'));
                }
            }
        } else {
            $ids = json_decode($this->request->query('ids'), true);
            if (empty($ids)) {
                throw new NotFoundException(__('Invalid event blocklist IDs.'));

            }
            $this->set('event_ids', $ids);
        }
    }
}
