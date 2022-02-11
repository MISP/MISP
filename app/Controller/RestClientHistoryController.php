<?php

App::uses('AppController', 'Controller');

class RestClientHistoryController extends AppController
{
    public $components = array(
        'AdminCrud',
        'RequestHandler'
    );

    public $paginate = array(
            'limit' => 10,
            'recursive' => -1
    );

    public function beforeFilter()
    {
        parent::beforeFilter();
        $this->Security->unlockedActions = array('delete');
        // We don't care about CSRF protection for deleting these entries.
    }

    public function index($bookmarked = false)
    {
        $params = array(
            'recursive' => -1,
            'conditions' => array(
                'RestClientHistory.user_id' => $this->Auth->user('id')
            ),
            'order' => array(
                'RestClientHistory.timestamp' => 'DESC'
            ),
        );
        if ($bookmarked) {
            $params['conditions']['RestClientHistory.bookmark'] = $bookmarked ? 1 : 0;
        }
        if ($this->_isRest()) {
            $list = $this->RestClientHistory->find('all', $params);
        } else {
            $this->paginate = array_merge($this->paginate, $params);
            $list = $this->paginate();
        }
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($list, $this->response->type());
        } else {
            $this->set('bookmarked', $bookmarked);
            $this->set('list', $list);
            $this->layout = false;
            $this->autoRender = false;
            $this->render('index');
        }
    }

    public function delete($id)
    {
        $entry = $this->RestClientHistory->find('first', array(
            'recursive' => -1,
            'conditions' => array('RestClientHistory.id' => $id, 'RestClientHistory.user_id' => $this->Auth->user('id')),
        ));
        if (empty($entry)) {
            throw new NotFoundException(__('Invalid entry.'));
        }
        $this->RestClientHistory->delete($id);
        return $this->RestResponse->saveSuccessResponse('RestClientHistory', 'delete', $id, false, __('Entry removed.'));
    }
}
