<?php
App::uses('AppController', 'Controller');

/**
 * @property RestClientHistory $RestClientHistory
 */
class RestClientHistoryController extends AppController
{
    public $components = array('Session', 'RequestHandler');

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
        $conditions = [
            'RestClientHistory.user_id' => $this->Auth->user('id')
        ];
        if ($bookmarked) {
            $conditions['RestClientHistory.bookmark'] = 1;
        }
        $params = [
            'conditions' => $conditions,
            'order' => ['RestClientHistory.timestamp' => 'DESC'],
            'afterFind' => function ($list) {
                return array_column($list, 'RestClientHistory');
            }
        ];
        $this->CRUD->index($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('bookmarked', $bookmarked);
        $this->set('list', $this->viewVars['data']);
        $this->layout = false;
        $this->autoRender = false;
        $this->render('index');
    }

    public function delete($id)
    {
        $params = [
            'conditions' => ['RestClientHistory.user_id' => $this->Auth->user('id')]
        ];
        $this->CRUD->delete($id, $params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }
}
