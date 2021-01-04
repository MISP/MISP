<?php
App::uses('AppController', 'Controller');

class NewsController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public $paginate = array(
            'limit' => 5,
            'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
            'order' => array(
                'News.id' => 'DESC'
            ),
    );

    public function index()
    {
        $this->paginate['contain'] = array('User' => array('fields' => array('User.email')));
        $newsItems = $this->paginate();

        $newsread = $this->Auth->user('newsread');
        foreach ($newsItems as $key => $item) {
            if ($item['News']['date_created'] > $newsread) {
                $newsItems[$key]['News']['new'] = true;
            } else {
                $newsItems[$key]['News']['new'] = false;
            }
        }
        $this->set('newsItems', $newsItems);

        $this->loadModel('User');
        $this->User->updateField($this->Auth->user(), 'newsread', time());
    }

    public function add()
    {
        if ($this->request->is('post')) {
            $this->News->create();
            $this->request->data['News']['date_created'] = time();
            if (!isset($this->request->data['News']['anonymise']) || !$this->request->data['News']['anonymise']) {
                $this->request->data['News']['user_id'] = $this->Auth->user('id');
            } else {
                $this->request->data['News']['user_id'] = 0;
            }
            if ($this->News->save($this->request->data)) {
                $this->Flash->success(__('News item added.'));
                $this->redirect(array('action' => 'index'));
            } else {
                $this->Flash->error(__('The news item could not be added.'));
            }
        }
    }

    public function edit($id)
    {
        $this->News->id = $id;
        if (!$this->News->exists()) {
            throw new NotFoundException('Invalid news item.');
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            $this->request->data['News']['id'] = $id;
            if ($this->News->save($this->request->data)) {
                $this->Flash->success(__('News item updated.'));
                $this->redirect(array('action' => 'index'));
            } else {
                $this->Flash->error(__('Could not update news item.'));
            }
        } else {
            $this->request->data = $this->News->read(null, $id);
            $this->set('newsItem', $this->request->data);
        }
    }

    public function delete($id)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException();
        }
        $this->News->id = $id;
        if (!$this->News->exists()) {
            throw new NotFoundException('Invalid news item');
        }
        if ($this->News->delete()) {
            $this->Flash->success(__('News item deleted.'));
            $this->redirect(array('action' => 'index'));
        }
        $this->Flash->error(__('News item could not be deleted.'));
        $this->redirect(array('action' => 'index'));
    }
}
