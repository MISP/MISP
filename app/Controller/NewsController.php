<?php
App::uses('AppController', 'Controller');

/**
 * @property News $News
 */
class NewsController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public $paginate = array(
        'limit' => 5,
        'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user can view/page.
        'order' => [
            'News.id' => 'DESC'
        ],
        'contain' => [
            'User' => ['fields' => ['User.email']],
        ]
    );

    public function index()
    {
        $user = $this->Auth->user();
        $newsItems = $this->paginate();

        $newsread = $user['newsread'];
        $hasUnreadNews = false;
        foreach ($newsItems as &$item) {
            $isNew = $item['News']['date_created'] > $newsread;
            $item['News']['new'] = $isNew;
            if ($isNew) {
                $hasUnreadNews = true;
            }
        }
        $this->set('newsItems', $newsItems);
        $this->set('hasUnreadNews', $hasUnreadNews);

        if ($hasUnreadNews) {
            $homepage = $this->User->UserSetting->getValueForUser($user['id'], 'homepage');
            if (!empty($homepage)) {
                $this->set('homepage', $homepage);
            } else {
                $this->set('homepage', "{$this->baseurl}/events/index");
            }

            $this->User->updateField($user, 'newsread', time());
        }
    }

    public function admin_index()
    {
        $user = $this->Auth->user();
        $this->paginate['limit'] = 25;
        $newsItems = $this->paginate();

        $this->set('newsItems', $newsItems);
        $this->set('user', $user);
    }

    public function add()
    {
        $currentUser = $this->Auth->user();
        $params = [
            'beforeSave' => function ($data) use ($currentUser) {
                $data['News']['date_created'] = time();
                if (empty($data['News']['anonymise'])) {
                    $data['News']['user_id'] = $currentUser['id'];
                } else {
                    $data['News']['user_id'] = 0;
                }
                return $data;
            },
            'redirect' => ['action' => 'index']
        ];
        $this->CRUD->add($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }

    public function edit($id)
    {
        $params = [
            'redirect' => ['action' => 'index']
        ];
        $this->CRUD->edit($id, $params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('newsItem', $this->request->data);
        $this->render('add');
    }

    public function delete($id)
    {
        $this->CRUD->delete($id);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }
}
