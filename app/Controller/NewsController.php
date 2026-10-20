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
        // The navbar's news panel loads its list from here
        $panel = $this->request->is('ajax') && $this->theme === 'Overmind';
        if ($panel) {
            $this->paginate['limit'] = 10;
        }
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
            // This one is emitted as a bare href with no baseurl in front of it
            // (News/index.ctp), so an unchecked '//attacker.example' is an
            // off-site link regardless of how MISP.baseurl is configured.
            $homepagePath = $this->User->UserSetting->getHomepagePath($user['id']);
            if ($homepagePath !== '') {
                $this->set('homepage', array('path' => $homepagePath));
            } else {
                $this->set('homepage', "{$this->baseurl}/events/index");
            }

            $this->User->updateField($user, 'newsread', time());
        }

        if ($panel) {
            $this->layout = false;
            $this->render('ajax/panel');
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
            'redirect' => $this->__returnUrl()
        ];
        $this->CRUD->add($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        if ($this->theme === "Overmind") {
            $this->layout = false;
            $this->render('add');
        }
    }

    public function edit($id)
    {
        $params = [
            'redirect' => $this->__returnUrl()
        ];
        $this->CRUD->edit($id, $params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('newsItem', $this->request->data);
        if ($this->theme === "Overmind") {
            $this->layout = false;
        }
        $this->render('add');
    }

    public function delete($id)
    {
        $this->CRUD->delete($id);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }

    public function deleteSelection($id = null)
    {
        return $this->CRUD->deleteSelection($id, [
            'modelName' => 'News',
            'restName' => 'News',
            'itemName' => 'news item',
            'view' => 'ajax/newsDeleteConfirmationForm',
            'checkModifyCallback' => function () {
                return $this->userRole['perm_site_admin'];
            },
            'multiSuccessMessageCallback' => function ($count) {
                return __n('%s news item deleted.', '%s news items deleted.', $count, $count);
            },
            'redirect' => $this->__returnUrl()
        ]);
    }

    /**
     * The page a news form goes back to: the one it was opened on, unless that
     * is the form itself. Controller::referer() only knows pages under
     * MISP.baseurl, so an instance reached under any other name would always
     * land on the news page; the referer is checked against the host the
     * request came to instead.
     *
     * @return array|string
     */
    private function __returnUrl()
    {
        App::uses('InternalRedirectValidator', 'Tools');
        $fallback = ['action' => 'index'];
        $referer = parse_url((string)env('HTTP_REFERER'));
        if (empty($referer['host'])) {
            return $fallback;
        }
        $host = $referer['host'] . (isset($referer['port']) ? ':' . $referer['port'] : '');
        if (strcasecmp($host, (string)$this->request->host()) !== 0) {
            return $fallback;
        }
        $path = InternalRedirectValidator::sanitize(
            ($referer['path'] ?? '/') . (isset($referer['query']) ? '?' . $referer['query'] : '')
        );
        $base = (string)$this->request->base;
        if ($base !== '' && strpos($path, $base . '/') === 0) {
            $path = substr($path, strlen($base));
        }
        if ($path === '' || preg_match('#^/news/(add|edit|delete)#i', $path)) {
            return $fallback;
        }
        return $path;
    }
}
