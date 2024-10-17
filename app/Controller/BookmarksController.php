<?php
App::uses('AppController', 'Controller');

class BookmarksController extends AppController
{
    public $components = ['RequestHandler'];

    public function beforeFilter()
    {
        parent::beforeFilter();
        $this->Bookmark->current_user = $this->Auth->user();
    }

    public function index()
    {
        $passedParams = $this->IndexFilter->harvestParameters([
            'scope',
        ]);
        $scope = $passedParams['scope'] ?? 'all';
        $conditions = [];
        if ($scope == 'mine') {
            $conditions = [
                'Bookmark.user_id' => $this->Auth->user()['id'],
            ];
        } else if ($scope == 'org') {
            $conditions = [
                'OR' => [
                    'Bookmark.user_id' => $this->Auth->user()['id'],
                    'AND' => [
                        'Bookmark.org_id' => $this->Auth->user()['Organisation']['id'],
                        'Bookmark.exposed_to_org' => true,
                    ],
                ],
            ];
        } else {
            if (empty($this->Auth->user()['Role']['perm_site_admin'])) {
                $conditions = [
                    'OR' => [
                        'Bookmark.user_id' => $this->Auth->user()['id'],
                        'AND' => [
                            'Bookmark.org_id' => $this->Auth->user()['Organisation']['id'],
                            'Bookmark.exposed_to_org' => true,
                        ],
                    ],
                ];
            }
        }
        $params = [
            'filters' => ['name', 'url', ],
            'quickFilters' => ['Bookmark.name', 'Bookmark.url', ],
            'conditions' => $conditions,
            'recursive' => -1,
            'contain' => ['Organisation' => ['fields' => ['id', 'name', 'uuid']], 'User' => ['fields' => ['id', 'email', 'org_id']], ],
            'afterFind' => function($results) {
                foreach ($results as $k => $data) {
                    $canSeeUser = $this->Bookmark->mayViewUser($this->Auth->user(), $data['Bookmark']['id']);
                    if (!$canSeeUser) {
                        unset($results[$k]['User']);
                    }
                }
                return $results;
            }
        ];
        $this->CRUD->index($params);
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }
        $this->set('menuData', ['menuList' => 'bookmarks', 'menuItem' => 'index']);
        $this->set('scope', $scope);
    }

    public function add()
    {
        $currentUser = $this->Auth->user();
        $params = [
            'beforeSave' => function($data) use ($currentUser) {
                if (!empty($currentUser['Role']['perm_admin'])) {
                    $data['Bookmark']['exposed_to_org'] = false;
                }
                return $data;
            }
        ];
        $this->CRUD->add($params);
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }
        $this->set('menuData', ['menuList' => 'bookmarks', 'menuItem' => 'add']);
    }

    public function edit($id)
    {
        if (!$this->Bookmark->mayModify($this->Auth->user(), intval($id))) {
            throw new MethodNotAllowedException(__('Invalid Bookmark or insuficient privileges'));
        }
        $params = [
        ];
        $this->CRUD->edit($id, $params);
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }
        $this->set('menuData', ['menuList' => 'bookmarks', 'menuItem' => 'edit']);
        $this->set('id', $id);
        $this->render('add');
    }

    public function delete($id)
    {
        if (!$this->Bookmark->mayModify($this->Auth->user(), intval($id))) {
            throw new MethodNotAllowedException(__('Invalid Bookmark or insuficient privileges'));
        }
        $this->CRUD->delete($id);
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }
        $this->set('menuData', ['menuList' => 'bookmarks', 'menuItem' => 'delete']);
    }

    public function view($id)
    {
        if (!$this->Bookmark->mayModify($this->Auth->user(), intval($id))) {
            throw new MethodNotAllowedException(__('Invalid Bookmark or insuficient privileges'));
        }
        $canSeeUser = false;
        $params = [
            'contain' => [
                'User' => [
                    'fields' => ['id', 'email', 'org_id']
                ], 
                'Organisation' => [
                    'fields' => ['id', 'name', 'uuid']
                ]
            ],
            'afterFind' => function($data) {
                $canSeeUser = $this->Bookmark->mayViewUser($this->Auth->user(), $data['Bookmark']['id']);
                if (!$canSeeUser) {
                    unset($data['User']);
                }
                return $data;
            }
        ];
        $this->CRUD->view($id, $params);
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }
        $this->set('id', $id);
        $this->set('menuData', ['menuList' => 'bookmarks', 'menuItem' => 'view']);
    }
}
