<?php
App::uses('AppController', 'Controller');

class BenchmarksController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public $paginate = [
        'limit' => 60,
        'maxLimit' => 9999,

    ];

    public function beforeFilter()
    {
        parent::beforeFilter();
    }

    public function index()
    {
        $this->set('menuData', ['menuList' => 'admin', 'menuItem' => 'index']);
        $this->loadModel('User');
        App::uses('BenchmarkTool', 'Tools');
        $this->Benchmark = new BenchmarkTool($this->User);
        $passedArgs = $this->passedArgs;
        $this->paginate['order'] = 'value';
        $defaults = [
            'days' => null,
            'average' => false,
            'aggregate' => false,
            'scope' => null,
            'field' => null,
            'key' => null,
            'quickFilter' => null
        ];
        $filters = $this->IndexFilter->harvestParameters(array_keys($defaults));
        foreach ($defaults as $key => $value) {
            if (!isset($filters[$key])) {
                $filters[$key] = $defaults[$key];
            }
        }
        $temp = $this->Benchmark->getAllTopLists(
            $filters['days'] ?? null,
            $filters['limit'] ?? 100,
            $filters['average'] ?? null,
            $filters['aggregate'] ?? null
        );
        $settings = $this->Benchmark->getSettings();
        $units = $this->Benchmark->getUnits();
        $this->set('settings', $settings);
        $data = [];
        $userLookup = [];
        foreach ($temp as $scope => $t) {
            if (!empty($filters['scope']) && $filters['scope'] !== 'all' && $scope !== $filters['scope']) {
                continue;
            }
            foreach ($t as $field => $t2) {
                if (!empty($filters['field']) && $filters['field'] !== 'all' && $field !== $filters['field']) {
                    continue;
                }
                foreach ($t2 as $date => $t3) {
                    foreach ($t3 as $key => $value) {
                        if ($scope == 'user') {
                            if ($key === 'SYSTEM') {
                                $text = 'SYSTEM';
                            } else if (isset($userLookup[$key])) {
                                $text = $userLookup[$key];
                            } else {
                                $user = $this->User->find('first', [
                                    'fields' => ['User.id', 'User.email'],
                                    'recursive' => -1,
                                    'conditions' => ['User.id' => $key]
                                ]);
                                if (empty($user)) {
                                    $text = '(' . $key . ') ' . __('Invalid user');
                                } else {
                                    $text = '(' . $key . ') ' . $user['User']['email'];
                                }
                                $userLookup[$key] = $text;
                            }
                        } else {
                            $text = $key;
                        }
                        if (!empty($filters['quickFilter'])) {
                            $q = strtolower($filters['quickFilter']);
                            if (
                                strpos(strtolower($scope), $q) === false &&
                                strpos(strtolower($field), $q) === false &&
                                strpos(strtolower($key), $q) === false &&
                                strpos(strtolower($value), $q) === false &&
                                strpos(strtolower($date), $q) === false &&
                                strpos(strtolower($text), $q) === false
                            ) {
                                continue;
                            }
                        }
                        if (empty($filters['key']) || $key == $filters['key']) {
                            $data[] = [
                                'scope' => $scope,
                                'field' => $field,
                                'date' => $date,
                                'key' => $key,
                                'text' => $text,
                                'value' => $value,
                                'unit' => $units[$field]
                            ];    
                        }
                    }
                }
            }
        }
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($data, $this->response->type());
        }
        App::uses('CustomPaginationTool', 'Tools');
        $customPagination = new CustomPaginationTool();
        $customPagination->truncateAndPaginate($data, $this->params, $this->modelClass, true);
        $this->set('data', $data);
        $this->set('passedArgs', json_encode($passedArgs));
        $this->set('filters', $filters);
    }

}
