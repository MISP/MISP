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
        $defaults = [
            'days' => null,
            'limit' => null,
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
        // `days` arrives as a count of days back ("days:7"), the same meaning
        // BenchmarkTopListWidget gives it — getAllTopLists() wants the dates
        // themselves, and being handed the raw string was a TypeError.
        $days = null;
        if (!empty($filters['days']) && is_numeric($filters['days'])) {
            $days = [];
            for ($i = 0; $i < (int)$filters['days']; $i++) {
                $days[] = date('Y-m-d', strtotime('-' . $i . ' days'));
            }
        } else if (is_array($filters['days']) && !empty($filters['days'])) {
            $days = $filters['days'];
        }
        // The top list is cut to $limit before the key filter below is applied,
        // so a named key outside the global top N would silently disappear.
        $limit = (!empty($filters['limit']) && is_numeric($filters['limit']))
            ? (int)$filters['limit']
            : (empty($filters['key']) ? 100 : -1);
        $temp = $this->Benchmark->getAllTopLists(
            $days,
            $limit,
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
        // Biggest first — that is what makes it a top list. CustomPaginationTool
        // only sorts on an explicit `sort` named param, so without this the rows
        // arrive in whatever order Redis returned them.
        if (empty($this->passedArgs['sort'])) {
            usort($data, function ($a, $b) {
                return $b['value'] <=> $a['value'];
            });
        }
        // A pinned key yields at most (fields x days) rows and the focused view
        // pivots them by date, so truncating to a page would drop whole days
        // out of the middle of the breakdown.
        if (empty($filters['key'])) {
            App::uses('CustomPaginationTool', 'Tools');
            $customPagination = new CustomPaginationTool();
            $customPagination->truncateAndPaginate($data, $this->params, $this->modelClass, true);
        }
        $this->set('data', $data);
        $this->set('passedArgs', json_encode($passedArgs));
        $this->set('filters', $filters);
        // Collection state, so the views can say why a screen is empty or stale.
        $this->set('benchmarkingEnabled', (bool)Configure::read('Plugin.Benchmarking_enable'));
        $this->set('recordedDays', $this->Benchmark->getRecordedDays());
    }

    public function sqlMetrics()
    {
        $metric_options = $this->request->params['pass'];
        $params = $this->IndexFilter->harvestParameters([
            'controller',
            'action',
            'limit',
            'page'
        ]);
        $redis = $this->User->setupRedis();
        $entries = [];
        $cursor = null;
        do {
            $results = $redis->scan($cursor, 'misp:slowlog:*', 1000);
            if ($results !== false) {
                foreach ($results as $key) {
                    $raw = $redis->get($key);
                    if ($raw !== false) {
                        $pipePos = strpos($raw, '|');
                        if ($pipePos !== false) {
                            $duration = (float) substr($raw, 0, $pipePos);
                            $sql = substr($raw, $pipePos + 1);
                            $controller = 'Unknown';
                            $action = 'Unknown';
                            if (preg_match('/(\w+)\s*::\s*(\w+)/', $sql, $matches)) {
                                $controller = strtolower($matches[1]);
                                $action = strtolower($matches[2]);
                            }
                            if (!empty($params['controller']) && $params['controller'] !== $controller) {
                                continue;
                            }
                            if (!empty($params['action']) && $params['action'] !== $action) {
                                continue;
                            }
                            $entries[] = ['duration' => $duration, 'sql' => $sql, 'controller' => $controller, 'action' => $action, 'key' => $key];
                        }
                    }
                }
            }

        } while ($cursor !== 0 && $cursor !== null);
        usort($entries, fn($a, $b) => $b['duration'] <=> $a['duration']);
        $start = 0;
        $limit = !empty($params['limit']) && is_numeric($params['limit']) && $params['limit'] > 0 ? (int)$params['limit'] : 100;

        if (!empty($params['page']) && is_numeric($params['page']) && $params['page'] > 0) {
            $start = ($params['page'] - 1) * $limit;
        }
        foreach ($entries as $k => $entry) {
            $command_pattern = '/^(?:\s*\/\*.*?\*\/\s*)*([A-Z]+)/i';
            preg_match($command_pattern, $entry['sql'], $matches);
            if ($matches[1] !== 'EXPLAIN' && $matches[1] !== 'ANALYZE') {
                if (in_array('explain', $metric_options)) {
                    $entries[$k]['explain'] = $this->User->query('EXPLAIN ' . $entry['sql']);
                }
                if (in_array('analyze', $metric_options)) {
                    $entries[$k]['analyze'] = $this->User->query('ANALYZE ' . $entry['sql']);
                }
                
            }
            
        }
        return $this->RestResponse->viewData(array_slice($entries, $start, $limit));
    }

    public function purgeSqlMetrics()
    {
        if ($this->request->is('post')) {
            $redis = $this->User->setupRedis();
            $cursor = null;
            do {
                $keys = $redis->scan($cursor, 'misp:slowlog:*', 1000);
                if ($keys !== false && count($keys) > 0) {
                    $redis->del($keys);
                }
            } while ($cursor !== 0 && $cursor !== null);
            $message = __('SQL metrics purged successfully.');
            if ($this->_isRest()) {
                return $this->RestResponse->saveSuccessResponse('Benchmarks', 'purgeSqlMetrics', false, $this->response->type(), $message);
            } else {
                $this->Flash->success($message);
                $this->redirect(Router::url($this->referer(), true));
            }
        } else {
            $this->set('id', null);
            $this->set('title', __('Purge SQL Metrics'));
            $this->set('question', __('Are you sure you want to purge the SQL slow log metrics?'));
            $this->set('actionName', __('Purge'));
            $this->layout = false;
            $this->render('/genericTemplates/confirm');
        }
    }
}
