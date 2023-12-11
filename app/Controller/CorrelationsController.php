<?php
App::uses('AppController', 'Controller');

/**
 * @property Correlation $Correlation
 */
class CorrelationsController extends AppController
{
    public $components = array('RequestHandler');

    public function top()
    {
        $query = [
            'limit' => 50,
            'page' => 1
        ];
        if (!empty($this->params['named']['limit'])) {
            $query['limit'] = $this->params['named']['limit'];
        }
        if (!empty($this->params['named']['page'])) {
            $query['page'] = $this->params['named']['page'];
        }
        if ($this->_isRest()) {
            $data = $this->Correlation->findTop($query);
            return $this->RestResponse->viewData($data, 'json');
        } else {
            $data = $this->Correlation->findTop($query);
            $age = $this->Correlation->getTopTime();
            $age = time() - $age;
            $unit = 's';
            if ($age >= 60) {
                $age = ceil($age / 60);
                $unit = 'm';
                if ($age >= 60) {
                    $age = ceil($age / 60);
                    $unit = 'h';
                    if ($age >= 24) {
                        $age = ceil($age / 24);
                        $unit = 'd';
                        if ($age >= 365) {
                            $age = ceil($age / 365);
                            $unit = 'y';
                        }
                    }
                }
            }

            $this->__setPagingParams($query['page'], $query['limit'], count($data), 'named');

            $this->set('age', $age);
            $this->set('age_unit', $unit);
            $this->set('data', $data);
            $this->set('title_for_layout', __('Top correlations index'));
            $this->set('menuData', [
                'menuList' => 'correlationExclusions',
                'menuItem' => 'top'
            ]);
        }
    }

    public function generateTopCorrelations()
    {
        $result = $this->Correlation->generateTopCorrelationsRouter();
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($result, 'json');
        } else {
            if ($result === false) {
                $message = __('No correlations found. Nothing to rank.');
            } else if ($result === true) {
                $message = __('Top correlation list regenerated.');
            } else {
                $message = __('Top correlation list generation queued for background processing. Job ID: %s.', $result);
            }
            $this->Flash->success($message);
            $this->redirect(['controller' => 'correlations', 'action' => 'top']);
        }
    }

    public function overCorrelations()
    {
        $query = [
            'limit' => 50,
            'page' => 1,
            'order' => 'occurrence desc'
        ];
        foreach ($query as $customParam => $foo) {
            if (isset($this->request->params['named'][$customParam])) {
                $query[$customParam] = $this->request->params['named'][$customParam];
            }
        }
        if (isset($this->request->params['named']['scope'])) {
            $limit = $this->Correlation->OverCorrelatingValue->getLimit();
            if ($this->request->params['named']['scope'] === 'over_correlating') {
                $scope = 'over_correlating';
                $query['conditions'][] = ['occurrence >=' => $limit];
            } else if ($this->request->params['named']['scope'] === 'not_over_correlating') {
                $query['conditions'][] = ['occurrence <' => $limit];
                $scope = 'not_over_correlating';
            }
        } else {
            $scope = 'all';
        }
        $data = $this->Correlation->OverCorrelatingValue->getOverCorrelations($query);
        $data = $this->Correlation->attachExclusionsToOverCorrelations($data);

        if ($this->_isRest()) {
            return $this->RestResponse->viewData($data, 'json');
        }

        $this->__setPagingParams($query['page'], $query['limit'], count($data), 'named');
        $this->set('data', $data);
        $this->set('scope', $scope);
        $this->set('title_for_layout', __('Index of over correlating values'));
        $this->set('menuData', [
            'menuList' => 'correlationExclusions',
            'menuItem' => 'over'
        ]);
    }

    public function switchEngine(string $engine)
    {
        $this->loadModel('Server');
        if (!isset($this->Correlation->validEngines[$engine])) {
            throw new MethodNotAllowedException(__('Not a valid engine choice. Please make sure you pass one of the following: ', implode(', ', array_keys($this->Correlation->validEngines))));
        }
        if ($this->request->is('post')) {
            $setting = $this->Server->getSettingData('MISP.correlation_engine');
            $result = $this->Server->serverSettingsEditValue($this->Auth->user(), $setting, $engine);
            if ($result === true) {
                $message = __('Engine switched.');
                if ($this->_isRest()) {
                    return $this->RestResponse->saveSuccessResponse('Correlations', 'switchEngine', false, $this->response->type(), $message);
                } else {
                    $this->Flash->success($message);
                    $this->redirect(['controller' => 'servers', 'action' => 'serverSettings', 'correlations']);
                }
            } else {
                $message = __('Couldn\'t switch to the requested engine.');
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('Correlations', 'switchEngine', false, $message, $this->response->type());
                } else {
                    $this->Flash->error($message);
                    $this->redirect(['controller' => 'servers', 'action' => 'serverSettings', 'correlations']);
                }
            }
        } else {
            $this->set('engine', $engine);
            $this->render('ajax/switch_engine_confirmation');
        }
    }

    public function truncate(string $engine)
    {
        if (!isset($this->Correlation->validEngines[$engine])) {
            throw new MethodNotAllowedException(__('Not a valid engine choice. Please make sure you pass one of the following: ', implode(', ', array_keys($this->Correlation->validEngines))));
        }
        if ($this->request->is('post')) {
            if (!Configure::read('MISP.background_jobs')) {
                $result = $this->Correlation->truncate($this->Auth->user(), $engine);
                $message = $result ? __('Table truncated.') : __('Could not truncate table');
                if ($this->_isRest()) {
                    if ($result) {
                        $this->RestResponse->saveSuccessResponse('Correlations', 'truncate', false, $this->response->type(), $message);
                    } else {
                        $this->RestResponse->saveFailResponse('Correlations', 'truncate', false, $message, $this->response->type());
                    }
                } else {
                    $this->Flash->{$result ? 'success' : 'error'}($message);
                    $this->redirect(['controller' => 'servers', 'action' => 'serverSettings', 'correlations']);
                }
            } else {
                $job = ClassRegistry::init('Job');
                $jobId = $job->createJob(
                    'SYSTEM',
                    Job::WORKER_DEFAULT,
                    'truncate table',
                    $this->Correlation->validEngines[$engine],
                    'Job created.'
                );

                $this->Correlation->Attribute->getBackgroundJobsTool()->enqueue(
                    BackgroundJobsTool::DEFAULT_QUEUE,
                    BackgroundJobsTool::CMD_ADMIN,
                    [
                        'truncateTable',
                        $this->Auth->user('id'),
                        $engine,
                        $jobId
                    ],
                    true,
                    $jobId
                );

                $message = __('Job queued. You can view the progress if you navigate to the active jobs view (Administration -> Jobs).');
                if ($this->_isRest()) {
                    return $this->RestResponse->saveSuccessResponse('Correlations', 'truncate', false, $this->response->type(), $message);
                } else {
                    $this->Flash->success($message);
                    $this->redirect(['controller' => 'servers', 'action' => 'serverSettings', 'correlations']);
                }
            }
        } else {
            $this->set('engine', $engine);
            $this->set('table_name', $this->Correlation->validEngines[$engine]);
            $this->render('ajax/truncate_confirmation');
        }
    }

    public function generateOccurrences()
    {
        $this->loadModel('OverCorrelatingValue');
        $this->OverCorrelatingValue->generateOccurrencesRouter();
        if (Configure::read('MISP.background_jobs')) {
            $message = __('Job queued.');
        } else {
            $message = __('Over-correlations counted successfully.');
        }
        if ($this->_isRest()) {
            return $this->RestResponse->saveSuccessResponse('Correlations', 'generateOccurrences', false, $this->response->type(), $message);
        }
        $this->Flash->info($message);
        $this->redirect(['controller' => 'correlations', 'action' => 'overCorrelations']);
    }
}
