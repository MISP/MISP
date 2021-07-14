<?php
App::uses('AppController', 'Controller');

/**
 * @property Correlation $Correlation
 */
class CorrelationsController extends AppController
{
    public $components = array('Security', 'RequestHandler');

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
}
