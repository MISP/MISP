<?php
App::uses('AppController', 'Controller');

/**
 * @property CorrelationExclusion $CorrelationExclusion
 */
class CorrelationExclusionsController extends AppController
{
    public $components = array(
        'Security',
        'CRUD',
        'RequestHandler'
    );

    public $paginate = array(
        'limit' => 60,
        'order' => array(
            'CorrelationExclusion.value' => 'ASC',
        )
    );

    public function index($id = false)
    {
        $this->CRUD->index([
            'filters' => ['value', 'comment'],
            'quickFilters' => ['value', 'comment']
        ]);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('title_for_layout', __('Correlation Exclusions index'));
        $this->set('menuData', [
            'menuList' => 'correlationExclusions',
            'menuItem' => 'index'
        ]);
    }

    public function delete($id)
    {
        $this->CRUD->delete($id);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }

    public function add()
    {
        $options = [
            'filters' => ['value', 'redirect', 'redirect_controller', 'comment']
        ];
        $params = $this->IndexFilter->harvestParameters($options['filters']);
        if (!empty($params['value'])) {
            $this->request->data['CorrelationExclusion']['value'] = $params['value'];
        }
        if (!empty($params['comment'])) {
            $this->request->data['CorrelationExclusion']['value'] = $params['comment'];
        }
        $this->CRUD->add($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $dropdownData = [];
        $this->set(compact('dropdownData'));
        $this->set('menuData', [
            'menuList' => 'correlationExclusions',
            'menuItem' => 'add',
        ]);
    }

    public function edit($id)
    {
        $this->set('menuData', [
            'menuList' => 'correlationExclusions',
            'menuItem' => 'edit',
        ]);
        $this->set('id', $id);
        $params = [
            'fields' => ['comment']
        ];
        $this->CRUD->edit($id, $params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }

        $this->loadModel('Organisation');
        $orgs = $this->Organisation->find('list', [
            'recursive' => -1,
            'fields' => ['id', 'name'],
            'order' => ['lower(name)' => 'ASC']
        ]);
        $dropdownData = [
            'org_id' => $orgs
        ];
        $this->set(compact('dropdownData'));
        $this->render('add');
    }

    public function view($id = false)
    {
        $this->CRUD->view($id);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }

        $this->set('title_for_layout', __('Correlation Exclusion'));
        $this->set('menuData', [
            'menuList' => 'correlationExclusions',
            'menuItem' => 'view',
        ]);
    }

    public function clean()
    {
        if ($this->request->is('post')) {
            $this->CorrelationExclusion->cleanRouter($this->Auth->user());
            $message = __('Correlations cleanup initiated, based on the exclusion rules.');
            if ($this->_isRest()) {
                return $this->RestResponse->saveSuccessResponse('CorrelationExclusion', 'clean', false, false, $message);
            } else {
                $this->Flash->success($message);
                $this->redirect($this->referer());
            }
        } else {
            $this->set('title', __('Clean up correlations'));
            $this->set('question', __('Execute the cleaning of all correlations that are at odds with the exclusion rules? This will delete all matching correlations.'));
            $this->set('actionName', 'clean');;
            $this->layout = 'ajax';
            $this->render('/genericTemplates/confirm');
        }
    }
}
