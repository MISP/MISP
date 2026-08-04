<?php

App::uses('AppController', 'Controller');

/**
 * @property EventReportTemplateVariable $EventReportTemplateVariable
 */
class EventReportTemplateVariablesController extends AppController
{
    public $components = [
        'AdminCrud',
        'RequestHandler'
    ];

    public $paginate = [
        'limit' => 60,
        'order' => [
            'EventReportTemplateVariable.name' => 'ASC'
        ],
        'recursive' => -1,
    ];

    public function add()
    {
        $params = [];
        $this->CRUD->add($params);
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }
         $this->set('menuData', ['menuList' => 'eventReports', 'menuItem' => 'template_variable_add']);
        if ($this->theme === 'Overmind') {
            $this->layout = false;
        }
    }

    public function view($id)
    {
        $params = [];
        $this->CRUD->view($id, $params);
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }
         $this->set('menuData', ['menuList' => 'eventReports', 'menuItem' => 'template_variable_view']);
    }

    public function index()
    {
        $params = [];
        $this->CRUD->index($params);
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }
         $this->set('menuData', ['menuList' => 'eventReports', 'menuItem' => 'template_variable_index']);
    }

    public function edit($id)
    {
        $params = [];
        $this->CRUD->edit($id, $params);
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }
        $this->set('menuData', ['menuList' => 'eventReports', 'menuItem' => 'template_variable_edit']);
        if ($this->theme === 'Overmind') {
            $this->layout = false;
        }
        $this->set('action', 'edit');
        $this->render('add');
    }

    public function delete($id)
    {
        $params = [];
        $this->CRUD->delete($id, $params);
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }
         $this->set('menuData', ['menuList' => 'eventReports', 'menuItem' => 'template_variable_delete']);
    }

    public function deleteSelection($id = null)
    {
        return $this->CRUD->deleteSelection($id, [
            'modelName' => 'EventReportTemplateVariable',
            'restName' => 'EventReportTemplateVariables',
            'itemName' => 'EventReportTemplateVariable',
            'view' => 'ajax/eventReportTemplateVariableDeleteConfirmationForm',
            'checkModifyCallback' => function($itemId) {
                return $this->userRole['perm_site_admin'];
            },
            'multiSuccessMessageCallback' => function($count) {
                return __n('%s event report template variable deleted.', '%s event report template variables deleted.', $count, $count);
            }
        ]);
    }

}
