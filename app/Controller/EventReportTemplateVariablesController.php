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

}
