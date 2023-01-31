<?php

namespace Tags\Controller;

use Tags\Controller\AppController;
use Cake\Utility\Hash;
use Cake\Utility\Inflector;
use Cake\Utility\Text;
use Cake\Database\Expression\QueryExpression;
use Cake\Http\Exception\NotFoundException;
use Cake\Http\Exception\MethodNotAllowedException;
use Cake\Http\Exception\ForbiddenException;
use Cake\ORM\TableRegistry;

class TagsController extends AppController
{

    public function index()
    {
        $this->CRUD->index([
            'filters' => ['name', 'colour'],
            'quickFilters' => [['name' => true], 'colour']
        ]);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
    }

    public function add()
    {
        $this->CRUD->add();
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
    }

    public function view($id)
    {
        $this->CRUD->view($id);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
    }

    public function edit($id)
    {
        $this->CRUD->edit($id);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
        $this->render('add');
    }

    public function delete($id)
    {
        $this->CRUD->delete($id);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
    }

    // public function tag($model, $id)
    // {
    //     $controller = $this->getControllerBeingTagged($model);
    //     $controller->CRUD->tag($id);
    //     $responsePayload = $controller->CRUD->getResponsePayload();
    //     if (!empty($responsePayload)) {
    //         return $responsePayload;
    //     }
    //     return $controller->getResponse();
    // }

    // public function untag($model, $id)
    // {
    //     $controller = $this->getControllerBeingTagged($model);
    //     $controller->CRUD->untag($id);
    //     $responsePayload = $controller->CRUD->getResponsePayload();
    //     if (!empty($responsePayload)) {
    //         return $responsePayload;
    //     }
    //     return $controller->getResponse();
    // }

    // public function viewTags($model, $id)
    // {
    //     $controller = $this->getControllerBeingTagged($model);
    //     $controller->CRUD->viewTags($id);
    //     $responsePayload = $controller->CRUD->getResponsePayload();
    //     if (!empty($responsePayload)) {
    //         return $responsePayload;
    //     }
    //     return $controller->getResponse();
    // }

    // private function getControllerBeingTagged($model)
    // {
    //     $modelName = Inflector::camelize($model);
    //     $controllerName = "\\App\\Controller\\{$modelName}Controller";
    //     if (!class_exists($controllerName)) {
    //         throw new MethodNotAllowedException(__('Model `{0}` does not exists', $model));
    //     }
    //     $controller = new $controllerName;
    //     // Make sure that the request is correctly assigned to this controller
    //     return $controller;
    // }
}
