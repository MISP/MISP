<?php

App::uses('AppController', 'Controller');

class ObjectRelationshipsController extends AppController
{
    public $components = ['RequestHandler', 'Session'];

    public $paginate = [
        'limit' => 60,
        'order' => [
            'ObjectRelationship.name' => 'asc'
        ],
        'recursive' => -1
    ];

    public function add()
    {
        $params = [
            'beforeSave' => function($relationship) {
                $relationship['ObjectRelationship']['version'] = (new DateTime())->getTimestamp();
                $relationship['ObjectRelationship']['format'] = '["misp"]';
                return $relationship;
            }
        ];
        $this->CRUD->add($params);
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }
        $this->set('menuData', ['menuList' => 'objectTemplates', 'menuItem' => 'object_relationship_add']);
    }

    public function index()
    {
        $allCounts = $this->ObjectRelationship->getUsage();
        $countsForTypes = [];
        foreach ($allCounts['object_reference'] as $type => $count) {
            $countsForTypes[$type]['tag_relationship'] = intval($count);
        }
        foreach ($allCounts['tag_relationship'] as $type => $count) {
            $countsForTypes[$type]['object_reference'] = intval($count);
        }
        foreach ($allCounts['analyst_relationship'] as $type => $count) {
            $countsForTypes[$type]['analyst_relationship'] = intval($count);
        }
        $filters = $this->IndexFilter->harvestParameters(['quickFilter']);
        $conditions = [];
        if (!empty($filters['quickFilter'])) {
            $conditions['name LIKE'] = '%' . $filters['quickFilter'] . '%';
        }
        $relationships = $this->ObjectRelationship->find('all', [
            'recursive' => -1,
            'conditions' => $conditions,
        ]);
        foreach ($relationships as $i => $relationship) {
            if (!empty($countsForTypes[$relationship['ObjectRelationship']['name']])) {
                $relationships[$i]['ObjectRelationship']['usage'] = $countsForTypes[$relationship['ObjectRelationship']['name']];
            } else {
                $relationships[$i]['ObjectRelationship']['usage'] = null;
            }
            if (!empty($allCounts['total'][$relationship['ObjectRelationship']['name']])) {
                $relationships[$i]['ObjectRelationship']['usage_all'] = $allCounts['total'][$relationship['ObjectRelationship']['name']];
            } else {
                $allCounts['total'][$relationship['ObjectRelationship']['name']] = 0;
            }
            $relationships[$i] = $relationships[$i]['ObjectRelationship'];
        }

        App::uses('CustomPaginationTool', 'Tools');
        $customPagination = new CustomPaginationTool();
        $customPagination->truncateAndPaginate($relationships, $this->params, $this->modelClass, true);

        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }

        $this->set('data', $relationships);
        $this->set('passedArgs', json_encode($this->passedArgs));
        $this->set('menuData', ['menuList' => 'objectTemplates', 'menuItem' => 'object_relationship_index']);
    }

    public function edit($id)
    {
        $params = [
            'beforeSave' => function ($relationship) {
                $relationship['ObjectRelationship']['version'] = (new DateTime())->getTimestamp();
                return $relationship;
            },
            'fields' => ['name', 'description', 'highlighted',]
        ];
        $this->CRUD->edit($id, $params);
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }
        $this->set('menuData', ['menuList' => 'objectTemplates', 'menuItem' => 'object_relationship_edit']);
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
        $this->set('menuData', ['menuList' => 'eventReports', 'menuItem' => 'object_relationship_delete']);
    }

    public function toggleHighlighted($name)
    {
        $relationship = $this->ObjectRelationship->find('first', [
            'fields' => ['id', 'name', 'highlighted'],
            'recursive' => -1,
            'conditions' => array('ObjectRelationship.name' => $name)
        ]);
        if (empty($relationship)) {
            return $this->RestResponse->saveFailResponse('ObjectRelationship', 'toggleHighlighted', $name, 'Invalid ObjectRelationship', $this->response->type());
        }
        if ($this->request->is('post')) {
            $relationship['ObjectRelationship']['highlighted'] = $this->request->data['ObjectRelationship']['highlighted'];
            $result = $this->ObjectRelationship->save($relationship, ['highlighted', ]);
            if ($result) {
                return $this->RestResponse->saveSuccessResponse('ObjectRelationship', 'toggleHighlighted', $name, $this->response->type());
            } else {
                return $this->RestResponse->saveFailResponse('ObjectRelationship', 'toggleHighlighted', $name, $this->validationError, $this->response->type());
            }
        }

        $this->set('highlighted', !$relationship['ObjectRelationship']['highlighted']);
        $this->set('id', $relationship['ObjectRelationship']['id']);
        $this->set('name', $name);
        $this->autoRender = false;
        $this->layout = false;
        $this->render('ajax/toggle_highlighted');
    }

}
