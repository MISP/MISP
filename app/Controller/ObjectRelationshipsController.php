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
        if($this->theme === "Overmind"){
            $this->layout = false;
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

        if($this->theme === "Overmind"){
            $this->layout = false;
            $relationship = $this->request->data;
            $highlighted = $relationship['ObjectRelationship']['highlighted'];
            $this->set('highlighted', $highlighted);
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

    public function deleteSelection($id = null)
    {
        return $this->CRUD->deleteSelection($id, [
            'modelName' => 'ObjectRelationship',
            'restName' => 'ObjectRelationships',
            'itemName' => 'ObjectRelationship',
            'view' => 'ajax/objectRelationshipDeleteConfirmationForm',
            'checkModifyCallback' => function() {
                return $this->userRole['perm_site_admin'];
            },
            'multiSuccessMessageCallback' => function($count) {
                return __n('%s object relationship deleted.', '%s object relationships deleted.', $count, $count);
            }
        ]);
    }

    // public function toggleHighlighted($name)
    // {
    //     $relationship = $this->ObjectRelationship->find('first', [
    //         'fields' => ['id', 'name', 'highlighted'],
    //         'recursive' => -1,
    //         'conditions' => array('ObjectRelationship.name' => $name)
    //     ]);
    //     if (empty($relationship)) {
    //         return $this->RestResponse->saveFailResponse('ObjectRelationship', 'toggleHighlighted', $name, 'Invalid ObjectRelationship', $this->response->type());
    //     }
    //     if ($this->request->is('post')) {
    //         $relationship['ObjectRelationship']['highlighted'] = $this->request->data['ObjectRelationship']['highlighted'];
    //         $result = $this->ObjectRelationship->save($relationship, ['highlighted', ]);
    //         if ($result) {
    //             return $this->RestResponse->saveSuccessResponse('ObjectRelationship', 'toggleHighlighted', $name, $this->response->type());
    //         } else {
    //             return $this->RestResponse->saveFailResponse('ObjectRelationship', 'toggleHighlighted', $name, $this->validationError, $this->response->type());
    //         }
    //     }

    //     $this->set('highlighted', !$relationship['ObjectRelationship']['highlighted']);
    //     $this->set('id', $relationship['ObjectRelationship']['id']);
    //     $this->set('name', $name);
    //     if($this->theme !== "Overmind"){
    //         $this->autoRender = false;
    //         $this->layout = false;
    //         $this->render('ajax/toggle_highlighted');
    //     }
    // }

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

        if ($this->theme === 'Overmind') {
            $this->request->allowMethod(['post']);

            $newState = !$relationship['ObjectRelationship']['highlighted'];
            $relationship['ObjectRelationship']['highlighted'] = $newState;

            $result = $this->ObjectRelationship->save($relationship);

            $action = $newState ? 'highlight' : 'unhighlight';
            $text = $newState ? 'highlighted' : 'unhighlighted';

            if ($this->_isRest()) {
                if ($result) {
                    return $this->RestResponse->saveSuccessResponse(
                        'ObjectRelationship',
                        'toggleHighlighted',
                        $name,
                        $this->response->type()
                    );
                } else {
                    return $this->RestResponse->saveFailResponse(
                        'ObjectRelationship',
                        'toggleHighlighted',
                        $name,
                        __('Could not toggle state.'),
                        $this->response->type()
                    );
                }
            } else {
                if ($result) {
                    $this->Flash->success(__('Object relationship %s.', $text));
                } else {
                    $this->Flash->error(__('Something went wrong.'));
                }
                return $this->redirect($this->referer());
            }
        }
        else{
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

    // --- HIGHLIGHTED ---
    public function massHighlight($idList = null)
    {
        return $this->_massToggleState($idList, 1, 'highlighted');
    }

    public function massRemoveHighlight($idList = null)
    {
        return $this->_massToggleState($idList, 0, 'highlighted');
    }

    private function _massToggleState($idList = null, $state = null, $field = '')
    {
        $cleanIdList = htmlspecialchars_decode(urldecode($idList));
        $ids = json_decode($cleanIdList, true);

        if (empty($ids) || !is_array($ids)) {
            $message = __('Invalid IDs provided.');
            if ($this->_isRest()) {
                return $this->RestResponse->saveFailResponse('ObjectRelationships', 'massToggle', false, $message, $this->response->type());
            }
            return new CakeResponse([
                'body' => json_encode(['saved' => false, 'errors' => $message]),
                'status' => 200,
                'type' => 'json'
            ]);
        }

        if (!in_array($field, ['enabled', 'required', 'highlighted'])) {
            $message = __('Invalid field provided.');
            if ($this->_isRest()) {
                return $this->RestResponse->saveFailResponse('ObjectRelationships', 'massToggle', false, $message, $this->response->type());
            }
            return new CakeResponse([
                'body' => json_encode(['saved' => false, 'errors' => $message]),
                'status' => 200,
                'type' => 'json'
            ]);
        }

        if ($this->request->is('post') || $this->request->is('put')) {
            $successCount = 0;

            foreach ($ids as $id) {
                $this->ObjectRelationship->id = $id;

                if ($this->ObjectRelationship->exists()) {
                    if ($this->ObjectRelationship->saveField($field, $state)) {

                        if ($field === 'enabled' && !$state) {
                            $this->ObjectRelationship->disableTags($id);
                        }
                        // Log
                        // $action = $state ? 'enable' : 'disable';
                        // if ($field === 'required') {
                        //     $action = $state ? 'required' : 'required';
                        // } elseif ($field === 'highlighted') {
                        //     $action = $state ? 'highlighted' : 'highlighted';
                        // }

                        // $this->__log(
                        //     $action,
                        //     $id,
                        //     'Taxonomy ' . $field . ' changed',
                        //     'Taxonomy ID ' . $id . ' set ' . $field . ' = ' . $state
                        // );

                        $successCount++;
                    }
                }
            }

            $actionTextMap = [
                'enabled' => $state ? __('enabled') : __('disabled'),
                'required' => $state ? __('required') : __('optional'),
                'highlighted' => $state ? __('highlighted') : __('not highlighted'),
            ];

            $message = __('%s ObjectRelationships successfully %s.', $successCount, $actionTextMap[$field]);

            if ($this->_isRest()) {
                return $this->RestResponse->saveSuccessResponse('ObjectRelationships', 'massToggle', false, $this->response->type(), $message);
            }
            if ($this->request->is('ajax')) {
                return new CakeResponse([
                    'body' => json_encode(['saved' => true, 'success' => $message]),
                    'status' => 200,
                    'type' => 'json'
                ]);
            }

            $this->Flash->success($message);
            return $this->redirect($this->referer(['action' => 'index']));
        }

        $this->layout = false;

        $actionTextMap = [
            'enabled' => $state ? 'enable' : 'disable',
            'required' => $state ? 'require' : 'make optional',
            'highlighted' => $state ? 'highlight' : 'remove highlight on',
        ];

        $urlMap = [
            'enabled' => $state ? 'massEnable' : 'massDisable',
            'required' => $state ? 'massRequire' : 'massOptional',
            'highlighted' => $state ? 'massHighlight' : 'massRemovehighlight',
        ];

        $this->set('actionText', __($actionTextMap[$field]));
        $this->set('idArray', $ids);
        $this->set('state', $state);
        $this->set('url', '/object_relationships/' . $urlMap[$field] . '/' . urlencode($cleanIdList));

        $this->render('ajax/objectRelationshipToggleConfirmationForm');
    }

}
