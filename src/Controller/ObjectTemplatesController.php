<?php

namespace App\Controller;

use App\Controller\AppController;
use Cake\Event\EventInterface;
use Cake\Http\Exception\MethodNotAllowedException;
use Cake\Http\Exception\NotFoundException;
use Cake\Http\Response;
use Cake\ORM\Locator\LocatorAwareTrait;
use Cake\Validation\Validation;

class ObjectTemplatesController extends AppController
{
    use LocatorAwareTrait;

    public $quickFilterFields = ['name', 'meta_category', 'uuid', 'description'];
    public $filterFields = ['name', 'meta_category', 'uuid', 'description'];

    public $paginate = [
        'limit' => 60,
        'order' => [
            'Object.id' => 'desc'
        ],
        'contain' => [
            'Organisations' => ['fields' => ['Organisations.id', 'Organisations.name', 'Organisations.uuid']]
        ],
        'recursive' => -1
    ];

    public function beforeFilter(EventInterface $event)
    {
        parent::beforeFilter($event);
        if (in_array($this->request->getParam('action'), ['objectMetaChoice', 'objectChoice', 'possibleObjectTemplates'], true)) {
            $this->Security->doNotGenerateToken = true;
        }
        $this->Security->setConfig('unlockedActions', ['possibleObjectTemplates']);
    }

    public function objectMetaChoice($eventId)
    {
        session_abort();

        $metas = $this->ObjectTemplate->find(
            'column',
            [
            'conditions' => ['ObjectTemplate.active' => 1],
            'fields' => ['ObjectTemplate.meta_category'],
            'order' => ['ObjectTemplate.meta_category asc'],
            'unique' => true,
            ]
        );

        $items = [[
            'name' => __('All Objects'),
            'value' => $this->baseurl . "/ObjectTemplates/objectChoice/$eventId/0"
        ]];
        foreach ($metas as $meta) {
            $items[] = [
                'name' => $meta,
                'value' => $this->baseurl . "/ObjectTemplates/objectChoice/$eventId/$meta",
            ];
        }

        $this->set('items', $items);
        $this->set(
            'options',
            [
            'multiple' => 0,
            ]
        );
        $this->render('/Elements/generic_picker');
    }

    public function objectChoice($event_id, $category = false)
    {
        $user = $this->closeSession();
        $this->ObjectTemplate->populateIfEmpty($user);
        $conditions = ['ObjectTemplate.active' => 1];
        if ($category !== false && $category !== "0") {
            $conditions['meta_category'] = $category;
        }
        $templates_raw = $this->ObjectTemplate->find(
            'all',
            [
            'recursive' => -1,
            'conditions' => $conditions,
            'fields' => ['id', 'meta_category', 'name', 'description'],
            'order' => ['ObjectTemplate.name asc']
            ]
        );

        $items = [];
        foreach ($templates_raw as $template) {
            $template = $template['ObjectTemplate'];
            $items[] = [
                'name' => $template['name'],
                'value' => $template['id'],
                'template' => [
                    'name' => $template['name'],
                    'infoExtra' => $template['description'],
                    'infoContextual' => $template['meta_category']
                ]
            ];
        }

        $this->set('items', $items);
        $this->set(
            'options',
            [
            'functionName' => 'redirectAddObject',
            'multiple' => 0,
            'select_options' => [
                'additionalData' => ['event_id' => $event_id],
            ],
            ]
        );
        $this->render('/Elements/generic_picker');
    }

    public function view($id)
    {
        if (Validation::uuid($id)) {
            $temp = $this->ObjectTemplates->find(
                'all',
                [
                'recursive' => -1,
                'conditions' => ['ObjectTemplates.uuid' => $id],
                'fields' => ['ObjectTemplates.id', 'ObjectTemplates.uuid'],
                'order' => ['ObjectTemplates.version desc']
                ]
            )->first();
            if (empty($temp)) {
                throw new NotFoundException(__('Invalid object template'));
            }
            $id = $temp['id'];
        } elseif (!is_numeric($id)) {
            throw new NotFoundException(__('Invalid object template id.'));
        }
        $params = [
            'recursive' => -1,
            'contain' => [
                'Organisations' => ['fields' => ['Organisations.id', 'Organisations.name', 'Organisations.uuid']]
            ],
            'conditions' => ['ObjectTemplates.id' => $id]
        ];
        if ($this->ParamHandler->isRest()) {
            $params['contain'][] = 'ObjectTemplateElements';
        }
        if ($this->isSiteAdmin()) {
            $params['contain']['Users'] = ['fields' => ['Users.id', 'Users.email']];
        }
        $objectTemplate = $this->ObjectTemplates->find('all', $params)->first();
        if (empty($objectTemplate)) {
            throw new NotFoundException('Invalid object template');
        }
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData($objectTemplate);
        } else {
            $this->set('id', $id);
            $this->set('template', $objectTemplate);
        }
    }

    public function delete($id)
    {
        if (!$this->request->is('post') && !$this->request->is('put') && !$this->request->is('delete')) {
            throw new MethodNotAllowedException();
        }

        $objectTemplate = $this->ObjectTemplates->get($id);

        if (empty($objectTemplate)) {
            throw new NotFoundException('Invalid Object Template');
        }
        if ($this->ObjectTemplates->delete($objectTemplate)) {
            if ($this->ParamHandler->isRest()) {
                return $this->RestResponse->saveSuccessResponse('ObjectTemplates', 'admin_delete', $id);
            } else {
                $this->Flash->success(__('Object Template deleted'));
            }
        } else {
            if ($this->ParamHandler->isRest()) {
                return $this->RestResponse->saveFailResponse('ObjectTemplates', 'admin_delete', $id, $this->ObjectTemplate->validationErrors);
            } else {
                $this->Flash->error('Object Template could not be deleted');
            }
        }
        $this->redirect($this->referer());
    }

    public function index($all = false)
    {
        $conditions = [];

        if (!$all || !$this->isSiteAdmin()) {
            $conditions['ObjectTemplates.active'] = 1;
        }

        $this->CRUD->index(
            [
            'filters' => $this->filterFields,
            'quickFilters' => $this->quickFilterFields,
            'quickFilterForMetaField' => ['enabled' => true, 'wildcard_search' => true],
            'conditions' => $conditions
            ]
        );

        $responsePayload = $this->CRUD->getResponsePayload();

        if (!empty($responsePayload)) {
            return $responsePayload;
        }
    }

    public function update($type = false, $force = false)
    {
        if (!empty($this->request->getParam('type'))) {
            $type = $this->request->getParam('type');
        }
        if (!empty($this->request->getParam('force'))) {
            $force = $this->request->getParam('force');
        }
        $result = $this->ObjectTemplates->update($this->ACL->getUser(), $type, $force);
        $ObjectRelationshipTable = $this->fetchTable('ObjectRelationships');
        $ObjectRelationshipTable->update();
        $this->Log = $this->fetchTable('Logs');
        $fails = 0;
        $successes = 0;
        if (!empty($result)) {
            if (isset($result['success'])) {
                foreach ($result['success'] as $id => $success) {
                    if (isset($success['old'])) {
                        $change = $success['name'] . ': updated from v' . $success['old'] . ' to v' . $success['new'];
                    } else {
                        $change = $success['name'] . ' v' . $success['new'] . ' installed';
                    }
                    $logEntry = $this->Log->newEntity(
                        [
                        'org' => $this->ACL->getUser()->Organisation->name,
                        'model' => 'ObjectTemplate',
                        'model_id' => $id,
                        'email' => $this->ACL->getUser()->email,
                        'action' => 'update',
                        'user_id' => $this->ACL->getUser()->id,
                        'title' => 'Object template updated',
                        'change' => $change,
                        ]
                    );
                    $this->Log->save($logEntry);
                    $successes++;
                }
            }
            if (isset($result['fails'])) {
                foreach ($result['fails'] as $id => $fail) {
                    $logEntry = $this->Log->newEntity(
                        [
                        'org' => $this->ACL->getUser()->Organisation->name,
                        'model' => 'ObjectTemplate',
                        'model_id' => $id,
                        'email' => $this->ACL->getUser()->email,
                        'action' => 'update',
                        'user_id' => $this->Auth->user('id'),
                        'title' => 'Object template failed to update',
                        'change' => $fail['name'] . ' could not be installed/updated. Error: ' . $fail['fail'],
                        ]
                    );
                    $this->Log->save($logEntry);
                    $fails++;
                }
            }
        } else {
            $logEntry = $this->Log->newEntity(
                [
                'org' => $this->ACL->getUser()->Organisation->name,
                'model' => 'ObjectTemplate',
                'model_id' => 0,
                'email' => $this->ACL->getUser()->email,
                'action' => 'update',
                'user_id' => $this->ACL->getUser()->id,
                'title' => 'Object template update (nothing to update)',
                'change' => 'Executed an update of the Object Template library, but there was nothing to update.',
                ]
            );
            $this->Log->save($logEntry);
        }
        if ($successes == 0 && $fails == 0) {
            $this->Flash->info('All object templates are up to date already.');
        } elseif ($successes == 0) {
            $this->Flash->error('Could not update any of the object templates');
        } else {
            $message = 'Successfully updated ' . $successes . ' object templates.';
            if ($fails != 0) {
                $message .= ' However, could not update ' . $fails . ' object templates.';
            }
            $this->Flash->success($message);
        }
        $this->redirect(['controller' => 'ObjectTemplates', 'action' => 'index']);
    }

    public function activate()
    {
        $id = $this->request->getData()['id'];
        if (!is_numeric($id)) {
            return new Response(['body' => json_encode(['saved' => false, 'errors' => 'Template not found.']), 'status' => 200, 'type' => 'json']);
        }
        $result = $this->ObjectTemplates->setActive($id);
        if ($result === false) {
            return new Response(['body' => json_encode(['saved' => false, 'errors' => 'Template\'s state could not be toggeled.']), 'status' => 200, 'type' => 'json']);
        }
        $message = (($result == 1) ? 'activated' : 'disabled');
        return new Response(['body' => json_encode(['saved' => true, 'success' => 'Template ' . $message . '.']), 'status' => 200, 'type' => 'json']);
    }

    public function getToggleField()
    {
        if (!$this->request->is('ajax')) {
            throw new MethodNotAllowedException('This action is available via AJAX only.');
        }
        $this->layout = false;
        $this->render('ajax/getToggleField');
    }

    public function getRaw($uuidOrName)
    {
        $template = $this->ObjectTemplate->getRawFromDisk($uuidOrName);
        if (empty($template)) {
            throw new NotFoundException(__('Template not found'));
        }
        return $this->RestResponse->viewData($template);
    }

    public function possibleObjectTemplates()
    {
        session_abort();
        $this->request->allowMethod(['post']);

        $attributeTypes = $this->request->getData()['attributeTypes'];
        $templates = $this->ObjectTemplate->fetchPossibleTemplatesBasedOnTypes($attributeTypes)['templates'];

        $results = [];
        foreach ($templates as $template) {
            $template = $template['ObjectTemplate'];
            if ($template['compatibility'] === true && empty($template['invalidTypes'])) {
                $results[] = [
                    'id' => $template['id'],
                    'name' => $template['name'],
                    'description' => $template['description'],
                    'meta_category' => $template['meta_category'],
                ];
            }
        }

        return $this->RestResponse->viewData($results, 'json');
    }
}
