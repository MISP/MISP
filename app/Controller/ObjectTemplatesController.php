<?php
App::uses('AppController', 'Controller');

/**
 * @property ObjectTemplate  $ObjectTemplate
 */
class ObjectTemplatesController extends AppController
{
    public $components = array('RequestHandler', 'Session');

    public $paginate = array(
        'limit' => 60,
        'order' => array(
            'Object.id' => 'desc'
        ),
        'contain' => array(
            'Organisation' => array('fields' => array('Organisation.id', 'Organisation.name', 'Organisation.uuid'))
        ),
        'recursive' => -1
    );

    public function beforeFilter()
    {
        parent::beforeFilter();
        if (in_array($this->request->action, ['objectMetaChoice', 'objectChoice', 'possibleObjectTemplates'], true)) {
            $this->Security->doNotGenerateToken = true;
        }
        $this->Security->unlockedActions[] = 'possibleObjectTemplates';
    }

    public function objectMetaChoice($eventId)
    {
        session_abort();

        $metas = $this->ObjectTemplate->find('column', array(
            'conditions' => array('ObjectTemplate.active' => 1),
            'fields' => array('ObjectTemplate.meta-category'),
            'order' => array('ObjectTemplate.meta-category asc'),
            'unique' => true,
        ));

        $items = [[
            'name' => __('All Objects'),
            'value' => $this->baseurl . "/ObjectTemplates/objectChoice/$eventId/0"
        ]];
        foreach ($metas as $meta) {
            $items[] = array(
                'name' => $meta,
                'value' => $this->baseurl . "/ObjectTemplates/objectChoice/$eventId/$meta",
            );
        }

        $this->set('items', $items);
        $this->set('options', array(
            'multiple' => 0,
        ));
        $this->render('/Elements/generic_picker');
    }

    public function objectChoice($event_id, $category=false)
    {
        $user = $this->_closeSession();
        $this->ObjectTemplate->populateIfEmpty($user);
        $conditions = array('ObjectTemplate.active' => 1);
        if ($category !== false && $category !== "0") {
            $conditions['meta-category'] = $category;
        }
        $templates_raw = $this->ObjectTemplate->find('all', array(
            'recursive' => -1,
            'conditions' => $conditions,
            'fields' => array('id', 'meta-category', 'name', 'description'),
            'order' => array('ObjectTemplate.name asc')
        ));

        $items = array();
        foreach($templates_raw as $template) {
            $template = $template['ObjectTemplate'];
            $items[] = array(
                'name' => $template['name'],
                'value' => $template['id'],
                'template' => array(
                    'name' => $template['name'],
                    'infoExtra' => $template['description'],
                    'infoContextual' => $template['meta-category']
                )
            );
        }

        $this->set('items', $items);
        $this->set('options', array(
            'functionName' => 'redirectAddObject',
            'multiple' => 0,
            'select_options' => array(
                'additionalData' => array('event_id' => $event_id),
            ),
        ));
        $this->render('/Elements/generic_picker');
    }

    public function view($id)
    {
        if (Validation::uuid($id)) {
            $temp = $this->ObjectTemplate->find('first', array(
                'recursive' => -1,
                'conditions' => array('ObjectTemplate.uuid' => $id),
                'fields' => array('ObjectTemplate.id', 'ObjectTemplate.uuid'),
                'order' => array('ObjectTemplate.version desc')
            ));
            if (empty($temp)) {
                throw new NotFoundException(__('Invalid object template'));
            }
            $id = $temp['ObjectTemplate']['id'];
        } elseif (!is_numeric($id)) {
            throw new NotFoundException(__('Invalid object template id.'));
        }
        $params = array(
            'recursive' => -1,
            'contain' => array(
                'Organisation' => array('fields' => array('Organisation.id', 'Organisation.name', 'Organisation.uuid'))
            ),
            'conditions' => array('ObjectTemplate.id' => $id)
        );
        if ($this->_isRest()) {
            $params['contain'][] = 'ObjectTemplateElement';
        }
        if ($this->_isSiteAdmin()) {
            $params['contain']['User']= array('fields' => array('User.id', 'User.email'));
        }
        $objectTemplate = $this->ObjectTemplate->find('first', $params);
        if (empty($objectTemplate)) {
            throw new NotFoundException('Invalid object template');
        }
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($objectTemplate, $this->response->type());
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
        $this->ObjectTemplate->id = $id;
        if (!$this->ObjectTemplate->exists()) {
            throw new NotFoundException('Invalid Object Template');
        }
        if ($this->ObjectTemplate->delete()) {
            if ($this->_isRest()) {
                return $this->RestResponse->saveSuccessResponse('ObjectTemplates', 'admin_delete', $id, $this->response->type());
            } else {
                $this->Flash->success(__('Object Template deleted'));
            }
        } else {
            if ($this->_isRest()) {
                return $this->RestResponse->saveFailResponse('ObjectTemplates', 'admin_delete', $id, $this->ObjectTemplate->validationErrors, $this->response->type());
            } else {
                $this->Flash->error('Object Template could not be deleted');
            }
        }
        $this->redirect($this->referer());
    }

    public function index($all = false)
    {
        $passedArgsArray = array();
        $passedArgs = $this->passedArgs;
        if (!$all || !$this->_isSiteAdmin()) {
            $this->paginate['conditions'][] = array('ObjectTemplate.active' => 1);
            $this->set('all', false);
        } else {
            $this->set('all', true);
        }
        if (!empty($this->params['named']['searchall'])) {
            $searchTerm = '%' . strtolower($this->request->params['named']['searchall']) . '%';
            $this->paginate['conditions']['AND']['OR'] = array(
                'ObjectTemplate.uuid LIKE' => $searchTerm,
                'LOWER(ObjectTemplate.name) LIKE' => $searchTerm,
                'ObjectTemplate.meta-category LIKE' => $searchTerm,
                'LOWER(ObjectTemplate.description) LIKE' => $searchTerm,
            );
        }
        if ($this->_isRest()) {
            $rules = $this->paginate;
            unset($rules['limit']);
            unset($rules['order']);
            $objectTemplates = $this->ObjectTemplate->find('all', $rules);
            return $this->RestResponse->viewData($objectTemplates, $this->response->type());
        }

        $this->paginate['order'] = array('ObjectTemplate.name' => 'ASC');
        $objectTemplates = $this->paginate();
        $this->set('list', $objectTemplates);
        $this->set('passedArgs', json_encode($passedArgs));
        $this->set('passedArgsArray', $passedArgsArray);
    }

    public function create()
    {
      if (!$this->request->is('post')) {
        throw new MethodNotAllowedException();
      }

      if ($this->_isRest() && $this->request->is('post')) {
        $result = $this->ObjectTemplate->addNewObjects($this->Auth->user(), json_decode($this->request->data));
        return $this->RestResponse->viewData(array(
          'result' => $result
        ));
      }
    }

    public function update($type = false, $force = false)
    {
        if (!empty($this->params['named']['type'])) {
            $type = $this->params['named']['type'];
        }
        if (!empty($this->params['named']['force'])) {
            $force = $this->params['named']['force'];
        }
        $result = $this->ObjectTemplate->update($this->Auth->user(), $type, $force);
        $this->loadModel('ObjectRelationship');
        $result2 = $this->ObjectRelationship->update();
        $this->Log = ClassRegistry::init('Log');
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
                    $this->Log->create();
                    $this->Log->saveOrFailSilently(array(
                            'org' => $this->Auth->user('Organisation')['name'],
                            'model' => 'ObjectTemplate',
                            'model_id' => $id,
                            'email' => $this->Auth->user('email'),
                            'action' => 'update',
                            'user_id' => $this->Auth->user('id'),
                            'title' => 'Object template updated',
                            'change' => $change,
                    ));
                    $successes++;
                }
            }
            if (isset($result['fails'])) {
                foreach ($result['fails'] as $id => $fail) {
                    $this->Log->create();
                    $this->Log->saveOrFailSilently(array(
                            'org' => $this->Auth->user('Organisation')['name'],
                            'model' => 'ObjectTemplate',
                            'model_id' => $id,
                            'email' => $this->Auth->user('email'),
                            'action' => 'update',
                            'user_id' => $this->Auth->user('id'),
                            'title' => 'Object template failed to update',
                            'change' => $fail['name'] . ' could not be installed/updated. Error: ' . $fail['fail'],
                    ));
                    $fails++;
                }
            }
        } else {
            $this->Log->create();
            $this->Log->saveOrFailSilently(array(
                    'org' => $this->Auth->user('Organisation')['name'],
                    'model' => 'ObjectTemplate',
                    'model_id' => 0,
                    'email' => $this->Auth->user('email'),
                    'action' => 'update',
                    'user_id' => $this->Auth->user('id'),
                    'title' => 'Object template update (nothing to update)',
                    'change' => 'Executed an update of the Object Template library, but there was nothing to update.',
            ));
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
        $this->redirect(array('controller' => 'ObjectTemplates', 'action' => 'index'));
    }

    public function activate()
    {
        $id = $this->request->data['ObjectTemplate']['data'];
        if (!is_numeric($id)) {
            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Template not found.')), 'status' => 200, 'type' => 'json'));
        }
        $result = $this->ObjectTemplate->setActive($id);
        if ($result === false) {
            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Template\'s state could not be toggeled.')), 'status' => 200, 'type' => 'json'));
        }
        $message = (($result == 1) ? 'activated' : 'disabled');
        return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Template ' . $message . '.')), 'status' => 200, 'type' => 'json'));
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
        return $this->RestResponse->viewData($template, $this->response->type());
    }

    public function possibleObjectTemplates()
    {
        session_abort();
        $this->request->allowMethod(['post']);

        $attributeTypes = $this->request->data['attributeTypes'];
        $templates = $this->ObjectTemplate->fetchPossibleTemplatesBasedOnTypes($attributeTypes)['templates'];

        $results = [];
        foreach ($templates as $template) {
            $template = $template['ObjectTemplate'];
            if ($template['compatibility'] === true && empty($template['invalidTypes'])) {
                $results[] = [
                    'id' => $template['id'],
                    'name' => $template['name'],
                    'description' => $template['description'],
                    'meta-category' => $template['meta-category'],
                ];
            }
        }

        return $this->RestResponse->viewData($results, 'json');
    }
}
