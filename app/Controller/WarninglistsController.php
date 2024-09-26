<?php
App::uses('AppController', 'Controller');

/**
 * @property Warninglist $Warninglist
 */
class WarninglistsController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public $paginate = array(
        'limit' => 60,
        'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user can view/page.
        'contain' => array(
            'WarninglistType'
        ),
        'order' => array(
            'Warninglist.id' => 'DESC'
        ),
        'recursive' => -1,
    );

    public function index()
    {
        $filters = $this->IndexFilter->harvestParameters(['value', 'enabled']);
        if (!empty($filters['value'])) {
            $this->paginate['conditions'] = [
                'OR' => [
                    'LOWER(Warninglist.name) LIKE' => '%' . strtolower($filters['value']) . '%',
                    'LOWER(Warninglist.description) LIKE' => '%' . strtolower($filters['value']) . '%',
                    'LOWER(Warninglist.type)' => strtolower($filters['value']),
                ]
            ];
        }
        if (isset($filters['enabled'])) {
            $this->paginate['conditions'][] = ['Warninglist.enabled' => $filters['enabled']];
        }
        $this->Warninglist->addCountField(
            'warninglist_entry_count',
            $this->Warninglist->WarninglistEntry,
            ['WarninglistEntry.warninglist_id = Warninglist.id']
        );
        if ($this->_isRest()) {
            unset($this->paginate['limit']);
            $warninglists = $this->Warninglist->find('all', $this->paginate);
        } else {
            $warninglists = $this->paginate();
        }
        foreach ($warninglists as &$warninglist) {
            $validAttributes = array_column($warninglist['WarninglistType'], 'type');
            $warninglist['Warninglist']['valid_attributes'] = implode(', ', $validAttributes);
            unset($warninglist['WarninglistType']);
        }
        if ($this->_isRest()) {
            return $this->RestResponse->viewData(['Warninglists' => $warninglists], $this->response->type());
        }

        $this->set('warninglists', $warninglists);
        $this->set('passedArgsArray', $filters);
        $this->set('possibleCategories', $this->Warninglist->categories());
    }

    public function update()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__('This action is only accessible via POST requests.'));
        }
        $result = $this->Warninglist->update();
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
                        'model' => 'Warninglist',
                        'model_id' => $id,
                        'email' => $this->Auth->user('email'),
                        'action' => 'update',
                        'user_id' => $this->Auth->user('id'),
                        'title' => __('Warning list updated'),
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
                        'model' => 'Warninglist',
                        'model_id' => $id,
                        'email' => $this->Auth->user('email'),
                        'action' => 'update',
                        'user_id' => $this->Auth->user('id'),
                        'title' => __('Warning list failed to update'),
                        'change' => __('%s could not be installed/updated. Error: %s', $fail['name'], $fail['fail']), // TODO: needs to be optimized for non-SVO languages
                    ));
                    $fails++;
                }
            }
        } else {
            $this->Log->create();
            $this->Log->saveOrFailSilently(array(
                'org' => $this->Auth->user('Organisation')['name'],
                'model' => 'Warninglist',
                'model_id' => 0,
                'email' => $this->Auth->user('email'),
                'action' => 'update',
                'user_id' => $this->Auth->user('id'),
                'title' => __('Warninglist update (nothing to update)'),
                'change' => __('Executed an update of the warning lists, but there was nothing to update.'),
            ));
        }
        if ($successes == 0 && $fails == 0) {
            $flashType = 'info';
            $message = __('All warninglists are up to date already.');
        } elseif ($successes == 0) {
            $flashType = 'error';
            $message = __('Could not update any of the warning lists');
        } else {
            $flashType = 'success';
            $message = __('Successfully updated %s warninglists.', $successes);
            if ($fails != 0) {
                $message .= __(' However, could not update %s warninglists.', $fails); // TODO: non-SVO languages need to be considered
            }
        }
        if ($this->_isRest()) {
            return $this->RestResponse->saveSuccessResponse('Warninglist', 'update', false, $this->response->type(), $message);
        } else {
            $this->Flash->{$flashType}($message);
            $this->redirect(array('controller' => 'warninglists', 'action' => 'index'));
        }
    }

    public function add()
    {
        $types = array_combine($this->Warninglist->validate['type']['rule'][1], $this->Warninglist->validate['type']['rule'][1]);
        $this->set('possibleTypes', $types);
        $this->set('possibleCategories', $this->Warninglist->categories());

        $this->loadModel('MispAttribute');
        $this->set('matchingAttributes', array_combine(array_keys($this->MispAttribute->typeDefinitions), array_keys($this->MispAttribute->typeDefinitions)));

        $this->CRUD->add([
            'beforeSave' => function (array $warninglist) {
                if (empty($warninglist['Warninglist'])) {
                    $warninglist = ['Warninglist' => $warninglist];
                }
                if (isset($warninglist['Warninglist']['entries'])) {
                    if (is_array($warninglist['Warninglist']['entries'])) {
                        $entries = $this->Warninglist->parseArray($warninglist['Warninglist']['entries']);
                    } else {
                        $entries = $this->Warninglist->parseFreetext($warninglist['Warninglist']['entries']);
                        
                    }
                    unset($warninglist['Warninglist']['entries']);
                    $warninglist['WarninglistEntry'] = $entries;
                }
                if (empty($warninglist['WarninglistEntry'])) {
                    $warninglist['Warninglist']['entries'] = ''; // Make model validation fails
                }
                if (empty($warninglist['Warninglist']['matching_attributes'])) {
                    $warninglist['Warninglist']['matching_attributes'] = ['ALL'];
                }
                if (isset($warninglist['Warninglist']['matching_attributes']) && is_array($warninglist['Warninglist']['matching_attributes'])) {
                    $warninglist['WarninglistType'] = [];
                    foreach ($warninglist['Warninglist']['matching_attributes'] as $attribute) {
                        $warninglist['WarninglistType'][] = ['type' => $attribute];
                    }
                }
                $warninglist['Warninglist']['default'] = 0;
                return $warninglist;
            },
        ]);
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }
    }

    public function edit($id = null)
    {
        $types = array_combine($this->Warninglist->validate['type']['rule'][1], $this->Warninglist->validate['type']['rule'][1]);
        $this->set('possibleTypes', $types);
        $this->set('possibleCategories', $this->Warninglist->categories());

        $this->loadModel('MispAttribute');
        $this->set('matchingAttributes', array_combine(array_keys($this->MispAttribute->typeDefinitions), array_keys($this->MispAttribute->typeDefinitions)));

        $this->CRUD->edit($id, [
            'conditions' => ['default' => 0], // it is not possible to edit default warninglist
            'contain' => ['WarninglistEntry', 'WarninglistType'],
            'fields' => ['name', 'description', 'type', 'category', 'entries', 'matching_attributes'],
            'redirect' => ['action' => 'view', $id],
            'beforeSave' => function (array $warninglist) {
                if (empty($warninglist['Warninglist'])) {
                    $warninglist = ['Warninglist' => $warninglist];
                }
                if (isset($warninglist['Warninglist']['entries'])) {
                    if (is_array($warninglist['Warninglist']['entries'])) {
                        $entries = $this->Warninglist->parseArray($warninglist['Warninglist']['entries']);
                    } else {
                        $entries = $this->Warninglist->parseFreetext($warninglist['Warninglist']['entries']);
                        
                    }
                    unset($warninglist['Warninglist']['entries']);
                    $warninglist['WarninglistEntry'] = $entries;
                }
                if (empty($warninglist['WarninglistEntry'])) {
                    $warninglist['Warninglist']['entries'] = ''; // Make model validation fails
                }
                if (isset($warninglist['Warninglist']['matching_attributes']) && is_array($warninglist['Warninglist']['matching_attributes'])) {
                    $warninglist['WarninglistType'] = [];
                    foreach ($warninglist['Warninglist']['matching_attributes'] as $attribute) {
                        $warninglist['WarninglistType'][] = ['type' => $attribute];
                    }
                }
                $warninglist['Warninglist']['version']++;
                return $warninglist;
            },
        ]);
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }

        if (isset($this->request->data['WarninglistEntry'])) {
            $entries = [];
            foreach ($this->request->data['WarninglistEntry'] as $entry) {
                $value = $entry['value'];
                if ($entry['comment']) {
                    $value .= ' # ' . $entry['comment'];
                }
                $entries[] = $value;
            }
            $this->request->data['Warninglist']['entries'] = implode("\n", $entries);
        }

        if (isset($this->request->data['WarninglistType'])) {
            $attributes = array_column($this->request->data['WarninglistType'], 'type');
            $this->request->data['Warninglist']['matching_attributes'] = $attributes;
        }

        $this->render('add');
    }

    /*
     * toggle warninglists on or offset
     * Simply POST an ID or a list of IDs to toggle the current state
     * To control what state the warninglists should have after execution instead of just blindly toggling them, simply pass the enabled flag
     * Example:
     *   {"id": [5, 8], "enabled": 1}
     * Alternatively search by a substring in the warninglist's named, such as:
     *   {"name": ["%alexa%", "%iana%"], "enabled": 1}
     */
    public function toggleEnable()
    {
        if (!$this->request->is('post')) {
            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => __('This function only accepts POST requests.'))), 'status' => 200, 'type' => 'json'));
        }
        if (isset($this->request->data['Warninglist']['data'])) {
            $id = $this->request->data['Warninglist']['data'];
        } else {
            if (!empty($this->request->data['id'])) {
                $id = $this->request->data['id'];
            } elseif (!empty($this->request->data['name'])) {
                if (!is_array($this->request->data['name'])) {
                    $names = array($this->request->data['name']);
                } else {
                    $names = $this->request->data['name'];
                }
                $conditions = array();
                foreach ($names as $name) {
                    $conditions['OR'][] = array('LOWER(Warninglist.name) LIKE' => strtolower($name));
                }
                $id = $this->Warninglist->find('column', array(
                    'conditions' => $conditions,
                    'fields' => array('Warninglist.id')
                ));
            }
        }
        if (isset($this->request->data['enabled'])) {
            $enabled = $this->request->data['enabled'];
        }
        if (empty($id)) {
            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => __('Warninglist not found.'))), 'status' => 200, 'type' => 'json'));
        }
        $currentState = $this->Warninglist->find('all', array('conditions' => array('id' => $id), 'recursive' => -1));
        if (empty($currentState)) {
            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => __('Warninglist(s) not found.'))), 'status' => 200, 'type' => 'json'));
        }
        $success = 0;
        foreach ($currentState as $warningList) {
            if (isset($enabled)) {
                $warningList['Warninglist']['enabled'] = $enabled;
                $message = $enabled ? 'enabled' : 'disabled';
            } else {
                if ($warningList['Warninglist']['enabled']) {
                    $warningList['Warninglist']['enabled'] = 0;
                    $message = 'disabled';
                } else {
                    $warningList['Warninglist']['enabled'] = 1;
                    $message = 'enabled';
                }
                if (!isset($enabled) && count($currentState) > 1) {
                    $message = 'toggled';
                }
            }
            if ($this->Warninglist->save($warningList)) {
                $success += 1;
            }
            $this->Warninglist->regenerateWarninglistCaches($warningList['Warninglist']['id']);
        }
        if ($success) {
            return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => $success . __(' warninglist(s) ') . $message)), 'status' => 200, 'type' => 'json')); // TODO: non-SVO lang considerations
        } else {
            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => __('Warninglist(s) could not be toggled.'))), 'status' => 200, 'type' => 'json'));
        }
    }

    public function enableWarninglist($id, $enable = false)
    {
        $this->Warninglist->id = $id;
        if (!$this->Warninglist->exists()) {
            throw new NotFoundException(__('Invalid Warninglist.'));
        }
        // DBMS interoperability: convert boolean false to integer 0 so cakephp doesn't try to insert an empty string into the database
        if ($enable === false) {
            $enable = 0;
        }
        $this->Warninglist->saveField('enabled', $enable);
        $this->Warninglist->regenerateWarninglistCaches($id);
        if ($enable === 0) {
            $this->Flash->success(__('Warninglist disabled'));
        }
        else {
            $this->Flash->success(__('Warninglist enabled'));
        }
        $this->redirect(array('controller' => 'warninglists', 'action' => 'view', $id));
    }

    public function getToggleField()
    {
        if (!$this->request->is('ajax')) {
            throw new MethodNotAllowedException(__('This action is available via AJAX only.'));
        }
        $this->layout = false;
        $this->render('ajax/getToggleField');
    }

    public function view($id)
    {
        if (!is_numeric($id)) {
            throw new NotFoundException(__('Invalid ID.'));
        }
        $warninglist = $this->Warninglist->find('first', array(
            'contain' => array('WarninglistEntry', 'WarninglistType'),
            'conditions' => array('id' => $id))
        );
        if (empty($warninglist)) {
            throw new NotFoundException(__('Warninglist not found.'));
        }
        if ($this->IndexFilter->isCsv()) {
            $csv = [];
            foreach ($warninglist['WarninglistEntry'] as $entry) {
                $line = $entry['value'];
                if ($entry['comment']) {
                    $line .= ';' . $entry['comment'];
                }
                $csv[] = $line;
            }
            return $this->RestResponse->viewData(implode("\n", $csv), 'csv');
        }
        if ($this->_isRest()) {
            $warninglist['Warninglist']['WarninglistEntry'] = $warninglist['WarninglistEntry'];
            $warninglist['Warninglist']['WarninglistType'] = $warninglist['WarninglistType'];
            return $this->RestResponse->viewData(['Warninglist' => $warninglist['Warninglist']], $this->response->type());
        }

        $this->set('warninglist', $warninglist);
        $this->set('possibleCategories', $this->Warninglist->categories());
    }

    public function import()
    {
        $this->request->allowMethod(['post']);

        if (empty($this->request->data)) {
            throw new BadRequestException(__('No valid data received.'));
        }

        foreach (['name', 'type', 'version', 'description', 'matching_attributes', 'list'] as $filed) {
            if (!isset($this->request->data[$filed])) {
                throw new BadRequestException(__('No valid data received: field `%s` is missing.', $filed));
            }
        }

        if (!is_array($this->request->data['list'])) {
            throw new BadRequestException(__('No valid data received: `list` field is not array'));
        }

        try {
            $id = $this->Warninglist->import($this->request->data);
            return $this->RestResponse->saveSuccessResponse('Warninglist', 'import', $id, false, __('Warninglist imported'));
        } catch (Exception $e) {
            return $this->RestResponse->saveFailResponse('Warninglist', 'import', false, $e->getMessage());
        }
    }

    public function export($id = null)
    {
        if (empty($id)) {
            throw new NotFoundException(__('Warninglist not found.'));
        }
        $warninglist = $this->Warninglist->find('first', [
            'contain' => ['WarninglistType'],
            'conditions' => ['id' => $id],
        ]);
        if (empty($warninglist)) {
            throw new NotFoundException(__('Warninglist not found.'));
        }
        $matchingAttributes = array_column($warninglist['WarninglistType'], 'type');
        $list = $this->Warninglist->WarninglistEntry->find('column', [
            'conditions' => ['warninglist_id' => $warninglist['Warninglist']['id']],
            'fields' => ['value'],
        ]);
        $output = [
            'name' => $warninglist['Warninglist']['name'],
            'type' => $warninglist['Warninglist']['type'],
            'version' => $warninglist['Warninglist']['version'],
            'description' => $warninglist['Warninglist']['description'],
            'matching_attributes' => $matchingAttributes,
            'list' => $list,
        ];
        return $this->RestResponse->viewData($output, 'json');
    }

    public function delete($id)
    {
        if ($this->request->is('post')) {
            $id = (int)$id;
            $result = $this->Warninglist->quickDelete($id);
            if ($result) {
                $this->Flash->success(__('Warninglist successfully deleted.'));
            } else {
                $this->Flash->error(__('Warninglist could not be deleted.'));
            }
            $this->redirect(['controller' => 'warninglists', 'action' => 'index']);
        } else {
            if ($this->request->is('ajax')) {
                $this->set('id', $id);
                $this->render('ajax/delete_confirmation');
            } else {
                throw new MethodNotAllowedException(__('This function can only be reached via AJAX.'));
            }
        }
    }

    public function checkValue()
    {
        if ($this->request->is('post')) {
            if (empty($this->request->data)) {
                throw new NotFoundException(__('No valid data received.'));
            }
            $data = $this->request->data;
            if (is_array($data) && isset($data['Warninglist'])) {
                $data = $data['Warninglist'];
            }
            if (!is_array($data)) {
                $data = array($data);
            }
            if (array_key_exists('[]', $data)) {
                $data = $data['[]'];
            }

            $hits = array();
            $warninglists = $this->Warninglist->getEnabled();
            foreach ($data as $dataPoint) {
                $dataPoint = trim($dataPoint);
                foreach ($warninglists as $warninglist) {
                    $values = $this->Warninglist->getFilteredEntries($warninglist);
                    $result = $this->Warninglist->checkValue($values, $dataPoint, '', $warninglist['Warninglist']['type']);
                    if ($result !== false) {
                        $hits[$dataPoint][] = [
                            'id' => $warninglist['Warninglist']['id'],
                            'name' => $warninglist['Warninglist']['name'],
                            'matched' => $result[0],
                        ];
                    }
                }
            }
            if ($this->_isRest()) {
                return $this->RestResponse->viewData($hits, $this->response->type());
            }
            $this->set('hits', $hits);
            $this->set('data', $data);
        } else {
            if ($this->_isRest()) {
                return $this->RestResponse->describe('Warninglists', 'checkValue', false, $this->response->type());
            }
        }
    }
}
