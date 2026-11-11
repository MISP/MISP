<?php

/**
 * create, read, update and delete (CRUD)
 */

class BlocklistComponent extends Component
{
    public $settings = array();
    public $defaultModel = '';

    public $components = array('RestResponse');

    public function index($rest = false, $filters = array())
    {
        if (!empty($filters)) {
            $this->controller->paginate['conditions'] = $filters;
        }
        if ($rest) {
            $data = $this->controller->{$this->controller->defaultModel}->find('all', array(
                'recursive' => -1,
                'conditions' => isset($this->controller->paginate['conditions']) ? $this->controller->paginate['conditions'] : []
            ));
            $blocklist = [];
            foreach ($data as $item) {
                $blocklist[] = $item[$this->controller->defaultModel];
            }
            return $this->RestResponse->viewData($blocklist);
        } else {
            $this->controller->set('response', $this->controller->paginate());
        }
    }

    public function add($rest = false)
    {
        if ($this->controller->request->is('post')) {
            if ($rest) {
                if ($this->controller->response->type() === 'application/json') {
                    $isJson = true;
                    $data = $this->controller->request->input('json_decode', true);
                } else {
                    $data = $this->controller->request->data;
                }
                if (isset($data['request'])) {
                    $data = $data['request'];
                }
            } else {
                $data = $this->controller->request->data;
            }
            if (!isset($data[$this->controller->defaultModel])) {
                $data = [$this->controller->defaultModel => $data];
            }
            if (!isset($data[$this->controller->defaultModel])) {
                throw new InvalidArgumentException(__('Pass a list of uuids via the "uuids" key in the request object.'));
            }
            if (is_array($data[$this->controller->defaultModel]['uuids'])) {
                $uuids = $data[$this->controller->defaultModel]['uuids'];
            } else {
                $uuids = explode(PHP_EOL, trim($data[$this->controller->defaultModel]['uuids']));
            }
            $successes = array();
            $fails = array();
            foreach ($uuids as $uuid) {
                $uuid = trim($uuid);
                if (strlen($uuid) == 36) {
                    $this->controller->{$this->controller->defaultModel}->create();
                    $object = array();
                    foreach ($this->controller->{$this->controller->defaultModel}->blocklistFields as $f) {
                        if ($f === $this->controller->{$this->controller->defaultModel}->blocklistTarget . '_uuid') {
                            $object[$f] = $uuid;
                        } else {
                            $object[$f] = !empty($data[$this->controller->defaultModel][$f]) ? $data[$this->controller->defaultModel][$f] : '';
                        }
                    }
                    if ($this->controller->{$this->controller->defaultModel}->save($object)) {
                        $successes[] = $uuid;
                    } else {
                        $fails[] = $uuid;
                    }
                } else {
                    $fails[] = $uuid;
                }
            }
            $message = sprintf(__('Done. Added %d new entries to the blocklist. %d entries could not be saved.'), count($successes), count($fails));
            if ($rest) {
                $result = [
                    'result' => [
                        'successes' => $successes,
                        'fails' => $fails
                    ],
                    'message' => $message
                ];
                return $this->RestResponse->viewData($result);
            } else {
                $this->controller->Flash->success($message);
                $this->controller->redirect(array('action' => 'index'));
            }
        }
    }

    public function edit($rest = false, $id)
    {
        if (Validation::uuid($id)) {
            $blockEntry = $this->controller->{$this->controller->defaultModel}->find('first', [
                'conditions' => array(
                    $this->controller->{$this->controller->defaultModel}->blocklistTarget . '_uuid' => $id
                )
            ]);
        } else {
            $blockEntry = $this->controller->{$this->controller->defaultModel}->find('first', array('conditions' => array('id' => $id)));
        }
        if (empty($blockEntry)) {
            throw new NotFoundException(__('Blocklist item not found.'));
        }
        $this->controller->set('blockEntry', $blockEntry);
        if ($this->controller->request->is('post')) {
            if ($rest) {
                if ($this->controller->response->type() === 'application/json') {
                    $isJson = true;
                    $data = $this->controller->request->input('json_decode', true);
                } else {
                    $data = $this->controller->request->data;
                }
                if (isset($data['request'])) {
                    $data = $data['request'];
                }
                if (!isset($data[$this->controller->defaultModel])) {
                    $data = [$this->controller->defaultModel => $data];
                }
            } else {
                $data = $this->controller->request->data;
            }
            $fields = $this->controller->{$this->controller->defaultModel}->blocklistFields;
            foreach ($fields as $f) {
                if ($f == 'uuid') {
                    continue;
                }
                if (isset($data[$this->controller->defaultModel][$f])) {
                    $blockEntry[$this->controller->defaultModel][$f] = $data[$this->controller->defaultModel][$f];
                }
            }
            if ($this->controller->{$this->controller->defaultModel}->save($blockEntry)) {
                if ($rest) {
                    return $this->RestResponse->viewData(
                        $this->controller->{$this->controller->defaultModel}->find('first', [
                            'recursive' => -1,
                            'conditions' => [
                                'id' => $this->controller->{$this->controller->defaultModel}->id
                            ]
                        ])
                    );
                } else {
                    $this->controller->Flash->success(__('Blocklist item added.'));
                    $this->controller->redirect(array('action' => 'index'));
                }
            } else {
                if ($rest) {
                    throw new MethodNotAllowedException('Could not save the blocklist item.');
                } else {
                    $this->controller->Flash->error(__('Could not save the blocklist item'));
                    $this->controller->redirect(array('action' => 'index'));
                }
            }
        }
    }

    public function delete($rest = false, $id)
    {
        // Every blocklist controller routes its delete() through here, including
        // the two that resolve a uuid themselves first, so one guard covers all
        // five. deleteSelection() and massDelete() already gate on the verb.
        $this->controller->request->allowMethod(['post']);
        if (Validation::uuid($id)) {
            $blockEntry = $this->controller->{$this->controller->defaultModel}->find('first', [
                'conditions' => array(
                    $this->controller->{$this->controller->defaultModel}->blocklistTarget . '_uuid' => $id
                )
            ]);
        } else {
            $blockEntry = $this->controller->{$this->controller->defaultModel}->find('first', array('conditions' => array('id' => $id)));
        }
        if (empty($blockEntry)) {
            throw new NotFoundException(__('Invalid blocklist entry'));
        }

        if ($this->controller->{$this->controller->defaultModel}->delete($blockEntry[$this->controller->defaultModel]['id'])) {
            $message = __('Blocklist entry removed');
            if ($rest) {
                return $this->RestResponse->saveSuccessResponse($this->controller->defaultModel, 'delete', $id, false, $message);
            }
            $this->controller->Flash->success($message);
        } else {
            $message = __('Could not remove the blocklist entry');
            if ($rest) {
                return $this->RestResponse->saveFailResponse($this->controller->defaultModel, 'delete', $id, $message);
            }
            $this->controller->error($message);
        }
        $this->controller->redirect(array('action' => 'index'));
    }

    /**
     * Modal-friendly deletion used by the Overmind BS5 index views.
     *
     * On GET it renders the themed confirmation fragment
     * (ajax/<model>DeleteConfirmationForm); on POST/PUT/DELETE it removes the
     * supplied id list (single row action or bulk multi-select) and redirects
     * back to the index. Mirrors CRUDComponent::deleteSelection so the shared
     * scaffold behaves identically for the blocklist family. The legacy
     * delete()/massDelete() actions are left untouched for the Default theme.
     */
    public function deleteSelection($rest = false, $id = null)
    {
        $model = $this->controller->defaultModel;
        $Model = $this->controller->{$model};
        if ($this->controller->request->is(['post', 'put', 'delete'])) {
            if (isset($this->controller->request->data['id'])) {
                $this->controller->request->data[$model] = $this->controller->request->data;
            }
            if (!isset($id) && isset($this->controller->request->data[$model]['id'])) {
                $idList = $this->controller->request->data[$model]['id'];
                if (!is_array($idList)) {
                    if (is_numeric($idList) || Validation::uuid($idList)) {
                        $idList = [$idList];
                    } else {
                        $idList = json_decode($idList, true);
                    }
                }
            } else {
                $idList = [$id];
            }
            if (empty($idList)) {
                throw new NotFoundException(__('Invalid input.'));
            }
            $successes = array();
            $fails = array();
            foreach ($idList as $cid) {
                $conditions = Validation::uuid($cid)
                    ? array($Model->blocklistTarget . '_uuid' => $cid)
                    : array($model . '.id' => $cid);
                $item = $Model->find('first', array(
                    'conditions' => $conditions,
                    'recursive' => -1,
                ));
                if (empty($item)) {
                    $fails[] = $cid;
                    continue;
                }
                if ($Model->delete($item[$model]['id'])) {
                    $successes[] = $cid;
                } else {
                    $fails[] = $cid;
                }
            }
            $successCount = count($successes);
            $failCount = count($fails);
            if ($successCount) {
                $message = __n('%s blocklist entry deleted.', '%s blocklist entries deleted.', $successCount, $successCount);
                if ($failCount) {
                    $message .= ' ' . __n('%s entry could not be deleted.', '%s entries could not be deleted.', $failCount, $failCount);
                }
            } else {
                $message = __('No blocklist entries were deleted.');
            }
            if ($rest) {
                if ($successCount) {
                    return $this->RestResponse->saveSuccessResponse($model, 'deleteSelection', $id, false, $message);
                }
                return $this->RestResponse->saveFailResponse($model, 'deleteSelection', false, $message);
            }
            if ($successCount) {
                $this->controller->Flash->success($message);
            } else {
                $this->controller->Flash->error($message);
            }
            return $this->controller->redirect(array('action' => 'index'));
        }
        $itemList = is_numeric($id) ? array($id) : json_decode($id, true);
        $this->controller->request->data[$model]['id'] = json_encode($itemList);
        $this->controller->set('idArray', $itemList);
        $this->controller->layout = false;
        return $this->controller->render('ajax/' . lcfirst($model) . 'DeleteConfirmationForm');
    }

    public $controller;

    public function initialize(Controller $controller)
    {
        $this->controller = $controller;
    }

    public function startup(Controller $controller)
    {
        $this->controller = $controller;
    }

    public function __construct(ComponentCollection $collection, $settings = array())
    {
        $this->settings = Set::merge($this->settings, $settings);
        parent::__construct($collection, $this->settings);
    }
}
