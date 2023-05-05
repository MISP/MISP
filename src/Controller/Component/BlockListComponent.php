<?php

namespace App\Controller\Component;

use Cake\Controller\Component;
use Cake\Validation\Validation;

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
            $data = $this->controller->{$this->defaultModel}->find('all', array(
                'recursive' => -1,
                'conditions' => isset($this->controller->paginate['conditions']) ? $this->controller->paginate['conditions'] : []
            ));
            $blocklist = [];
            foreach ($data as $item) {
                $blocklist[] = $item[$this->defaultModel];
            }
            return $this->RestResponse->viewData($blocklist);
        } else {
            $this->controller->set('response', $this->controller->paginate());
        }
    }

    public function add($rest = false)
    {
        if ($this->controller->getRequest()->is('post')) {
            if ($rest) {
                if ($this->controller->getResponse()->getType() === 'application/json') {
                    $isJson = true;
                    $data = $this->controller->getRequest()->input('json_decode', true);
                } else {
                    $data = $this->controller->getRequest()->getData();
                }
                if (isset($data['request'])) {
                    $data = $data['request'];
                }
            } else {
                $data = $this->controller->getRequest()->getData();
            }
            if (!isset($data[$this->defaultModel])) {
                $data = [$this->defaultModel => $data];
            }
            if (!isset($data[$this->defaultModel])) {
                throw new InvalidArgumentException(__('Pass a list of uuids via the "uuids" key in the request object.'));
            }
            if (is_array($data[$this->defaultModel]['uuids'])) {
                $uuids = $data[$this->defaultModel]['uuids'];
            } else {
                $uuids = explode(PHP_EOL, trim($data[$this->defaultModel]['uuids']));
            }
            $successes = array();
            $fails = array();
            foreach ($uuids as $uuid) {
                $uuid = trim($uuid);
                if (strlen($uuid) == 36) {
                    $object = $this->controller->{$this->defaultModel}->newEmptyEntity();
                    foreach ($this->controller->{$this->defaultModel}->blocklistFields as $f) {
                        if ($f === $this->controller->{$this->defaultModel}->blocklistTarget . '_uuid') {
                            $object[$f] = $uuid;
                        } else {
                            $object[$f] = !empty($data[$this->defaultModel][$f]) ? $data[$this->defaultModel][$f] : '';
                        }
                    }
                    if ($this->controller->{$this->defaultModel}->save($object)) {
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

    public function edit($id, $rest = false)
    {
        if (Validation::uuid($id)) {
            $blockEntry = $this->controller->{$this->defaultModel}->find('all', [
                'conditions' => array(
                    $this->controller->{$this->defaultModel}->blocklistTarget . '_uuid' => $id
                )
            ])->first();
        } else {
            $blockEntry = $this->controller->{$this->defaultModel}->find('all', array('conditions' => array('id' => $id)))->first();
        }
        if (empty($blockEntry)) {
            throw new NotFoundException(__('Blocklist item not found.'));
        }
        $this->controller->set('blockEntry', $blockEntry);
        if ($this->controller->getRequest()->is('post')) {
            if ($rest) {
                if ($this->controller->getResponse()->getType() === 'application/json') {
                    $data = $this->controller->getRequest()->input('json_decode', true);
                } else {
                    $data = $this->controller->getRequest()->getData();
                }
                if (isset($data['request'])) {
                    $data = $data['request'];
                }
                if (!isset($data[$this->defaultModel])) {
                    $data = [$this->defaultModel => $data];
                }
            } else {
                $data = $this->controller->getRequest()->getData();
            }
            $fields = $this->controller->{$this->defaultModel}->blocklistFields;
            foreach ($fields as $f) {
                if ($f == 'uuid') {
                    continue;
                }
                if (isset($data[$this->defaultModel][$f])) {
                    $blockEntry[$f] = $data[$this->defaultModel][$f];
                }
            }
            if ($this->controller->{$this->defaultModel}->save($blockEntry)) {
                if ($rest) {
                    return $this->RestResponse->viewData(
                        $this->controller->{$this->defaultModel}->get($blockEntry->id)

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

    public function delete($id, $rest = false)
    {
        if (Validation::uuid($id)) {
            $blockEntry = $this->controller->{$this->defaultModel}->find('all', [
                'conditions' => array(
                    $this->controller->{$this->defaultModel}->blocklistTarget . '_uuid' => $id
                )
            ])->first();
        } else {
            $blockEntry = $this->controller->{$this->defaultModel}->find('all', array('conditions' => array('id' => $id)))->first();
        }
        if (empty($blockEntry)) {
            throw new NotFoundException(__('Invalid blocklist entry'));
        }

        if ($this->controller->{$this->defaultModel}->delete($blockEntry)) {
            $message = __('Blocklist entry removed');
            if ($rest) {
                return $this->RestResponse->saveSuccessResponse($this->defaultModel, 'delete', $id, false, $message);
            }
            $this->controller->Flash->success($message);
        } else {
            $message = __('Could not remove the blocklist entry');
            if ($rest) {
                return $this->RestResponse->saveFailResponse($this->defaultModel, 'delete', $id, $message);
            }
            $this->controller->error($message);
        }
        $this->controller->redirect(array('action' => 'index'));
    }

    public $controller;

    public function initialize(array $config): void
    {
        $this->controller = $config['controller'];
        $this->defaultModel = $config['table'];
    }
}
