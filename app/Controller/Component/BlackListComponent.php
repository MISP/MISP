<?php

/**
 * create, read, update and delete (CRUD)
 */

class BlackListComponent extends Component
{
    public $settings = array();
    public $defaultModel = '';


    public function index($rest = false, $filters = array())
    {
		if (!empty($filters)) {
			$this->controller->paginate['conditions'] = $filters;
		}
        if ($this->controller->response->type() === 'application/json' || $this->controller->response->type() == 'application/xml' || $rest) {
            $blackList = $this->controller->paginate();
            $blacklist= array();
            foreach ($blackList as $item) {
                $blacklist[] = $item[$this->controller->defaultModel];
            }
            $this->controller->set($this->controller->defaultModel, $blacklist);
            $this->controller->set('_serialize', $this->controller->defaultModel);
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
            if (is_array($data[$this->controller->defaultModel]['uuids'])) {
                $uuids = $data[$this->controller->defaultModel]['uuids'];
            } else {
                $uuids = explode(PHP_EOL, $data[$this->controller->defaultModel]['uuids']);
            }
            $successes = array();
            $fails = array();
            foreach ($uuids as $uuid) {
                $uuid = trim($uuid);
                if (strlen($uuid) == 36) {
                    $this->controller->{$this->controller->defaultModel}->create();
                    $object = array();
                    foreach ($this->controller->{$this->controller->defaultModel}->blacklistFields as $f) {
                        if (strpos($f, '_uuid')) {
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
            $message = sprintf(__('Done. Added %d new entries to the blacklist. %d entries could not be saved.'), count($successes), count($fails));
            if ($rest) {
                $this->set('result', array('successes' => $successes, 'fails' => $fails));
                $this->set('message', $message);
                $this->set('_serialize', array('message', 'result'));
            } else {
                $this->controller->Session->setFlash($message);
                $this->controller->redirect(array('action' => 'index'));
            }
        }
    }

    public function edit($rest = false, $id)
    {
        if (strlen($id) == 36) {
            $blockEntry = $this->controller->{$this->controller->defaultModel}->find('first', array('conditions' => array('uuid' => $id)));
        } else {
            $blockEntry = $this->controller->{$this->controller->defaultModel}->find('first', array('conditions' => array('id' => $id)));
        }
        if (empty($blockEntry)) {
            throw new NotFoundException('Blacklist item not found.');
        }
        $this->controller->set('blockEntry', $blockEntry);
        if ($this->controller->request->is('post')) {
            if ($rest) {
                if ($this->response->type() === 'application/json') {
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
            $fields = $this->controller->{$this->controller->defaultModel}->blacklistFields;
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
                    $this->controller->set('message', array('Blacklist item added.'));
                    $this->controller->set('_serialize', array('message'));
                } else {
                    $this->controller->Session->setFlash(__('Blacklist item added.'));
                    $this->controller->redirect(array('action' => 'index'));
                }
            } else {
                if ($rest) {
                    throw new MethodNotAllowedException('Could not save the blacklist item.');
                } else {
                    $this->controller->Session->setFlash('Could not save the blacklist item');
                    $this->controller->redirect(array('action' => 'index'));
                }
            }
        }
    }

    public function delete($rest = false, $id)
    {
        if (strlen($id) == 36) {
            $blockEntry = $this->controller->{$this->controller->defaultModel}->find('first', array(
                'fields' => array('id'),
                'conditions' => array('event_uuid' => $id),
            ));
            $id = $blockEntry[$this->controller->defaultModel]['id'];
        }
        if (!$this->controller->request->is('post') && !$rest) {
            throw new MethodNotAllowedException();
        }

        $this->controller->{$this->controller->defaultModel}->id = $id;
        if (!$this->controller->{$this->controller->defaultModel}->exists()) {
            throw new NotFoundException(__('Invalid blacklist entry'));
        }

        if ($this->controller->{$this->controller->defaultModel}->delete()) {
            $this->controller->Session->setFlash(__('Blacklist entry removed'));
        } else {
            $this->controller->Session->setFlash(__('Could not remove the blacklist entry'));
        }
        $this->controller->redirect(array('action' => 'index'));
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
