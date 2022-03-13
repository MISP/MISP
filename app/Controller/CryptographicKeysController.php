<?php
App::uses('AppController', 'Controller');

class CryptographicKeysController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public function beforeFilter()
    {
        parent::beforeFilter();
    }

    public $paginate = array(
            'limit' => 60,
            'maxLimit' => 9999
    );

    public function index($type, $parent_id)
    {
        if (empty($type) || empty($parent_id)) {
            throw new MethodNotAllowedException(__('No type and/or parent_id supplied.'));
        }
        $params = [
            'filters' => ['name', 'url', 'uuid'],
            'quickFilters' => ['name'],
            'conditions' => [
                'CryptographicKey.type' => $type,
                'CryptographicKey.parent_id' => $id
            ]
        ];
        $this->CRUD->index($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('menuData', array('menuList' => 'cryptographic_keys', 'menuItem' => 'list_cryptographic_keys'));
    }

    public function add($type, $parent_id)
    {
        if (empty($type) || empty($parent_id)) {
            throw new MethodNotAllowedException(__('No type and/or parent_id supplied.'));
        }
        $params = [
            'beforeSave' => function ($data) use($type, $parent_id) {
                $data['CryptographicKey']['parent_type'] = $type;
                $data['CryptographicKey']['parent_id'] = $parent_id;
                return $data;
            },
            'redirect' => [
                'controller' => Inflector::tableize($type),
                'action' => 'view',
                $parent_id
            ]
        ];
        $this->CRUD->add($params);
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }
        $instanceKey = FileAccessTool::readFromFile(APP . 'webroot/gpg.asc');
        $this->set('instanceKey', $instanceKey);
        $this->set('menuData', array('menuList' => 'cryptographic_keys', 'menuItem' => 'add_cryptographic_key'));
    }

    public function delete($id)
    {
        $this->CRUD->delete($id);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }

    public function view($id)
    {
        $key = $this->CryptographicKey->find('first', [
            'recursive' => -1,
            'fields' => ['id', 'type', 'key_data', 'fingerprint']
        ]);
        $this->set('id', $id);
        $this->set('title', __('Viewing %s key #%s', h($key['CryptographicKey']['type']), h($key['CryptographicKey']['id'])));
        $this->set(
            'html',
            sprintf(
                '<span class="quickSelect">%s</span>',
                nl2br(h($key['CryptographicKey']['key_data']))
            )
        );
        $this->layout = 'ajax';
        $this->render('/genericTemplates/display');
    }
}
