<?php
App::uses('AppController', 'Controller');

/**
 * @property CryptographicKey $CryptographicKey
 */
class CryptographicKeysController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public $paginate = array(
        'limit' => 60,
        'maxLimit' => 9999
    );

    public function add($type, $parent_id)
    {
        if (empty($type) || empty($parent_id)) {
            throw new MethodNotAllowedException(__('No type and/or parent_id supplied.'));
        }
        if ($type === 'Event') {
            $existingEvent = $this->CryptographicKey->Event->fetchSimpleEvent(
                $this->Auth->user(),
                $parent_id,
                [
                    'conditions' => [
                        'Event.orgc_id' => $this->Auth->user('org_id')
                    ]
                ]
            );
            if (empty($existingEvent)) {
                throw new MethodNotAllowedException(__('Invalid Event.'));
            }
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
        $instanceKey = file_exists(APP . 'webroot/gpg.asc') ? FileAccessTool::readFromFile(APP . 'webroot/gpg.asc') : '';
        $this->set('instanceKey', $instanceKey);
        $this->set('menuData', array('menuList' => 'cryptographic_keys', 'menuItem' => 'add_cryptographic_key'));
    }

    public function delete($id)
    {
        $user = $this->Auth->user();
        $this->CRUD->delete($id, [
            'beforeDelete' => function ($data) use($user) {
                $parent_type = $data['CryptographicKey']['parent_type'];
                $tempModel = ClassRegistry::init($parent_type);
                $existingData = $tempModel->find('first', [
                    'conditions' => [
                        $parent_type . '.id' => $data['CryptographicKey']['parent_id']
                    ],
                    'recursive' => -1
                ]);
                if ($parent_type === 'Event') {
                    if (!$user['Role']['perm_site_admin'] && $existingData['Event']['orgc_id'] !== $user['org_id']) {
                        return false;
                    }
                }
                return $data;
           }
        ]);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }

    public function view($id)
    {
        $key = $this->CryptographicKey->find('first', [
            'recursive' => -1,
            'fields' => ['id', 'type', 'key_data', 'fingerprint'],
            'conditions' => ['CryptographicKey.id' => $id]
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
