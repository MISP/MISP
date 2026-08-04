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
        // DPT-7: Event is the only supported/consumed parent type (the model
        // belongsTo only Event). Any other type was previously saved with NO
        // ownership check - parent_type/parent_id are forced from the route,
        // so a perm_add user could attach a key to an arbitrary parent of any
        // other type. Reject unsupported types so the ownership check below
        // always applies.
        if ($type !== 'Event') {
            throw new MethodNotAllowedException(__('Unsupported parent type.'));
        }
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
        if ($this->theme === 'Overmind') {
            $this->layout = false;
            $this->render('add');
        }
    }

    public function delete($id)
    {
        $user = $this->Auth->user();
        if (
            $this->theme === 'Overmind' &&
            !$this->IndexFilter->isRest() &&
            !$this->request->is('post') &&
            !$this->request->is('delete')
        ) {
            // Overmind: render the BS5 confirmation fragment for the delete
            // modal. The actual deletion (POST) still flows through
            // CRUD->delete below, so the ownership gate in beforeDelete is
            // unchanged - this branch only themes the confirm dialog.
            $this->layout = false;
            $this->set('id', $id);
            $this->render('ajax/cryptographicKeyDeleteConfirmationForm');
            return;
        }
        $this->CRUD->delete($id, [
            'beforeDelete' => function ($data) use($user) {
                $parent_type = $data['CryptographicKey']['parent_type'];
                // DPT-7: Event is the only supported parent type with an
                // ownership model. For any other type (inert/unconsumed rows)
                // fall back to site-admin only, rather than allowing an
                // unauthorised delete with no check at all.
                if ($parent_type !== 'Event') {
                    return $user['Role']['perm_site_admin'] ? $data : false;
                }
                $tempModel = ClassRegistry::init($parent_type);
                $existingData = $tempModel->find('first', [
                    'conditions' => [
                        $parent_type . '.id' => $data['CryptographicKey']['parent_id']
                    ],
                    'recursive' => -1
                ]);
                if (!$user['Role']['perm_site_admin'] && $existingData['Event']['orgc_id'] !== $user['org_id']) {
                    return false;
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
        $this->layout = false;
        if ($this->theme === 'Overmind') {
            $this->render('view');
        } else {
            $this->render('/genericTemplates/display');
        }
    }

    public function serverSign()
    {
        if ($this->request->is('post')) {
            $data = file_get_contents('php://input');
            $signature = $this->CryptographicKey->signWithInstanceKey($data);
            if (!$signature) {
                throw new Exception('Could not sign data.');
            }
            return $this->RestResponse->viewData(base64_encode($signature), false, false, true);
        }
        
    }
}
