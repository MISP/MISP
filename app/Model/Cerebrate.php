<?php
App::uses('AppModel', 'Model');
App::uses('EncryptedValue', 'Tools');

class Cerebrate extends AppModel
{
    public $actsAs = [
        'AuditLog',
        'SysLogLogable.SysLogLogable' => [
            'roleModel' => 'Role',
            'roleKey' => 'role_id',
            'change' => 'full'
        ],
        'Containable'
    ];

    public $belongsTo = array(
        'Organisation' => array(
            'className' => 'Organisation',
            'foreignKey' => 'org_id'
        )
    );

    public function beforeSave($options = array())
    {
        $cerebrate = &$this->data['Server'];
        // Encrypt authkey if plain key provided and encryption is enabled
        if (!empty($cerebrate['authkey']) && strlen($cerebrate['authkey']) === 40) {
            $cerebrate['authkey'] = EncryptedValue::encryptIfEnabled($cerebrate['authkey']);
        }
        return true;
    }

    public function queryInstance($options)
    {
        $url = $options['cerebrate']['Cerebrate']['url'] . $options['path'];
        $url_params = [];

        $HttpSocket = $this->setupHttpSocket($options['cerebrate']);
        $request = $this->setupSyncRequest($options['cerebrate'], 'Cerebrate');
        try {
            if (!empty($options['type']) && $options['type'] === 'post') {
                $response = $HttpSocket->post($url, json_encode($options['body']), $request);
            } else {
                $response = $HttpSocket->get(
                    $url,
                    (isset($options['params']) ? $options['params'] : []),
                    $request
                );
            }
            if ($response->isOk()) {
                return json_decode($response->body, true);
            }
        } catch (SocketException $e) {
            throw new BadRequestException(__('Something went wrong. Error returned: %s', $e->getMessage));
        }
        if ($response->code === 403 || $response->code === 401) {
            throw new ForbiddenException(__('Authentication failed.'));
        }
        throw new BadRequestException(__('Something went wrong with the request or the remote side is having issues.'));
    }

    public function convertOrg($org_data) {
        $mapping = [
            'name' => [
                'field' => 'name',
                'required' => 1
            ],
            'uuid' => [
                'field' => 'uuid',
                'required' => 1
            ],
            'nationality' => [
                'field' => 'nationality'
            ],
            'sector' => [
                'field' => 'sector'
            ],
            'type' => [
                'field' => 'type'
            ]
        ];
        $org = [];
        foreach ($mapping as $cerebrate_field => $field_data) {
            if (empty($org_data[$cerebrate_field])) {
                if (!empty($field_data['required'])) {
                    return false;
                } else {
                    continue;
                }
            }
            $org[$field_data['field']] = $org_data[$cerebrate_field];
        }
        return $org;
    }

    public function saveRemoteOrgs($orgs)
    {
        $outcome = [
            'add' => 0,
            'edit' => 0,
            'fails' => 0
        ];
        foreach ($orgs as $org) {
            $isEdit = false;
            $noChange = false;
            $result = $this->captureOrg($org, $isEdit, $noChange);
            if (!is_array($result)) {
                $outcome['fails'] += 1;
            } else {
                if ($isEdit) {
                    if (!$noChange) {
                        $outcome['edit'] += 1;
                    }
                } else {
                    $outcome['add'] += 1;
                }
            }
        }
        return $outcome;
    }

    public function saveRemoteSgs($sgs, $user)
    {
        $outcome = [
            'add' => 0,
            'edit' => 0,
            'fails' => 0
        ];
        foreach ($sgs as $sg) {
            $isEdit = false;
            $noChange = false;
            $result = $this->captureSg($sg, $user, $isEdit, $noChange);
            if (!is_array($result)) {
                $outcome['fails'] += 1;
            } else {
                if ($isEdit) {
                    if (!$noChange) {
                        $outcome['edit'] += 1;
                    }
                } else {
                    $outcome['add'] += 1;
                }
            }
        }
        return $outcome;
    }

    public function captureOrg($org_data, &$edit=false, &$noChange=false) {
        $org = $this->convertOrg($org_data);
        if ($org) {
            $existingOrg = $this->Organisation->find('first', [
                'recursive' => -1,
                'conditions' => ['Organisation.uuid' => $org['uuid']]
            ]);
            if (!empty($existingOrg)) {
                $fieldsToSave = ['name', 'sector', 'nationality', 'type'];
                unset($org['uuid']);
                $dirty = false;
                foreach ($fieldsToSave as $fieldToSave) {
                    if (!empty($org[$fieldToSave])) {
                        if ($existingOrg['Organisation'][$fieldToSave] !== $org[$fieldToSave]) {
                            if ($fieldToSave === 'name') {
                                if ($this->__compareNames($existingOrg['Organisation']['name'], $org[$fieldToSave])) {
                                    continue;
                                }
                            }
                            $existingOrg['Organisation'][$fieldToSave] = $org[$fieldToSave];
                            $dirty = true;
                        }
                    }
                }
                $orgToSave = $existingOrg['Organisation'];
                $edit = true;
            } else {
                $dirty = true;
                $fieldsToSave = ['name', 'uuid', 'sector', 'nationality', 'type'];
                $orgToSave = [];
                foreach ($fieldsToSave as $fieldToSave) {
                    if (!empty($org[$fieldToSave])) {
                        $orgToSave[$fieldToSave] = $org[$fieldToSave];
                    }
                }
                $this->Organisation->create();
            }
            if ($dirty) {
                $nameCheck = $this->Organisation->find('first', [
                    'recursive' => -1,
                    'conditions' => ['Organisation.name' => $orgToSave['name']],
                    'fields' => ['Organisation.id']
                ]);
                if (!empty($nameCheck)) {
                    $orgToSave['name'] = $orgToSave['name'] . '_' . mt_rand(0, 9999);
                }
                $result = $this->Organisation->save($orgToSave);
                if ($result) {
                    return $this->Organisation->find('first', [
                        'recursive' => -1,
                        'conditions' => ['Organisation.id' => $this->Organisation->id]
                    ]);
                } else {
                    return __('The organisation could not be saved.');
                }
            } else {
                $noChange = true;
                return $existingOrg['Organisation'];
            }
        }
        return __('The retrieved data isn\'t a valid organisation.');
    }

    /*
     *  Checks remote for the current status of each organisation
     *  Adds the exists_locally field with a boolean status
     *  If exists_loally is true, adds a list with the differences (keynames)
     */
    public function checkRemoteOrgs($orgs)
    {
        $uuids = Hash::extract($orgs, '{n}.uuid');
        $existingOrgs = $this->Organisation->find('all', [
            'recursive' => -1,
            'conditions' => [
                'Organisation.uuid' => $uuids
            ]
        ]);
        $rearranged = [];
        foreach ($existingOrgs as $existingOrg) {
            $rearranged[$existingOrg['Organisation']['uuid']] = $existingOrg['Organisation'];
        }
        unset($existingOrgs);
        $fieldsToCheck = ['name', 'sector', 'type', 'nationality'];
        foreach ($orgs as $k => $org) {
            $orgs[$k]['exists_locally'] = false;
            if (isset($rearranged[$org['uuid']])) {
                $orgs[$k]['exists_locally'] = true;
                $orgs[$k]['differences'] = [];
                foreach ($fieldsToCheck as $fieldToCheck) {
                    if (
                        !(empty($orgs[$k][$fieldToCheck]) && empty($rearranged[$org['uuid']][$fieldToCheck])) &&
                        $orgs[$k][$fieldToCheck] !== $rearranged[$org['uuid']][$fieldToCheck]
                    ) {
                        if ($fieldToCheck === 'name') {
                            if ($this->__compareNames($rearranged[$org['uuid']][$fieldToCheck], $orgs[$k][$fieldToCheck])) {
                                continue;
                            }
                        }
                        $orgs[$k]['differences'][] = $fieldToCheck;
                    }
                }
            }
        }
        return $orgs;
    }

    private function __compareNames($name1, $name2)
    {
        if (preg_match('/\_[0-9]{4}$/i', $name1)) {
            if (substr($name1, 0, -5) === $name2) {
                return true;
            } else {
                return false;
            }
        }
        return false;
    }

    private function __compareMembers($existingMembers, $remoteMembers)
    {
        $memberFound = [];
        $memberNotFound = [];
        foreach ($remoteMembers as $remoteMember) {
            $found = false;
            foreach ($existingMembers as $existingMember) {
                if ($existingMember['uuid'] == $remoteMember['uuid']) {
                    $found = true;
                    $memberFound[] = $remoteMember['uuid'];
                    break;
                }
            }
            if (!$found) {
                $memberNotFound[] = $remoteMember['uuid'];
            }
        }
        return empty($memberNotFound);
    }

    /*
     *  Checks remote for the current status of each sharing groups
     *  Adds the exists_locally field with a boolean status
     *  If exists_loally is true, adds a list with the differences (keynames)
     */
    public function checkRemoteSharingGroups($sgs)
    {
        $this->SharingGroup = ClassRegistry::init('SharingGroup');
        $uuids = Hash::extract($sgs, '{n}.uuid');
        $existingSgs = $this->SharingGroup->find('all', [
            'recursive' => -1,
            'contain' => [
                'SharingGroupOrg' => ['Organisation'],
                'Organisation',
            ],
            'conditions' => [
                'SharingGroup.uuid' => $uuids
            ],
        ]);
        $rearranged = [];
        foreach ($existingSgs as $existingSg) {
            $existingSg['SharingGroup']['SharingGroupOrg'] = $existingSg['SharingGroupOrg'];
            $existingSg['SharingGroup']['Organisation'] = $existingSg['Organisation'];
            $rearranged[$existingSg['SharingGroup']['uuid']] = $existingSg['SharingGroup'];
        }
        unset($existingSgs);
        $fieldsToCheck = ['name', 'releasability', 'description'];
        foreach ($sgs as $k => $sg) {
            $sgs[$k]['exists_locally'] = false;
            if (isset($rearranged[$sg['uuid']])) {
                $sgs[$k]['exists_locally'] = true;
                $sgs[$k]['differences'] = $this->compareSgs($rearranged[$sg['uuid']], $sgs[$k]);
            }
        }
        return $sgs;
    }

    private function compareSgs($existingSg, $remoteSg)
    {
        $differences = [];
        $fieldsToCheck = ['name', 'releasability', 'description'];

        foreach ($fieldsToCheck as $fieldToCheck) {
            if (
                !(empty($remoteSg[$fieldToCheck]) && empty($existingSg[$fieldToCheck])) &&
                $remoteSg[$fieldToCheck] !== $existingSg[$fieldToCheck]
            ) {
                if ($fieldToCheck === 'name') {
                    if ($this->__compareNames($existingSg[$fieldToCheck], $remoteSg[$fieldToCheck])) {
                        continue;
                    }
                }
                $differences[] = $fieldToCheck;
            }
        }
        if (!$this->__compareMembers(Hash::extract($existingSg['SharingGroupOrg'], '{n}.Organisation'), $remoteSg['sharing_group_orgs'])) {
            $differences[] = 'members';
        }
        return $differences;
    }

    private function convertSg($sg_data)
    {
        $mapping = [
            'name' => [
                'field' => 'name',
                'required' => 1
            ],
            'uuid' => [
                'field' => 'uuid',
                'required' => 1
            ],
            'releasability' => [
                'field' => 'releasability'
            ],
            'description' => [
                'field' => 'description'
            ],
        ];
        $sg = [];
        foreach ($mapping as $cerebrate_field => $field_data) {
            if (empty($sg_data[$cerebrate_field])) {
                if (!empty($field_data['required'])) {
                    return false;
                } else {
                    continue;
                }
            }
            $sg[$field_data['field']] = $sg_data[$cerebrate_field];
        }
        $sg['SharingGroupOrg'] = [];
        if (!empty($sg_data['sharing_group_orgs'])) {
            $sg['SharingGroupOrg'] = $sg_data['sharing_group_orgs'];
            foreach ($sg['SharingGroupOrg'] as $k => $org) {
                if (isset($org['_joinData'])) {
                    unset($sg['SharingGroupOrg'][$k]['_joinData']);
                }
                if (!isset($org['extend'])) {
                    $sg['SharingGroupOrg'][$k]['extend'] = false;
                }
            }
        }
        return $sg;
    }

    public function captureSg($sg_data, $user, &$edit=false, &$noChange=false) {
        $this->SharingGroup = ClassRegistry::init('SharingGroup');
        $sg = $this->convertSg($sg_data);
        if ($sg) {
            $existingSg = $this->SharingGroup->find('first', [
                'recursive' => -1,
                'contain' => [
                    'SharingGroupOrg' => ['Organisation'],
                    'Organisation',
                ],
                'conditions' => [
                    'SharingGroup.uuid' => $sg_data['uuid']
                ],
            ]);
            if (!empty($existingSg)) {
                $edit = true;
            }
            $captureResult = $this->SharingGroup->captureSG($sg, $user, false);
            if (!empty($captureResult)) {
                $savedSg = $this->SharingGroup->find('first', [
                    'recursive' => -1,
                    'contain' => [
                        'SharingGroupOrg' => ['Organisation'],
                        'Organisation',
                    ],
                    'conditions' => [
                        'SharingGroup.id' => $captureResult
                    ],
                ]);
                return $savedSg;
            }
            return __('The organisation could not be saved.');
        }
        return __('The retrieved data isn\'t a valid sharing group.');
    }

    /**
     * @param string|null $old Old (or current) encryption key.
     * @param string|null $new New encryption key. If empty, encrypted values will be decrypted.
     * @throws Exception
     */
    public function reencryptAuthKeys($old, $new)
    {
        $cerebrates = $this->find('list', [
            'fields' => ['Cerebrate.id', 'Cerebrate.authkey'],
        ]);
        $toSave = [];
        foreach ($cerebrates as $id => $authkey) {
            if (EncryptedValue::isEncrypted($authkey)) {
                try {
                    $authkey = BetterSecurity::decrypt(substr($authkey, 2), $old);
                } catch (Exception $e) {
                    throw new Exception("Could not decrypt auth key for Cerebrate #$id", 0, $e);
                }
            }
            if (!empty($new)) {
                $authkey = EncryptedValue::ENCRYPTED_MAGIC . BetterSecurity::encrypt($authkey, $new);
            }
            $toSave[] = ['Cerebrate' => [
                'id' => $id,
                'authkey' => $authkey,
            ]];
        }
        if (empty($toSave)) {
            return true;
        }
        return $this->saveMany($toSave, ['validate' => false, 'fields' => ['authkey']]);
    }
}
