<?php

App::uses('AppModel', 'Model');

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

    public function queryInstance($options) {
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
                    $orgToSave['name'] = $orgToSave['name'] . '_' . rand(0, 9999);
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
}

?>
