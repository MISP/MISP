<?php
App::uses('AppModel', 'Model');
App::uses('EncryptedValue', 'Tools');

class SharingGroupBlueprint extends AppModel
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
        'SharingGroup',
        'Organisation' => array(
            'className' => 'Organisation',
            'foreignKey' => 'org_id'
        )
    );

    public $validFilters = [
        'org' => [
            'org_id' => 'id',
            'org_uuid' => 'uuid',
            'org_name' => 'name',
            'org_nationality' => 'nationality',
            'org_sector' => 'sector',
            'org_type' => 'type'
        ],
        'sharing_group' => [
            'sharing_group_id' => 'id',
            'sharing_group_uuid' => 'uuid'
        ]
    ];

    public $operands = [
        'OR',
        'AND',
        'NOT'
    ];

    public function beforeSave($options = array())
    {
        $this->data['SharingGroupBlueprint']['timestamp'] = time();
        $this->data['SharingGroupBlueprint']['rules'] = json_decode($this->data['SharingGroupBlueprint']['rules']);
        $this->data['SharingGroupBlueprint']['rules'] = json_encode($this->data['SharingGroupBlueprint']['rules']);
        return true;
    }

    public function afterFind($results, $primary = false)
    {
        foreach ($results as &$v) {
            $v['SharingGroupBlueprint']['rules'] = json_encode(json_decode($v['SharingGroupBlueprint']['rules']), JSON_PRETTY_PRINT);
        }
        return $results;
    }

    public function execute($sharingGroupBlueprints)
    {
        $stats = [
            'changed' => 0,
            'created' => 0,
            'failed' => 0
        ];
        $updated = $failed = 0;
        foreach ($sharingGroupBlueprints as $sharingGroupBlueprint) {
            // we create a fake user to restrict the visible sharing groups to the creator of the SharingGroupBlueprint, in case an admin wants to update it
            $fake_user = [
                'Role' => [
                    'perm_site_admin' => false
                ],
                'org_id' => $sharingGroupBlueprint['SharingGroupBlueprint']['org_id'],
                'id' => 1
            ];
            $result = $this->updateSharingGroup($sharingGroupBlueprint, $fake_user);
            foreach (array_keys($stats) as $field) {
                $stats[$field] += $result[$field];
            }

        }
        return $stats;
    }

    public function updateSharingGroup($sharingGroupBlueprint, $user)
    {
        $this->Organisation = ClassRegistry::init('Organisation');
        $data = $this->evaluateSharingGroupBlueprint($sharingGroupBlueprint, $user);
        $failed = 0;
        if (empty($sharingGroupBlueprint['SharingGroupBlueprint']['sharing_group_id'])) {
            $created = true;
            $this->SharingGroup->create();
            $org_uuid = $this->SharingGroup->Organisation->find('first', [
                'recursive' => -1,
                'conditions' => ['Organisation.id' => $sharingGroupBlueprint['SharingGroupBlueprint']['org_id']],
                'fields' => ['Organisation.uuid']
            ]);
            if (empty($org_uuid)) {
                throw new MethodNotAllowedException(__('Invalid owner organisation.'));
            }
            $org_uuid = $org_uuid['Organisation']['uuid'];
            $sg = [
                'name' => $sharingGroupBlueprint['SharingGroupBlueprint']['name'],
                'description' => __('Generated based on Sharing Group Blueprint rules'),
                'org_id' => $user['org_id'],
                'organisation_uuid' => $org_uuid,
                'releasability' => __('Generated based on Sharing Group Blueprint rules'),
                'local' => 1,
                'roaming' => 1,
                'active' => 1
            ];
            if ($this->SharingGroup->save($sg)) {
                $id = $this->SharingGroup->id;
                $sharingGroupBlueprint['SharingGroupBlueprint']['sharing_group_id'] = $id;
                $existingOrgs = [];
                $this->save($sharingGroupBlueprint);
            } else {
                $failed++;
            }

        } else {
            $created = false;
            $sg = $this->SharingGroup->find('first', [
                'recursive' => -1,
                'contain' => ['SharingGroupOrg'],
                'conditions' => ['SharingGroup.id' => $sharingGroupBlueprint['SharingGroupBlueprint']['sharing_group_id']]
            ]);
            $existingOrgs = [];
            foreach ($sg['SharingGroupOrg'] as $sgo) {
                $existingOrgs[] = $sgo['org_id'];
            }
            $existingOrgs = array_unique($existingOrgs);
            $id = $sg['SharingGroup']['id'];
        }
        return [
            'id' => $id,
            'changed' => $this->__handleSharingGroupOrgs($existingOrgs, $data['orgs'], $id) || $created,
            'created' => $created,
            'failed' => $failed
        ];
    }

    private function __handleSharingGroupOrgs($existingOrgs, $newOrgs, $id)
    {
        $added = 0;
        $removed = 0;
        $this->Log = ClassRegistry::init('Log');
        foreach ($existingOrgs as $existingOrg) {
            if (!in_array($existingOrg, $newOrgs)) {
                $this->SharingGroup->SharingGroupOrg->deleteAll([
                    'sharing_group_id' => $id,
                    'org_id' => $existingOrg
                ], false);
                $removed++;
            }
        }
        foreach ($newOrgs as $newOrg) {
            if (!in_array($newOrg, $existingOrgs)) {
                $sgo = [
                    'sharing_group_id' => $id,
                    'org_id' => $newOrg,
                    'extend' => false
                ];
                $this->SharingGroup->SharingGroupOrg->create();
                $this->SharingGroup->SharingGroupOrg->save($sgo);
                $added++;
            }
        }
        if ($added || $removed) {
            $this->Log->create();
            $entry = array(
                'org' => 'SYSTEM',
                'model' => 'SharingGroup',
                'model_id' => $id,
                'email' => 'SYSTEM',
                'action' => 'execute_blueprint',
                'user_id' => 0,
                'title' => 'Updated the sharing group.',
                'change' => __('Updated sharing group. Added %s and removed %s organisations', $added, $removed)
            );
            $this->Log->save($entry);
            return true;
        }
        return false;
    }

    // Walking on water and developing software from a specification are easy if both are frozen - Edward V Berard
    public function evaluateSharingGroupBlueprint($sharingGroupBlueprint, $user)
    {
        $data = [];
        $rules = json_decode($sharingGroupBlueprint['SharingGroupBlueprint']['rules'], true);
        $data = $this->__recursiveEvaluate($user, $rules, 'OR');
        return $data;
    }

    private function __recursiveEvaluate($user, $rules, $operand)
    {
        if (!empty($rules)) {
            $data = [];
            foreach ($rules as $key => $value) {
                if (in_array($key, $this->operands)) {
                    if ($operand === 'NOT') {
                        throw new MethodNotAllwedException(__('Boolean branches within a NOT branch are not supported.'));
                    }
                    $temp = $this->__recursiveEvaluate($user, $rules[$key], $key);
                } else {
                    $negation = $operand === 'NOT';
                    $temp = $this->__evaluateLeaf($user, $key, $value, $negation);
                }
                if ($operand === 'OR') {
                    if (!isset($data['orgs'])) {
                        $data['orgs'] = [];
                    }
                    $data['orgs'] = array_merge(
                        $data['orgs'],
                        isset($temp['orgs']) ? $temp['orgs'] : []
                    );
                } else if ($operand === 'AND' || $operand === 'NOT') {
                    if (!isset($data['orgs'])) {
                        $data['orgs'] = $temp['orgs'];
                    } else {
                        $data['orgs'] = array_intersect($data['orgs'], $temp['orgs']);
                    }
                }
            }
        }
        return $data;
    }

    private function __evaluateLeaf($user, $key, $value, $negation = false)
    {
        if (substr($key, 0, strlen('org')) === 'org') {
            return $this->__evaluateOrgLeaf(
                $user,
                substr($key, (strlen('org_'))),
                $value,
                $negation
            );
        } else if (substr($key, 0, strlen('sharing_group')) === 'sharing_group') {
            return $this->__evaluateSGLeaf(
                $user,
                substr($key, (strlen('sharing_group_'))),
                $value,
                $negation
            );
        }
        return [];
    }

    private function __evaluateOrgLeaf($user, $key, $value, $negation)
    {
        if (in_array($key, $this->validFilters['org'])) {
            $conditions = [$key => $value];
            if ($negation) {
                $conditions = ['NOT' => $conditions];
            }
            $orgs = $this->SharingGroup->Organisation->find('list', [
                'fields' => ['id', 'id'],
                'recursive' => -1,
                'conditions' => $conditions
            ]);
            $orgs = array_values($orgs);
            if (empty($orgs)) {
                $orgs = [-1];
            }
            return [
                'orgs' => $orgs
            ];
        }
        return [];
    }

    private function __evaluateSGLeaf($user, $key, $value, $negation)
    {
        $orgs = [];
        if (in_array($key, $this->validFilters['sharing_group'])) {
            $conditions = [$key => $value];
            if ($negation) {
                $conditions = ['NOT' => $conditions];
            }
            $sgs = $this->SharingGroup->find('all', [
                'fields' => ['id', 'uuid', 'name', 'org_id'],
                'contain' => ['SharingGroupOrg.org_id'],
                'recursive' => -1,
                'conditions' => $conditions
            ]);
            foreach ($sgs as $sg) {
                if ($this->SharingGroup->checkIfAuthorised($user, $sg['SharingGroup']['id'])) {
                    $orgs[$sg['SharingGroup']['org_id']] = true;
                    foreach ($sg['SharingGroupOrg'] as $sgo) {
                        $orgs[$sgo['org_id']] = true;
                    }
                }
            }
            $orgs = array_keys($orgs);
            if (empty($orgs)) {
                $orgs = [-1];
            }
            return [
                'orgs' => $orgs
            ];
        }
        return [];
    }
}
