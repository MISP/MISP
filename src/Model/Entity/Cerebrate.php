<?php
declare(strict_types=1);

namespace App\Model\Entity;

use App\Lib\Tools\HttpTool;
use Cake\Database\Expression\QueryExpression;
use Cake\Database\Query;
use Cake\Http\Client\Exception\NetworkException;
use Cake\Http\Exception\BadRequestException;
use Cake\Http\Exception\ForbiddenException;
use Cake\ORM\TableRegistry;
use Cake\Utility\Hash;

/**
 * Cerebrate Entity
 *
 * @property int $id
 * @property string $name
 * @property string $url
 * @property string|resource $authkey
 * @property bool|null $open
 * @property int $org_id
 * @property bool|null $pull_orgs
 * @property bool|null $pull_sharing_groups
 * @property bool|null $self_signed
 * @property string|null $cert_file
 * @property string|null $client_cert_file
 * @property bool $internal
 * @property bool $skip_proxy
 * @property string|null $description
 */
class Cerebrate extends AppModel
{
    /**
     * Fields that can be mass assigned using newEntity() or patchEntity().
     *
     * Note that when '*' is set to true, this allows all unspecified fields to
     * be mass assigned. For security purposes, it is advised to set '*' to false
     * (or remove it), and explicitly make individual fields accessible as needed.
     *
     * @var array<string, bool>
     */
    protected $_accessible = [
        'name' => true,
        'url' => true,
        'authkey' => true,
        'open' => true,
        'org_id' => true,
        'pull_orgs' => true,
        'pull_sharing_groups' => true,
        'self_signed' => true,
        'cert_file' => true,
        'client_cert_file' => true,
        'internal' => true,
        'skip_proxy' => true,
        'description' => true,
    ];

    /**
     * queryInstance - Query a remote Cerebrate instance for a specific path
     *
     * @param  array $options path and more
     * @return array Json response in an array
     */
    public function queryInstance($options)
    {
        $url = $this->url . $options['path'];
        $url_params = [];
        $httpTool = new HttpTool([], $this->toArray());
        try {
            if (!empty($options['type']) && $options['type'] === 'post') {
                $response = $httpTool->post($url, json_encode($options['body']));
            } else {
                $response = $httpTool->get(
                    $url,
                    [],
                    ($options['params'] ?? [])
                );
            }
            if ($response->isOk()) {
                return json_decode($response->getBody()->__toString(), true);
            }
        } catch (NetworkException $e) {
            throw new BadRequestException(__('Something went wrong. Error returned: {0}', $e->getMessage()));
        }
        if ($response->getStatusCode() === 403 || $response->getStatusCode() === 401) {
            throw new ForbiddenException(__('Authentication failed.'));
        }
        throw new BadRequestException(__('Something went wrong with the request or the remote side is having issues.'));
    }

    /**
     * convertOrg
     *
     * @param  mixed $org_data organisation data
     * @return array
     */
    public function convertOrg($org_data)
    {
        $mapping = [
            'name' => [
                'field' => 'name',
                'required' => 1,
            ],
            'uuid' => [
                'field' => 'uuid',
                'required' => 1,
            ],
            'nationality' => [
                'field' => 'nationality',
            ],
            'sector' => [
                'field' => 'sector',
            ],
            'type' => [
                'field' => 'type',
            ],
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

    /**
     * saveRemoteOrgs -
     *
     * @param  array $orgs An array of organisations with name, uuid, sector, nationality, type
     * @return array {'add': int, 'edit': int, 'fails': int}
     */
    public function saveRemoteOrgs($orgs)
    {
        $outcome = [
            'add' => 0,
            'edit' => 0,
            'fails' => 0,
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

    /**
     * saveRemoteSgs
     *
     * @param  mixed $sgs SharingGroups
     * @param  mixed $user user
     * @return array ['add'=> 0, 'edit' => 0, 'fails' => 0]
     */
    public function saveRemoteSgs($sgs, $user)
    {
        $outcome = [
            'add' => 0,
            'edit' => 0,
            'fails' => 0,
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

    /**
     * captureOrg - save or update an Org locally that comes from a Remote Cerebrate server
     *
     * @param  array $org_data The Org array from the remote Cerebrate server
     * @param  bool $edit Returns if the org was edited or not
     * @param  bool $noChange Returns
     * @return string|array Error message or Organisation array
     */
    public function captureOrg($org_data, &$edit = false, &$noChange = false)
    {
        $org = $this->convertOrg($org_data);
        if ($org) {
            /** @var \App\Model\Table\OrganisationsTable $organisationTable */
            $organisationTable = TableRegistry::getTableLocator()->get('Organisations');
            $existingOrg = $organisationTable->find(
                'all',
                [
                    'recursive' => -1,
                    'conditions' => ['uuid' => $org['uuid']],
                ]
            )->first();
            if (!empty($existingOrg)) {
                $fieldsToSave = ['name', 'sector', 'nationality', 'type'];
                unset($org['uuid']);
                $dirty = false;
                foreach ($fieldsToSave as $fieldToSave) {
                    if (!empty($org[$fieldToSave])) {
                        if ($existingOrg->$fieldToSave !== $org[$fieldToSave]) {
                            if ($fieldToSave === 'name') {
                                if ($this->__compareNames($existingOrg->name, $org[$fieldToSave])) {
                                    continue;
                                }
                            }
                            $existingOrg->$fieldToSave = $org[$fieldToSave];
                            $dirty = true;
                        }
                    }
                }
                $orgToSave = $existingOrg;
                $edit = true;
            } else {
                $dirty = true;
                $fieldsToSave = ['name', 'uuid', 'sector', 'nationality', 'type'];
                $orgToSave = $organisationTable->newEntity([]);
                foreach ($fieldsToSave as $fieldToSave) {
                    if (!empty($org[$fieldToSave])) {
                        $orgToSave->$fieldToSave = $org[$fieldToSave];
                    }
                }
            }
            if ($dirty) {
                // verify if the name exists, if so generate a new name
                $nameCheck = $organisationTable->find(
                    'all',
                    [
                        'recursive' => -1,
                        'conditions' => ['name' => $orgToSave->name],
                        'fields' => ['id'],
                    ]
                )->first();
                if (!empty($nameCheck)) {
                    $orgToSave['name'] = $orgToSave['name'] . '_' . mt_rand(0, 9999);
                }
                // save the organisation
                $savedOrganisation = $organisationTable->save($orgToSave);
                if ($savedOrganisation) {
                    return $organisationTable->find(
                        'all',
                        [
                            'recursive' => -1,
                            'conditions' => ['id' => $savedOrganisation->id],
                        ]
                    )->first()->toArray();
                } else {
                    return __('The organisation could not be saved.');
                }
            } else {
                $noChange = true;

                return $existingOrg->toArray();
            }
        }

        return __('The retrieved data isn\'t a valid organisation.');
    }

    /**
     * checkRemoteOrgs
     *  Checks remote for the current status of each organisation
     *  Adds the exists_locally field with a boolean status
     *  If exists_loally is true, adds a list with the differences (keynames)
     *
     * @param  array $orgs orgs
     * @return array
     */
    public function checkRemoteOrgs($orgs)
    {
        $uuids = Hash::extract($orgs, '{n}.uuid');
        /** @var \App\Model\Table\OrganisationsTable $organisationTable */
        $organisationTable = TableRegistry::getTableLocator()->get('Organisations');
        $existingOrgs = $organisationTable->find('all')
        ->where(['uuid'])
        ->where(
            function (QueryExpression $exp, Query $q) use ($uuids) {
                return $exp->in('uuid', array_values($uuids));
            }
        );
        $rearranged = [];
        foreach ($existingOrgs as $existingOrg) {
            $rearranged[$existingOrg->uuid] = $existingOrg->toArray();
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

    /**
     * __compareNames
     *
     * @param  string $name1 orgname
     * @param  string $name2 orgname
     * @return bool
     */
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

    /**
     * __compareMembers
     *
     * @param  array $existingMembers members
     * @param  array $remoteMembers members
     * @return bool
     */
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

    /**
     * checkRemoteSharingGroups
     * Checks remote for the current status of each sharing groups
     * Adds the exists_locally field with a boolean status
     * If exists_loally is true, adds a list with the differences (keynames)
     *
     * @param  array $sgs SharingGroups
     * @return array
     */
    public function checkRemoteSharingGroups($sgs)
    {
        /** @var \App\Model\Table\SharingGroupsTable $sharingGroupTable */
        $sharingGroupTable = TableRegistry::getTableLocator()->get('SharingGroups');
        $uuids = Hash::extract($sgs, '{n}.uuid');
        $existingSgs = $sharingGroupTable->find('all')
        ->contain(['SharingGroupOrgs' => 'Organisations', 'Organisations'])
        ->where(['SharingGroups.uuid'])
        ->where(
            function (QueryExpression $exp, Query $q) use ($uuids) {
                return $exp->in('SharingGroups.uuid', array_values($uuids));
            }
        );
        $rearranged = [];
        foreach ($existingSgs as $existingSg) {
            $existingSg = $existingSg->toArray();
            $rearranged[$existingSg['uuid']] = $existingSg;
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

    /**
     * compareSgs
     *
     * @param  array $existingSg existing SharingGroup
     * @param  array $remoteSg remote Sharing Group
     * @return array
     */
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

    /**
     * convertSg
     *
     * @param  array $sg_data Sharing Group data
     * @return array
     */
    private function convertSg($sg_data)
    {
        $mapping = [
            'name' => [
                'field' => 'name',
                'required' => 1,
            ],
            'uuid' => [
                'field' => 'uuid',
                'required' => 1,
            ],
            'releasability' => [
                'field' => 'releasability',
            ],
            'description' => [
                'field' => 'description',
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
                foreach ($org as $ok => $ov) {
                    if ($ov === null) {
                        unset($sg['SharingGroupOrg'][$k][$ok]);
                    }
                }
            }
        }

        return $sg;
    }

    /**
     * captureSg
     *
     * @param  array $sg_data Sharing Group data
     * @param  \App\Model\Entity\User $user user
     * @param  bool $edit data was changed or not
     * @param  bool $noChange noChange
     * @return string|array
     */
    public function captureSg($sg_data, $user, &$edit = false, &$noChange = false)
    {
        /** @var \App\Model\Table\SharingGroupsTable $sharingGroupTable */
        $sharingGroupTable = TableRegistry::getTableLocator()->get('SharingGroups');
        $sg = $this->convertSg($sg_data);
        if ($sg) {
            $existingSg = $sharingGroupTable->findByUuid($sg_data['uuid'])->first();
            if (!empty($existingSg)) {
                $edit = true;
            }
            $captureResult = $sharingGroupTable->captureSG($sg, $user->toArray(), false);
            if (!empty($captureResult)) {
                $savedSg = $sharingGroupTable->findById($captureResult)
                ->contain(['SharingGroupOrgs' => 'Organisations', 'Organisations'])
                ->first();

                return $savedSg->toArray();
            }

            return __('The organisation could not be saved.');
        }

        return __('The retrieved data isn\'t a valid sharing group.');
    }
}
