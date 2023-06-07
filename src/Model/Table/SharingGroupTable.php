<?php

namespace App\Model\Table;

use App\Model\Entity\SharingGroup;
use App\Model\Table\AppTable;
use ArrayObject;
use Cake\Core\Configure;
use Cake\Datasource\EntityInterface;
use Cake\Event\EventInterface;
use Cake\Http\Exception\MethodNotAllowedException;
use Cake\ORM\Locator\LocatorAwareTrait;
use Cake\ORM\RulesChecker;
use Cake\Utility\Text;
use Cake\Validation\Validation;
use Cake\Validation\Validator;
use InvalidArgumentException;
use App\Model\Entity\Log;

class SharingGroupTable extends AppTable
{
    use LocatorAwareTrait;

    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('AuditLog');

        $this->belongsTo(
            'Organisation'
        );

        // $this->hasMany(
        //     'SharingGroupOrg',
        //     [
        //         'dependent' => true,
        //     ],
        // );
        // $this->hasMany(
        //     'SharingGroupServer',
        //     [
        //         'dependent' => true,
        //     ],
        // );
        // $this->hasMany('Event');
        // $this->hasMany('Attribute');
        // $this->hasMany('Thread');
    }

    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->requirePresence(['name'], 'create')
            ->add(
                'uuid',
                'uuid',
                [
                    'rule' => 'uuid',
                    'message' => 'Please provide a valid RFC 4122 UUID'
                ]
            );

        return $validator;
    }

    public function buildRules(RulesChecker $rules): RulesChecker
    {
        $rules->add($rules->isUnique(['name']));
        $rules->add($rules->isUnique(['uuid']));
        return $rules;
    }

    private $__sgAuthorisationCache = [
        'save' => [],
        'access' => []
    ];

    private $authorizedIds = [];

    public function beforeMarshal(EventInterface $event, ArrayObject $data, ArrayObject $options)
    {
        if (empty($data['uuid'])) {
            $data['uuid'] = Text::uuid();
        } else {
            $data['uuid'] = strtolower($data['uuid']);
        }
        $date = date('Y-m-d H:i:s');
        if (empty($data['created'])) {
            $data['created'] = $date;
        }
        if (!isset($data['active'])) {
            $data['active'] = 0;
        }
        $data['modified'] = $date;
        if (!isset($data['id']) && $this->hasAny(['name' => $data['name']])) {
            $data['name'] = $data['name'] . '_' . mt_rand(0, 9999);
        }
        return true;
    }

    public function beforeDelete(EventInterface $event, EntityInterface $entity, ArrayObject $options)
    {
        if ($this->Event->hasAny(['sharing_group_id' => $entity->id])) {
            return false;
        }
        if ($this->Thread->hasAny(['sharing_group_id' => $entity->id])) {
            return false;
        }
        if ($this->Attribute->hasAny(['sharing_group_id' => $entity->id])) {
            return false;
        }
        if ($this->Attribute->Object->hasAny(['sharing_group_id' => $entity->id])) {
            return false;
        }
        if ($this->Event->EventReport->hasAny(['sharing_group_id' => $entity->id])) {
            return false;
        }
        return true;
    }

    /**
     * Returns a list of all sharing groups that the user is allowed to see.
     * Scope can be:
     *  - full: Entire SG object with all organisations and servers attached
     *  - simplified: Just important fields from SG, organisations and servers
     *  - sharing_group: specific scope that fetch just necessary information for generating distribution graph
     *  - name: array in ID => name format
     *  - uuid: array in ID => uuid format
     *
     * @param array $user
     * @param string|false $scope
     * @param bool $active If true, return only active sharing groups
     * @param int|array|false $id
     * @return array
     */
    public function fetchAllAuthorised(array $user, $scope = false, $active = false, $id = false)
    {
        $authorizedIds = $this->authorizedIds($user);
        if ($authorizedIds === [-1]) { // hack
            return [];
        }

        if ($id) {
            if (!in_array($id, $authorizedIds)) {
                return []; // user is not authorized to see that sharing group
            }
            $conditions['SharingGroup.id'] = $id;
        } else {
            $conditions = ['SharingGroup.id' => $authorizedIds];
        }
        if ($active !== false) {
            $conditions['SharingGroup.active'] = $active;
        }
        if ($scope === 'full') {
            $sgs = $this->find(
                'all',
                [
                    'contain' => ['SharingGroupServer' => ['Server'], 'SharingGroupOrg' => ['Organisation'], 'Organisation'],
                    'conditions' => $conditions,
                    'order' => 'SharingGroup.name ASC'
                ]
            );
            return $sgs;
        } elseif ($scope === 'simplified') {
            $fieldsOrg = ['id', 'name', 'uuid'];
            $fieldsServer = ['id', 'url', 'name'];
            //$permissionTree = ($user['Role']['perm_site_admin'] || $user['Role']['perm_sync']) ? 1 : 0;
            //Temporary fix: read only users used for pulling were stripping organisation data from sharing groups
            $permissionTree = 1;
            $fieldsSharingGroup = [
                [
                    'fields' => [
                        'id',
                        'uuid',
                        'modified',
                        'name',
                        'releasability',
                        'description',
                        'org_id'
                    ],
                    'contain' => []
                ],
                [
                    'fields' => ['SharingGroup.*'],
                    'contain' => [
                        'SharingGroupOrg',
                        'SharingGroupServer',
                    ]
                ]
            ];
            $sgs = $this->find(
                'all',
                [
                    'contain' => $fieldsSharingGroup[$permissionTree]['contain'],
                    'conditions' => $conditions,
                    'fields' => $fieldsSharingGroup[$permissionTree]['fields'],
                    'order' => 'SharingGroup.name ASC'
                ]
            )->toArray();
            return $this->appendOrgsAndServers($sgs, $fieldsOrg, $fieldsServer);
        } elseif ($scope === 'distribution_graph') {
            // Specific scope that fetch just necessary information for distribution graph
            // @see DistributionGraphTool
            $canSeeOrgs = $user['Role']['perm_sharing_group'] || !Configure::read('Security.hide_organisations_in_sharing_groups');
            $sgs = $this->find(
                'all',
                [
                    'contain' => $canSeeOrgs ? ['SharingGroupOrg' => ['org_id']] : [],
                    'conditions' => $conditions,
                    'fields' => ['SharingGroup.id', 'SharingGroup.name', 'SharingGroup.org_id'],
                    'order' => 'SharingGroup.name ASC'
                ]
            )->toArray();
            if ($canSeeOrgs) {
                return $this->appendOrgsAndServers($sgs, ['id', 'name'], []);
            }
            foreach ($sgs as &$sg) {
                $sg['SharingGroupOrg'] = [];
            }
            return $sgs;
        } elseif ($scope === 'name') {
            $sgs = $this->find(
                'list',
                [
                    'recursive' => -1,
                    'fields' => ['SharingGroup.id', 'SharingGroup.name'],
                    'order' => 'SharingGroup.name ASC',
                    'conditions' => $conditions,
                ]
            );
            return $sgs;
        } elseif ($scope === 'uuid') {
            $sgs = $this->find(
                'list',
                [
                    'recursive' => -1,
                    'fields' => ['SharingGroup.id', 'SharingGroup.uuid'],
                    'conditions' => $conditions,
                ]
            );
            return $sgs;
        }
        throw new InvalidArgumentException("Invalid scope $scope");
    }

    /**
     * @param array $sharingGroups
     * @param array|null $orgFields
     * @param array|null $serverFields
     * @return array
     */
    private function appendOrgsAndServers(array $sharingGroups, $orgFields = null, $serverFields = null)
    {
        $orgsToFetch = [];
        $serverToFetch = [];
        foreach ($sharingGroups as $sg) {
            if (isset($sg['SharingGroup']['org_id'])) {
                $orgsToFetch[$sg['SharingGroup']['org_id']] = true;
            }
            if (isset($sg['SharingGroupOrg'])) {
                foreach ($sg['SharingGroupOrg'] as $sgo) {
                    $orgsToFetch[$sgo['org_id']] = true;
                }
            }
            if (isset($sg['SharingGroupServer'])) {
                foreach ($sg['SharingGroupServer'] as $sgs) {
                    if ($sgs['server_id'] == 0) { // local server
                        continue;
                    }
                    $serverToFetch[$sgs['server_id']] = true;
                }
            }
        }

        $orgsById = [];
        if (!empty($orgsToFetch)) {
            $orgs = $this->Organisation->find(
                'all',
                [
                    'recursive' => -1,
                    'fields' => $orgFields,
                    'conditions' => ['id' => array_keys($orgsToFetch)],
                ]
            );
            $orgsById = array_column(array_column($orgs, 'Organisation'), null, 'id');
        }

        $serversById = [];
        if (!empty($serverToFetch)) {
            $servers = $this->SharingGroupServer->Server->find(
                'all',
                [
                    'recursive' => -1,
                    'fields' => $serverFields,
                    'conditions' => ['id' => array_keys($serverToFetch)],
                ]
            );
            $serversById = array_column(array_column($servers, 'Server'), null, 'id');
        }

        foreach ($sharingGroups as &$sg) {
            if (isset($sg['SharingGroup']['org_id']) && isset($orgsById[$sg['SharingGroup']['org_id']])) {
                $sg['Organisation'] = $orgsById[$sg['SharingGroup']['org_id']];
            }

            if (isset($sg['SharingGroupOrg'])) {
                foreach ($sg['SharingGroupOrg'] as &$sgo) {
                    if (isset($orgsById[$sgo['org_id']])) {
                        $sgo['Organisation'] = $orgsById[$sgo['org_id']];
                    }
                }
            }
            if (isset($sg['SharingGroupServer'])) {
                foreach ($sg['SharingGroupServer'] as &$sgs) {
                    if (isset($serversById[$sgs['server_id']])) {
                        $sgs['Server'] = $serversById[$sgs['server_id']];
                    }
                }
            }
        }

        return $sharingGroups;
    }

    /**
     * Who can create a new sharing group with the elements pre-defined (via REST for example)?
     * 1. site admins
     * 2. Sharing group enabled users
     *   a. as long as they are creator or extender of the SG object
     * 3. Sync users
     *  a. as long as they are at least users of the SG (they can circumvent the extend rule to
     *     avoid situations where no one can create / edit an SG on an instance after a push)
     * @param array $user
     * @param array $sg
     * @return bool
     */
    private function checkIfAuthorisedToSave(array $user, array $sg)
    {
        if (isset($sg[0])) {
            $sg = $sg[0];
        }
        if ($user['Role']['perm_site_admin']) {
            return true;
        }
        if (!$user['Role']['perm_sharing_group']) {
            return false;
        }
        // First let us find out if we already have the SG
        $local = $this->find(
            'first',
            [
                'recursive' => -1,
                'conditions' => ['uuid' => $sg['uuid']],
                'fields' => ['id'],
            ]
        );
        if (empty($local)) {
            $orgCheck = false;
            $serverCheck = false;
            if (isset($sg['SharingGroupOrg'])) {
                foreach ($sg['SharingGroupOrg'] as $org) {
                    if (isset($org['Organisation'][0])) {
                        $org['Organisation'] = $org['Organisation'][0];
                    }
                    if ($org['Organisation']['uuid'] == $user['Organisation']['uuid']) {
                        if ($user['Role']['perm_sync'] || $org['extend'] == 1) {
                            $orgCheck = true;
                            break;
                        }
                    }
                }
            }
            if (!empty($sg['SharingGroupServer'])) {
                foreach ($sg['SharingGroupServer'] as $server) {
                    if (isset($server['Server'][0])) {
                        $server['Server'] = $server['Server'][0];
                    }
                    if (
                        $server['Server']['url'] == Configure::read('MISP.baseurl') ||
                        (!empty(Configure::read('MISP.external_baseurl')) && Configure::read('MISP.external_baseurl') === $server['Server']['url'])
                    ) {
                        $serverCheck = true;
                        if ($user['Role']['perm_sync'] && $server['all_orgs']) {
                            $orgCheck = true;
                        }
                    }
                }
            } else {
                $serverCheck = true;
            }
            if ($serverCheck && $orgCheck) {
                return true;
            }
        } else {
            return $this->checkIfAuthorisedExtend($user, $local['SharingGroup']['id']);
        }
        return false;
    }

    // Who is authorised to extend a sharing group?
    // 1. Site admins
    // 2. Sharing group permission enabled users that:
    //    a. Belong to the organisation that created the SG
    //    b. Have an organisation entry in the SG with the extend flag set
    // 3. Sync users that have synced the SG to the local instance
    public function checkIfAuthorisedExtend(array $user, $id)
    {
        if ($user['Role']['perm_site_admin']) {
            return true;
        }
        if (!$user['Role']['perm_sharing_group']) {
            return false;
        }
        if ($this->checkIfOwner($user, $id)) {
            return true;
        }
        if (!$this->exists(['id' => $id])) {
            return false;
        }
        if ($user['Role']['perm_sync']) {
            $sg = $this->find(
                'first',
                [
                    'conditions' => [
                        'id' => $id,
                        'sync_user_id' => $user['id'],
                    ],
                    'recursive' => -1,
                ]
            );
            if (!empty($sg)) {
                return true;
            }
        }

        return $this->SharingGroupOrg->hasAny(
            [
                'sharing_group_id' => $id,
                'org_id' => $user['org_id'],
                'extend' => 1,
            ]
        );
    }

    public function checkIfExists($uuid)
    {
        return $this->hasAny(['SharingGroup.uuid' => $uuid]);
    }

    /**
     * Returns true if the SG exists and the user is allowed to see it
     * @param array $user
     * @param int|string $id SG ID or UUID
     * @param bool $adminCheck
     * @return bool|mixed
     */
    public function checkIfAuthorised($user, $id, $adminCheck = true)
    {
        $adminCheck = (bool)$adminCheck;
        if (isset($this->__sgAuthorisationCache['access'][$adminCheck][$id])) {
            return $this->__sgAuthorisationCache['access'][$adminCheck][$id];
        }
        if (Validation::uuid($id)) {
            $sgid = $this->find(
                'first',
                [
                    'conditions' => ['SharingGroup.uuid' => $id],
                    'recursive' => -1,
                    'fields' => ['SharingGroup.id']
                ]
            );
            if (empty($sgid)) {
                return false;
            }
            $uuid = $id;
            $id = $sgid['SharingGroup']['id'];
        } else {
            if (!$this->exists($id)) {
                return false;
            }
        }
        if (!isset($user['id'])) {
            throw new MethodNotAllowedException('Invalid user.');
        }
        $sg_org_id = $this->find(
            'first',
            [
                'recursive' => -1,
                'fields' => ['SharingGroup.org_id'],
                'conditions' => ['SharingGroup.id' => $id]
            ]
        );
        $authorized = ($adminCheck && $user['Role']['perm_site_admin']) ||
            $user['org_id'] === $sg_org_id['SharingGroup']['org_id'] ||
            $this->SharingGroupServer->checkIfAuthorised($id) ||
            $this->SharingGroupOrg->checkIfAuthorised($id, $user['org_id']);
        $this->__sgAuthorisationCache['access'][$adminCheck][$id] = $authorized;
        if (isset($uuid)) {
            // If uuid was provided, cache also result by UUID to make check faster
            $this->__sgAuthorisationCache['access'][$adminCheck][$uuid] = $authorized;
        }
        return $authorized;
    }

    /**
     * Returns sharing groups IDs that the user is allowed to see it
     * @param array $user
     * @param bool $useCache
     * @return int[]
     */
    public function authorizedIds(array $user, $useCache = true)
    {
        $cacheKey = "{$user['Role']['perm_site_admin']}-{$user['org_id']}";
        if ($useCache && isset($this->authorizedIds[$cacheKey])) {
            return $this->authorizedIds[$cacheKey];
        }

        if ($user['Role']['perm_site_admin']) {
            $sgids = $this->find(
                'column',
                [
                    'fields' => ['id'],
                ]
            )->toArray();
            $sgids = array_map('intval', $sgids);
        } else {
            $sgids = array_unique(
                array_merge(
                    $this->SharingGroupServer->fetchAllAuthorised(),
                    $this->SharingGroupOrg->fetchAllAuthorised($user['org_id'])
                ),
                SORT_REGULAR
            );
        }
        if (empty($sgids)) {
            $sgids = [-1];
        }
        if ($useCache) {
            $this->authorizedIds[$cacheKey] = $sgids;
        }
        return $sgids;
    }

    /**
     * @param array $user
     * @param string|int $id Sharing group ID or UUID
     * @return bool False if sharing group doesn't exists or user org is not sharing group owner
     */
    public function checkIfOwner(array $user, $id)
    {
        if (!isset($user['id'])) {
            throw new MethodNotAllowedException('Invalid user.');
        }
        $sg = $this->find(
            'first',
            [
                'conditions' => Validation::uuid($id) ? ['SharingGroup.uuid' => $id] : ['SharingGroup.id' => $id],
                'recursive' => -1,
                'fields' => ['org_id'],
            ]
        );
        if (empty($sg)) {
            return false;
        }
        if ($user['Role']['perm_site_admin']) {
            return true;
        }
        return $sg['SharingGroup']['org_id'] == $user['org_id'];
    }

    /**
     * Get all organisation ids that can see a SG.
     * @param int $id Sharing group ID
     * @return array|bool
     */
    public function getOrgsWithAccess($id)
    {
        $sg = $this->find(
            'first',
            [
                'conditions' => ['SharingGroup.id' => $id],
                'recursive' => -1,
                'fields' => ['id', 'org_id'],
                'contain' => [
                    'SharingGroupOrg' => ['fields' => ['id', 'org_id']],
                    'SharingGroupServer' => ['fields' => ['id', 'server_id', 'all_orgs']],
                ]
            ]
        );
        if (empty($sg)) {
            return [];
        }
        // if the current server is marked as "all orgs" in the sharing group, just return true
        foreach ($sg['SharingGroupServer'] as $sgs) {
            if ($sgs['server_id'] == 0) {
                if ($sgs['all_orgs']) {
                    return true;
                }
            }
        }
        // return a list of arrays with all organisations tied to the SG.
        return array_column($sg['SharingGroupOrg'], 'org_id');
    }

    public function checkIfServerInSG($sg, $server)
    {
        $conditional = false;
        if (isset($sg['SharingGroupServer']) && !empty($sg['SharingGroupServer']) && (empty($sg['SharingGroup']['roaming']) && empty($sg['roaming']))) {
            foreach ($sg['SharingGroupServer'] as $s) {
                if ($s['server_id'] == $server['Server']['id']) {
                    if ($s['all_orgs']) {
                        return true;
                    } else {
                        $conditional = true;
                    }
                }
            }
            if ($conditional === false && empty($server['Server']['internal'])) {
                return false;
            }
        }
        if (isset($sg['SharingGroupOrg']) && !empty($sg['SharingGroupOrg'])) {
            foreach ($sg['SharingGroupOrg'] as $org) {
                if (isset($org['Organisation']) && $org['Organisation']['uuid'] === $server['RemoteOrg']['uuid']) {
                    return true;
                }
            }
        }
        return false;
    }

    /*
     * Capture a sharing group
     * Return false if something goes wrong
     * Return an integer with the sharing group's ID, irregardless of the need to update or not
     *
     * @param array $sg
     * @param array $user
     * @param array $server
     * @return int || false
     */
    public function captureSG($sg, $user, $server = false)
    {
        $syncLocal = false;
        if (!empty($server) && !empty($server['Server']['local'])) {
            $syncLocal = true;
        }
        $existingSG = !isset($sg['uuid']) ? null : $this->find(
            'first',
            [
                'recursive' => -1,
                'conditions' => ['SharingGroup.uuid' => $sg['uuid']],
                'contain' => [
                    'Organisation',
                    'SharingGroupServer' => ['Server'],
                    'SharingGroupOrg' => ['Organisation']
                ]
            ]
        );
        $forceUpdate = false;
        if (empty($existingSG)) {
            if (!$user['Role']['perm_sharing_group']) {
                return false;
            }
            $sg_id = $this->captureSGNew($user, $sg, $syncLocal);
            if ($sg_id === false) {
                return false;
            }
        } else {
            $existingCaptureResult = $this->captureSGExisting($user, $existingSG, $sg);
            if ($existingCaptureResult !== true) {
                return $existingCaptureResult;
            }
            $sg_id = $existingSG['SharingGroup']['id'];
            $forceUpdate = true;
        }
        unset($sg['Organisation']);
        $creatorOrgFound = $this->captureSGOrgs($user, $sg, $sg_id, $forceUpdate);
        $creatorOrgFound = $this->captureSGServers($user, $sg, $sg_id, $forceUpdate) || $creatorOrgFound;
        if (!$creatorOrgFound && !empty($server)) {
            $this->captureCreatorOrg($user, $sg_id);
        }
        if (!empty($existingSG)) {
            return $existingSG[$this->alias]['id'];
        }
        return $this->id;
    }

    /*
     * Capture updates for an existing sharing group
     * Return true if updates are occurring
     * Return false if something goes wrong
     * Return an integer if no update is done but the sharing group can be attached
     *
     * @param array $user
     * @param array $existingSG
     * @param array $sg
     * @return int || false || true
     */
    private function captureSGExisting($user, $existingSG, $sg)
    {
        if (!$this->checkIfAuthorised($user, $existingSG['SharingGroup']['id']) && !$user['Role']['perm_sync']) {
            return false;
        }
        if (empty($sg['modified']) || $sg['modified'] > $existingSG['SharingGroup']['modified']) {
            // consider the local field being set to be equivalent to an event's locked == 0 state
            $isUpdatableBySync = $user['Role']['perm_sync'] && empty($existingSG['SharingGroup']['local']);
            // TODO: reconsider this, org admins will be blocked from legitimate edits if they have sync permissions.
            // We need a mechanism to check whether we're in sync context.
            $isSGOwner = !$user['Role']['perm_sync'] && $existingSG['org_id'] == $user['org_id'];
            if ($isUpdatableBySync || $isSGOwner || $user['Role']['perm_site_admin']) {
                $editedSG = $existingSG['SharingGroup'];
                $attributes = ['name', 'releasability', 'description', 'created', 'modified', 'roaming'];
                foreach ($attributes as $a) {
                    if (isset($sg[$a])) {
                        $editedSG[$a] = $sg[$a];
                    }
                }
                $this->save($editedSG);
                return true;
            } else {
                return $existingSG['SharingGroup']['id'];
            }
        } else {
            return $existingSG['SharingGroup']['id'];
        }
    }

    /**
     * Capture a new sharing group, rather than update an existing one
     *
     * @param array $user
     * @param array $sg
     * @param boolean $syncLocal
     * @return int|false
     * @throws Exception
     */
    private function captureSGNew(array $user, array $sg, $syncLocal)
    {
        // check if current user is contained in the SG and we are in a local sync setup
        if (!empty($sg['uuid'])) {
            if (isset($this->__sgAuthorisationCache['save'][boolval($syncLocal)][$sg['uuid']])) {
                $authorisedToSave = $this->__sgAuthorisationCache['save'][boolval($syncLocal)][$sg['uuid']];
            } else {
                $authorisedToSave = $this->checkIfAuthorisedToSave($user, $sg);
                $this->__sgAuthorisationCache['save'][boolval($syncLocal)][$sg['uuid']] = $authorisedToSave;
            }
        } else {
            $authorisedToSave = $this->checkIfAuthorisedToSave($user, $sg);
        }
        if (
            !$user['Role']['perm_site_admin'] &&
            !($user['Role']['perm_sync'] && $syncLocal) &&
            !$authorisedToSave
        ) {
            $this->loadLog()->createLogEntry($user, 'error', 'SharingGroup', 0, "Tried to save a sharing group with UUID '{$sg['uuid']}' but the user does not belong to it.");
            return false;
        }
        if (empty($sg['name'])) {
            return false;
        }
        $this->create();
        $date = date('Y-m-d H:i:s');
        $newSG = new SharingGroup([
            'name' => $sg['name'],
            'releasability' => !isset($sg['releasability']) ? '' : $sg['releasability'],
            'description' => !isset($sg['description']) ? '' : $sg['description'],
            'uuid' => !isset($sg['uuid']) ? Text::uuid() : $sg['uuid'],
            'organisation_uuid' => !isset($sg['organisation_uuid']) ? $user['Organisation']['uuid'] : $sg['organisation_uuid'],
            'created' => !isset($sg['created']) ? $date : $sg['created'],
            'modified' => !isset($sg['modified']) ? $date : $sg['modified'],
            'active' => !isset($sg['active']) ? 1 : $sg['active'],
            'roaming' => !isset($sg['roaming']) ? false : $sg['roaming'],
            'local' => 0,
            'sync_user_id' => $user['id'],
            'org_id' => $user['Role']['perm_sync'] ? $this->__retrieveOrgIdFromCapturedSG($user, $sg) : $user['org_id']
        ]);
        if (empty($newSG->org_id)) {
            return false;
        }
        if (!$this->save($newSG)) {
            return false;
        }
        return (int)$this->id;
    }

    /*
     * When trying to capture a sharing group, capture the org_id
     * For older MISP instances (<2.4.86) we might need to deduce it from the org list
     *
     * @param array $user
     * @param array $sg
     * @return int || false
     */
    private function __retrieveOrgIdFromCapturedSG($user, $sg)
    {
        if (!isset($sg['Organisation'])) {
            if (!isset($sg['SharingGroupOrg'])) {
                $sg['SharingGroupOrg'] = [[
                    'extend' => 1,
                    'uuid' => $user['Organisation']['uuid'],
                    'name' => $user['Organisation']['name'],
                ]];
                return $user['org_id'];
            } else {
                foreach ($sg['SharingGroupOrg'] as $k => $org) {
                    if (!isset($org['Organisation'])) {
                        $org['Organisation'] = $org;
                    }
                    if (isset($org['Organisation'][0])) {
                        $org['Organisation'] = $org['Organisation'][0];
                    }
                    if (isset($sg['organisation_uuid'])) {
                        if ($org['Organisation']['uuid'] == $sg['organisation_uuid']) {
                            return $this->Organisation->captureOrg($org['Organisation'], $user);
                        }
                    } else {
                        return $user['org_id'];
                    }
                }
            }
        } else {
            return $this->Organisation->captureOrg($sg['Organisation'], $user);
        }
        return false;
    }

    /*
     * we've pulled a sharing group from a remote server, but are not part of the SG
     * This can happen when we have access to the data on the remote by being inherently included in the exchange
     * Add our org to the sharing group!
     *
     * @param array $user
     * @param int $sg_id
     * @return void
     */
    public function captureCreatorOrg(array $user, int $sg_id)
    {
        $this->SharingGroupOrg->create();
        $this->SharingGroupOrg->save(
            [
                'sharing_group_id' => $sg_id,
                'org_id' => $user['org_id'],
                'extend' => false
            ]
        );
    }

    /*
     * Capture orgs of a sharing group. If the creator org is contained in the list, return true
     * Otherwise return false
     *
     * @param array $user
     * @param array $sg
     * @param int $sg_id
     * @param bool $force
     * @return void
     */
    public function captureSGOrgs(array $user, array $sg, int $sg_id, bool $force)
    {
        $creatorOrgFound = false;
        if (!empty($sg['SharingGroupOrg'])) {
            if (isset($sg['SharingGroupOrg']['id'])) {
                $temp = $sg['SharingGroupOrg'];
                unset($sg['SharingGroupOrg']);
                $sg['SharingGroupOrg'][0] = $temp;
            }
            foreach ($sg['SharingGroupOrg'] as $k => $org) {
                if (empty($org['Organisation'])) {
                    $org['Organisation'] = $org;
                }
                if (isset($org['Organisation'][0])) {
                    $org['Organisation'] = $org['Organisation'][0];
                }
                $sg['SharingGroupOrg'][$k]['org_id'] = $this->Organisation->captureOrg($org['Organisation'], $user, $force);
                if ($sg['SharingGroupOrg'][$k]['org_id'] == $user['org_id']) {
                    $creatorOrgFound = true;
                }
                unset($sg['SharingGroupOrg'][$k]['Organisation']);
                if ($force) {
                    // we are editing not creating here
                    $temp = $this->SharingGroupOrg->find(
                        'first',
                        [
                            'recursive' => -1,
                            'conditions' => [
                                'sharing_group_id' => $sg_id,
                                'org_id' => $sg['SharingGroupOrg'][$k]['org_id']
                            ],
                        ]
                    );
                    if (empty($temp)) {
                        $this->SharingGroupOrg->create();
                        $this->SharingGroupOrg->save(['sharing_group_id' => $sg_id, 'org_id' => $sg['SharingGroupOrg'][$k]['org_id'], 'extend' => $org['extend']]);
                    } else {
                        if ($temp['SharingGroupOrg']['extend'] != $sg['SharingGroupOrg'][$k]['extend']) {
                            $temp['SharingGroupOrg']['extend'] = $sg['SharingGroupOrg'][$k]['extend'];
                            $this->SharingGroupOrg->save($temp['SharingGroupOrg']);
                        }
                    }
                } else {
                    $this->SharingGroupOrg->create();
                    $this->SharingGroupOrg->save(['sharing_group_id' => $sg_id, 'org_id' => $sg['SharingGroupOrg'][$k]['org_id'], 'extend' => $org['extend']]);
                }
            }
        }
        return $creatorOrgFound;
    }

    public function captureSGServers(array $user, array $sg, int $sg_id, bool $force)
    {
        $creatorOrgFound = false;
        if (!empty($sg['SharingGroupServer'])) {
            if (isset($sg['SharingGroupServer']['id'])) {
                $temp = $sg['SharingGroupServer'];
                unset($sg['SharingGroupServer']);
                $sg['SharingGroupServer'][0] = $temp;
            }
            foreach ($sg['SharingGroupServer'] as $k => $server) {
                if (isset($server['Server'])) {
                    $server = $server['Server'];
                }
                if (isset($server[0])) {
                    $server = $server[0];
                }
                if (!isset($server['all_orgs'])) {
                    $sg['SharingGroupServer'][$k]['all_orgs'] = 0;
                }
                $sg['SharingGroupServer'][$k]['server_id'] = $this->SharingGroupServer->Server->captureServer($server, $user, $force);
                if ($sg['SharingGroupServer'][$k]['server_id'] == 0 && !empty($sg['SharingGroupServer'][$k]['all_orgs'])) {
                    $creatorOrgFound = true;
                }
                if ($sg['SharingGroupServer'][$k]['server_id'] === false) {
                    unset($sg['SharingGroupServer'][$k]);
                } else {
                    if ($force) {
                        // we are editing not creating here
                        $temp = $this->SharingGroupServer->find(
                            'first',
                            [
                                'recursive' => -1,
                                'conditions' => [
                                    'sharing_group_id' => $sg_id,
                                    'server_id' => $sg['SharingGroupServer'][$k]['server_id']
                                ],
                            ]
                        );
                        if (empty($temp)) {
                            $this->SharingGroupServer->create();
                            $this->SharingGroupServer->save(['sharing_group_id' => $sg_id, 'server_id' => $sg['SharingGroupServer'][$k]['server_id'], 'all_orgs' => empty($server['all_orgs']) ? 0 : $server['all_orgs']]);
                        } else {
                            if ($temp['SharingGroupServer']['all_orgs'] != $sg['SharingGroupServer'][$k]['all_orgs']) {
                                $temp['SharingGroupServer']['all_orgs'] = $sg['SharingGroupServer'][$k]['all_orgs'];
                                $this->SharingGroupServer->save($temp['SharingGroupServer']);
                            }
                        }
                    } else {
                        $this->SharingGroupServer->create();
                        $this->SharingGroupServer->save(['sharing_group_id' => $sg_id, 'server_id' => $sg['SharingGroupServer'][$k]['server_id'], 'all_orgs' => empty($server['all_orgs']) ? 0 : $server['all_orgs']]);
                    }
                }
            }
        }
        return $creatorOrgFound;
    }

    // Correct an issue that existed pre 2.4.49 where a pulled sharing group can end up not being visible to the sync user
    // This could happen if a sharing group visible to all organisations on the remote end gets pulled and for some reason (mismatch in the baseurl string for example)
    // the instance cannot be associated with a local sync link. This method checks all non-local sharing groups if the assigned sync user has access to it, if not
    // it adds the organisation of the sync user (as the only way for them to pull the event is if it is visible to them in the first place remotely).
    public function correctSyncedSharingGroups()
    {
        $sgs = $this->find(
            'all',
            [
                'recursive' => -1,
                'conditions' => ['local' => 0],
            ]
        );
        $LogsTable = $this->fetchTable('Logs');
        $UsersTable = $this->fetchTable('Users');
        $syncUsers = [];
        foreach ($sgs as $sg) {
            if (!isset($syncUsers[$sg['SharingGroup']['sync_user_id']])) {
                $syncUsers[$sg['SharingGroup']['sync_user_id']] = $UsersTable->getAuthUser($sg['SharingGroup']['sync_user_id']);
                if (empty($syncUsers[$sg['SharingGroup']['sync_user_id']])) {
                    $LogsTable->create();
                    $entry = new Log([
                        'org' => 'SYSTEM',
                        'model' => 'SharingGroup',
                        'model_id' => $sg['SharingGroup']['id'],
                        'email' => 'SYSTEM',
                        'action' => 'error',
                        'user_id' => 0,
                        'title' => 'Tried to update a sharing group as part of the 2.4.49 update, but the user used for creating the sharing group locally doesn\'t exist any longer.'
                    ]);
                    $LogsTable->save($entry);
                    unset($syncUsers[$sg['SharingGroup']['sync_user_id']]);
                    continue;
                }
            }
            if (!$this->checkIfAuthorised($syncUsers[$sg['SharingGroup']['sync_user_id']], $sg['SharingGroup']['id'], false)) {
                $sharingGroupOrg = ['sharing_group_id' => $sg['SharingGroup']['id'], 'org_id' => $syncUsers[$sg['SharingGroup']['sync_user_id']]['org_id'], 'extend' => 0];
                $result = $this->SharingGroupOrg->save($sharingGroupOrg);
                if (!$result) {
                    $entry = new Log([
                        'org' => 'SYSTEM',
                        'model' => 'SharingGroup',
                        'model_id' => $sg['SharingGroup']['id'],
                        'email' => 'SYSTEM',
                        'action' => 'error',
                        'user_id' => 0,
                        'title' => 'Tried to update a sharing group as part of the 2.4.49 update, but saving the changes has resulted in the following error: ' . json_encode($this->SharingGroupOrg->validationErrors)
                    ]);
                    $LogsTable->save($entry);
                }
            }
        }
    }

    public function updateRoaming()
    {
        $sgs = $this->find(
            'all',
            [
                'recursive' => -1,
                'conditions' => ['local' => 1, 'roaming' => 0],
                'contain' => ['SharingGroupServer']
            ]
        );
        foreach ($sgs as $sg) {
            if (empty($sg['SharingGroupServer'])) {
                $sg['SharingGroup']['roaming'] = 1;
                $this->save($sg);
            }
        }
    }

    // Fetch the Sharing Group passed as ID/uuid. Can be queried for read only and for write operations.
    public function fetchSG($id, $user, $readOnly = true)
    {
        if (empty($id)) {
            return false;
        }
        if (Validation::uuid($id)) {
            $id = $this->find(
                'first',
                [
                    'conditions' => ['SharingGroup.uuid' => $id],
                    'recursive' => -1,
                    'fields' => ['SharingGroup.id']
                ]
            );
            if (empty($id)) {
                return false;
            } else {
                $id = $id['SharingGroup']['id'];
            }
        }
        if ($readOnly) {
            if (!$this->checkIfAuthorised($user, $id)) {
                return false;
            }
        } else {
            if (!$this->checkIfAuthorisedExtend($user, $id)) {
                return false;
            }
        }
        $sg = $this->fetchAllAuthorised($user, 'full', false, $id);
        if (empty($sg)) {
            return false;
        }
        return $sg[0];
    }

    /**
     * fetchAllSharingGroup collect all saved sharing group ignore ACL checks
     *
     * @return array
     */
    public function fetchAllSharingGroup(): array
    {
        return $this->find(
            'all',
            [
                'recursive' => -1,
            ]
        )->toArray();
    }
}