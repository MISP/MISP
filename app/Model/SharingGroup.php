<?php
App::uses('AppModel', 'Model');

/**
 * @property SharingGroupOrg $SharingGroupOrg
 * @property SharingGroupServer $SharingGroupServer
 * @property Organisation $Organisation
 */
class SharingGroup extends AppModel
{
    public $actsAs = array(
            'Containable',
            'SysLogLogable.SysLogLogable' => array( // TODO Audit, logable
                    'roleModel' => 'SharingGroup',
                    'roleKey' => 'sharing_group_id',
                    'change' => 'full'
            ),
    );

    public $validate = array(
        'name' => array(
            'unique' => array(
                'rule' => 'isUnique',
                'message' => 'A sharing group with this name already exists.'
            ),
            'valueNotEmpty' => array(
                'rule' => array('valueNotEmpty'),
            ),
        ),
        'uuid' => array(
            'uuid' => array(
                'rule' => 'uuid',
                'message' => 'Please provide a valid RFC 4122 UUID'
            ),
        )
    );

    public $hasMany = array(
        'SharingGroupOrg' => array(
            'className' => 'SharingGroupOrg',
            'foreignKey' => 'sharing_group_id',
            'dependent' => true,    // cascade deletes
        ),
        'SharingGroupServer' => array(
            'className' => 'SharingGroupServer',
            'foreignKey' => 'sharing_group_id',
            'dependent' => true,    // cascade deletes
        ),
        'Event',
        'Attribute',
        'Thread'
    );

    public $belongsTo = array(
        'Organisation' => array(
            'className' => 'Organisation',
            'foreignKey' => 'org_id',
        )
    );

    private $__sgAuthorisationCache = array(
        'save' => array(),
        'access' => array()
    );


    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        if (empty($this->data['SharingGroup']['uuid'])) {
            $this->data['SharingGroup']['uuid'] = CakeText::uuid();
        } else {
            $this->data['SharingGroup']['uuid'] = strtolower($this->data['SharingGroup']['uuid']);
        }
        $date = date('Y-m-d H:i:s');
        if (empty($this->data['SharingGroup']['created'])) {
            $this->data['SharingGroup']['created'] = $date;
        }
        if (!isset($this->data['SharingGroup']['active'])) {
            $this->data['SharingGroup']['active'] = 0;
        }
        $this->data['SharingGroup']['modified'] = $date;
        $sameNameSG = $this->find('first', array(
            'conditions' => array('SharingGroup.name' => $this->data['SharingGroup']['name']),
            'recursive' => -1,
            'fields' => array('SharingGroup.name')
        ));
        if (!empty($sameNameSG) && !isset($this->data['SharingGroup']['id'])) {
            $this->data['SharingGroup']['name'] = $this->data['SharingGroup']['name'] . '_' . rand(0, 9999);
        }
        return true;
    }

    public function beforeDelete($cascade = false)
    {
        $countEvent = $this->Event->find('count', array(
                'recursive' => -1,
                'conditions' => array('sharing_group_id' => $this->id)
        ));
        $countThread = $this->Thread->find('count', array(
                'recursive' => -1,
                'conditions' => array('sharing_group_id' => $this->id)
        ));
        $countAttribute = $this->Attribute->find('count', array(
                'recursive' => -1,
                'conditions' => array('sharing_group_id' => $this->id)
        ));
        if (($countEvent + $countThread + $countAttribute) == 0) {
            return true;
        }
        return false;
    }

    /**
     * Returns a list of all sharing groups that the user is allowed to see.
     * Scope can be:
     *  - full: Entire SG object with all organisations and servers attached
     *  - simplified: Just important fields from SG, organisations and servers
     *  - sharing_group: specific scope that fetch just necessary information for generating distribution graph
     *  - name: array in ID => name format
     *  - uuid: array in ID => uuid format
     *  - false: array with all sharing group IDs
     *
     * @param array $user
     * @param string|false $scope
     * @param bool $active If true, return only active sharing groups
     * @param int|array|false $id
     * @return array
     */
    public function fetchAllAuthorised(array $user, $scope = false, $active = false, $id = false)
    {
        $conditions = array();
        if ($id) {
            $conditions['AND']['SharingGroup.id'] = $id;
        }
        if ($active !== false) {
            $conditions['AND']['SharingGroup.active'] = $active;
        }

        if ($user['Role']['perm_site_admin']) {
            $ids = $this->find('column', array(
                'fields' => array('id'),
                'conditions' => $conditions
            ));
        } else {
            $ids = array_unique(array_merge(
                $this->SharingGroupServer->fetchAllAuthorised(),
                $this->SharingGroupOrg->fetchAllAuthorised($user['Organisation']['id'])
            ));
        }
        if (!empty($ids)) {
            $conditions['AND'][] = array('SharingGroup.id' => $ids);
        } else {
            return array();
        }
        if ($scope === 'full') {
            $sgs = $this->find('all', array(
                'contain' => array('SharingGroupServer' => array('Server'), 'SharingGroupOrg' => array('Organisation'), 'Organisation'),
                'conditions' => $conditions,
                'order' => 'SharingGroup.name ASC'
            ));
            return $sgs;
        } elseif ($scope === 'simplified') {
            $fieldsOrg = array('id', 'name', 'uuid');
            $fieldsServer = array('id', 'url', 'name');
            //$permissionTree = ($user['Role']['perm_site_admin'] || $user['Role']['perm_sync']) ? 1 : 0;
            //Temporary fix: read only users used for pulling were stripping organisation data from sharing groups
            $permissionTree = 1;
            $fieldsSharingGroup = array(
                array(
                    'fields' => array(
                        'SharingGroup.id',
                        'SharingGroup.uuid',
                        'SharingGroup.modified',
                        'SharingGroup.name',
                        'SharingGroup.releasability',
                        'SharingGroup.description',
                        'SharingGroup.org_id'
                    ),
                    'contain' => array()
                ),
                array(
                    'fields' => array('SharingGroup.*'),
                    'contain' => array(
                        'SharingGroupOrg',
                        'SharingGroupServer',
                    )
                )
            );
            $sgs = $this->find('all', array(
                'contain' => $fieldsSharingGroup[$permissionTree]['contain'],
                'conditions' => $conditions,
                'fields' => $fieldsSharingGroup[$permissionTree]['fields'],
                'order' => 'SharingGroup.name ASC'
            ));
            return $this->appendOrgsAndServers($sgs, $fieldsOrg, $fieldsServer);
        } elseif ($scope === 'distribution_graph') {
            // Specific scope that fetch just necessary information for distribution graph
            // @see DistributionGraphTool
            $canSeeOrgs = $user['Role']['perm_sharing_group'] || !Configure::read('Security.hide_organisations_in_sharing_groups');
            $sgs = $this->find('all', array(
                'contain' => $canSeeOrgs ? ['SharingGroupOrg' => ['org_id']] : [],
                'conditions' => $conditions,
                'fields' => ['SharingGroup.id', 'SharingGroup.name', 'SharingGroup.org_id'],
                'order' => 'SharingGroup.name ASC'
            ));
            if ($canSeeOrgs) {
                return $this->appendOrgsAndServers($sgs, ['id', 'name'], []);
            }
            foreach ($sgs as &$sg) {
                $sg['SharingGroupOrg'] = [];
            }
            return $sgs;
        } elseif ($scope === 'name') {
            $sgs = $this->find('list', array(
                'recursive' => -1,
                'fields' => array('SharingGroup.id', 'SharingGroup.name'),
                'order' => 'SharingGroup.name ASC',
                'conditions' => $conditions,
            ));
            return $sgs;
        } elseif ($scope === 'uuid') {
            $sgs = $this->find('list', array(
                'recursive' => -1,
                'fields' => array('SharingGroup.id', 'SharingGroup.uuid'),
                'conditions' => $conditions,
            ));
            return $sgs;
        } else {
            return $ids;
        }
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
            $orgs = $this->Organisation->find('all', [
                'recursive' => -1,
                'fields' => $orgFields,
                'conditions' => ['id' => array_keys($orgsToFetch)],
            ]);
            foreach ($orgs as $org) {
                $orgsById[$org['Organisation']['id']] = $org['Organisation'];
            }
        }

        $serversById = [];
        if (!empty($serverToFetch)) {
            $servers = $this->SharingGroupServer->Server->find('all', [
                'recursive' => -1,
                'fields' => $serverFields,
                'conditions' => ['id' => array_keys($serverToFetch)],
            ]);
            foreach ($servers as $server) {
                $serversById[$server['Server']['id']] = $server['Server'];
            }
        }

        foreach ($sharingGroups as &$sg) {
            if (isset($sg['SharingGroup']['org_id']) && isset($orgsById[$sg['SharingGroup']['org_id']])) {
                $sg['Organisation'] = $orgsById[$sg['SharingGroup']['org_id']];
            }

            if (isset($sg['SharingGroupOrg'])) {
                foreach($sg['SharingGroupOrg'] as &$sgo) {
                    if (isset($orgsById[$sgo['org_id']])) {
                        $sgo['Organisation'] = $orgsById[$sgo['org_id']];
                    }
                }
            }
            if (isset($sg['SharingGroupServer'])) {
                foreach($sg['SharingGroupServer'] as &$sgs) {
                    if (isset($serversById[$sgs['server_id']])) {
                        $sgs['Server'] = $serversById[$sgs['server_id']];
                    }
                }
            }
        }

        return $sharingGroups;
    }

    // Who can create a new sharing group with the elements pre-defined (via REST for example)?
    // 1. site admins
    // 2. Sharing group enabled users
    //    a. as long as they are creator or extender of the SG object
    // 3. Sync users
    //    a. as long as they are at least users of the SG (they can circumvent the extend rule to
    //       avoid situations where no one can create / edit an SG on an instance after a push)

    public function checkIfAuthorisedToSave($user, $sg)
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
        $local = $this->find('first', array(
                'recursive' => -1,
                'conditions' => array('uuid' => $sg['uuid'])
        ));
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
    public function checkIfAuthorisedExtend($user, $id)
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
        $this->id = $id;
        if (!$this->exists()) {
            return false;
        }
        if ($user['Role']['perm_sync']) {
            $sg = $this->find('first', array(
                'conditions' => array(
                    'id' => $id,
                    'sync_user_id' => $user['id'],
                ),
                'recursive' => -1,
            ));
            if (!empty($sg)) {
                return true;
            }
        }
        $sgo = $this->SharingGroupOrg->find('first', array(
                'conditions' => array(
                        'sharing_group_id' => $id,
                        'org_id' => $user['org_id'],
                        'extend' => 1,
                ),
                'recursive' => -1,
                'fields' => array('id', 'org_id', 'extend')
        ));
        if (empty($sgo)) {
            return false;
        } else {
            return true;
        }
    }

    public function checkIfExists($uuid)
    {
        return !empty($this->SharingGroup->find('first', array(
            'conditions' => array('SharingGroup.uuid' => $uuid),
            'recursive' => -1,
            'fields' => array('SharingGroup.id')
        )));
    }

    // returns true if the SG exists and the user is allowed to see it
    public function checkIfAuthorised($user, $id, $adminCheck = true)
    {
        if (isset($this->__sgAuthorisationCache['access'][boolval($adminCheck)][$id])) {
            return $this->__sgAuthorisationCache['access'][boolval($adminCheck)][$id];
        }
        if (Validation::uuid($id)) {
            $sgid = $this->find('first', array(
                'conditions' => array('SharingGroup.uuid' => $id),
                'recursive' => -1,
                'fields' => array('SharingGroup.id')
            ));
            if (empty($sgid)) {
                return false;
            }
            $id = $sgid['SharingGroup']['id'];
        } else {
            if (!$this->exists($id)) {
                return false;
            }
        }
        if (!isset($user['id'])) {
            throw new MethodNotAllowedException('Invalid user.');
        }
        if (($adminCheck && $user['Role']['perm_site_admin']) || $this->SharingGroupServer->checkIfAuthorised($id) || $this->SharingGroupOrg->checkIfAuthorised($id, $user['org_id'])) {
            $this->__sgAuthorisationCache['access'][boolval($adminCheck)][$id] = true;
            return true;
        }
        $this->__sgAuthorisationCache['access'][boolval($adminCheck)][$id] = false;
        return false;
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
        $sg = $this->find('first', array(
            'conditions' => Validation::uuid($id) ? ['SharingGroup.uuid' => $id] : ['SharingGroup.id' => $id],
            'recursive' => -1,
            'fields' => array('org_id'),
        ));
        if (empty($sg)) {
            return false;
        }
        if ($user['Role']['perm_site_admin']) {
            return true;
        }
        return $sg['SharingGroup']['org_id'] == $user['org_id'];
    }

    // Get all organisation ids that can see a SG
    public function getOrgsWithAccess($id)
    {
        $sg = $this->find('first', array(
            'conditions' => array('SharingGroup.id' => $id),
            'recursive' => -1,
            'fields' => array('id', 'org_id'),
            'contain' => array(
                'SharingGroupOrg' => array('fields' => array('id', 'org_id')),
                'SharingGroupServer' => array('fields' => array('id', 'server_id', 'all_orgs')),
            )
        ));
        if (empty($sg)) {
            return array();
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
        $orgs = array();
        foreach ($sg['SharingGroupOrg'] as $sgo) {
            $orgs[] = $sgo['org_id'];
        }
        return $orgs;
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
            if ($conditional === false) {
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

    public function getSGSyncRules($sg)
    {
        $results = array(
            'conditional' => array(),
            'full' => array(),
            'orgs' => array(),
            'no_server_settings' => false
        );
        if (isset($sg['SharingGroupServer'])) {
            foreach ($sg['SharingGroupServer'] as $server) {
                if ($server['server_id'] != 0) {
                    if ($server['all_orgs']) {
                        $results['full'][] = $server['id'];
                    } else {
                        $results['conditional'][] = $server['id'];
                    }
                }
            }
            if (empty($results['full']) && empty($results['conditional'])) {
                return false;
            }
        } else {
            $results['no_server_settings'] = true;
        }
        foreach ($sg['SharingGroupOrg'] as $org) {
            $results['orgs'][] = $org['Organisation']['uuid'];
        }
        return $results;
    }

    public function captureSG($sg, $user, $syncLocal=false)
    {
        $this->Log = ClassRegistry::init('Log');
        $existingSG = !isset($sg['uuid']) ? null : $this->find('first', array(
                'recursive' => -1,
                'conditions' => array('SharingGroup.uuid' => $sg['uuid']),
                'contain' => array(
                    'Organisation',
                    'SharingGroupServer' => array('Server'),
                    'SharingGroupOrg' => array('Organisation')
                )
        ));
        $force = false;
        if (empty($existingSG)) {
            if (!$user['Role']['perm_sharing_group']) {
                return false;
            }
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
            if (!$user['Role']['perm_site_admin'] &&
                !($user['Role']['perm_sync'] && $syncLocal ) &&
                !$authorisedToSave
            ) {
                $this->Log->create();
                $entry = array(
                        'org' => $user['Organisation']['name'],
                        'model' => 'SharingGroup',
                        'model_id' => $sg['SharingGroup']['uuid'],
                        'email' => $user['email'],
                        'action' => 'error',
                        'user_id' => $user['id'],
                        'title' => 'Tried to save a sharing group but the user does not belong to it.'
                );
                $this->Log->save($entry);
                return false;
            }
            $this->create();
            $newSG = array();
            $attributes = array(
                'name' => array(),
                'releasability' => array(),
                'description' => array('default' => ''),
                'uuid' => array('default' => CakeText::uuid()),
                'organisation_uuid' => array('default' => $user['Organisation']['uuid']),
                'created' => array('default' => $date = date('Y-m-d H:i:s')),
                'modified' => array('default' => $date = date('Y-m-d H:i:s')),
                'active' => array('default' => 1),
                'roaming' => array('default' => false),
            );
            foreach (array_keys($attributes) as $a) {
                if (isset($sg[$a])) {
                    $newSG[$a] = $sg[$a];
                } else {
                    if (!isset($attributes[$a]['default'])) {
                        return false;
                    } else {
                        $newSG[$a] = $attributes[$a]['default'];
                    }
                }
            }
            $newSG['local'] = 0;
            $newSG['sync_user_id'] = $user['id'];
            if (!$user['Role']['perm_sync']) {
                $newSG['org_id'] = $user['org_id'];
            } else {
                if (!isset($sg['Organisation'])) {
                    if (!isset($sg['SharingGroupOrg'])) {
                        $sg['SharingGroupOrg'] = array(array(
                            'extend' => 1,
                            'uuid' => $user['Organisation']['uuid'],
                            'name' => $user['Organisation']['name'],
                        ));
                        $newSG['org_id'] = $user['org_id'];
                    } else {
                        // Try to capture the creator organisation using the organisation_uuid if the org is contained in the SG (in some rare cases pre 2.4.86 the lack of this could occur)
                        foreach ($sg['SharingGroupOrg'] as $k => $org) {
                            if (!isset($org['Organisation'])) {
                                $org['Organisation'] = $org;
                            }
                            if (isset($org['Organisation'][0])) {
                                $org['Organisation'] = $org['Organisation'][0];
                            }
                            if (isset($sg['organisation_uuid'])) {
                                if ($org['Organisation']['uuid'] == $sg['organisation_uuid']) {
                                    $newSG['org_id'] = $this->Organisation->captureOrg($org['Organisation'], $user);
                                }
                            } else {
                                $newSG['org_id'] = $user['org_id'];
                            }
                        }
                    }
                } else {
                    $newSG['org_id'] = $this->Organisation->captureOrg($sg['Organisation'], $user);
                }
            }
            if (empty($newSG['org_id'])) {
                return false;
            }
            if (!$this->save($newSG)) {
                return false;
            }
            $sgids = $this->id;
        } else {
            if (!$this->checkIfAuthorised($user, $existingSG['SharingGroup']['id']) && !$user['Role']['perm_sync']) {
                return false;
            }
            if (empty($sg['modified']) || $sg['modified'] > $existingSG['SharingGroup']['modified']) {
                if (
                    ($user['Role']['perm_sync'] && isset($existingSG['SharingGroup']['local']) && $existingSG['SharingGroup']['local'] == 0) ||
                    ((!$user['Role']['perm_sync'] && $existingSG['org_id'] == $user['org_id']) || $user['Role']['perm_site_admin'])
                ) {
                    $force = true;
                }
                if ($force) {
                    $sgids = $existingSG['SharingGroup']['id'];
                    $editedSG = $existingSG['SharingGroup'];
                    $attributes = ['name', 'releasability', 'description', 'created', 'modified', 'active', 'roaming'];
                    foreach ($attributes as $a) {
                        if (isset($sg[$a])) {
                            $editedSG[$a] = $sg[$a];
                        }
                    }
                    $this->save($editedSG);
                } else {
                    return $existingSG['SharingGroup']['id'];
                }
            } else {
                return $existingSG['SharingGroup']['id'];
            }
        }
        unset($sg['Organisation']);
        if (!empty($sg['SharingGroupOrg'])) {
            $creatorOrgFound = false;
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
                    $temp = $this->SharingGroupOrg->find('first', array(
                        'recursive' => -1,
                        'conditions' => array(
                            'sharing_group_id' => $existingSG['SharingGroup']['id'],
                            'org_id' => $sg['SharingGroupOrg'][$k]['org_id']
                        ),
                    ));
                    if (empty($temp)) {
                        $this->SharingGroupOrg->create();
                        $this->SharingGroupOrg->save(array('sharing_group_id' => $sgids, 'org_id' => $sg['SharingGroupOrg'][$k]['org_id'], 'extend' => $org['extend']));
                    } else {
                        if ($temp['SharingGroupOrg']['extend'] != $sg['SharingGroupOrg'][$k]['extend']) {
                            $temp['SharingGroupOrg']['extend'] = $sg['SharingGroupOrg'][$k]['extend'];
                            $this->SharingGroupOrg->save($temp['SharingGroupOrg']);
                        }
                    }
                } else {
                    $this->SharingGroupOrg->create();
                    $this->SharingGroupOrg->save(array('sharing_group_id' => $sgids, 'org_id' => $sg['SharingGroupOrg'][$k]['org_id'], 'extend' => $org['extend']));
                }
            }
        }
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
                        $temp = $this->SharingGroupServer->find('first', array(
                            'recursive' => -1,
                            'conditions' => array(
                                'sharing_group_id' => $existingSG['SharingGroup']['id'],
                                'server_id' => $sg['SharingGroupServer'][$k]['server_id']
                            ),
                        ));
                        if (empty($temp)) {
                            $this->SharingGroupServer->create();
                            $this->SharingGroupServer->save(array('sharing_group_id' => $sgids, 'server_id' => $sg['SharingGroupServer'][$k]['server_id'], 'all_orgs' => empty($server['all_orgs']) ? 0 : $server['all_orgs']));
                        } else {
                            if ($temp['SharingGroupServer']['all_orgs'] != $sg['SharingGroupServer'][$k]['all_orgs']) {
                                $temp['SharingGroupServer']['all_orgs'] = $sg['SharingGroupServer'][$k]['all_orgs'];
                                $this->SharingGroupServer->save($temp['SharingGroupServer']);
                            }
                        }
                    } else {
                        $this->SharingGroupServer->create();
                        $this->SharingGroupServer->save(array('sharing_group_id' => $sgids, 'server_id' => $sg['SharingGroupServer'][$k]['server_id'], 'all_orgs' => empty($server['all_orgs']) ? 0 : $server['all_orgs']));
                    }
                }
            }
        }
        if (!empty($existingSG)) {
            return $existingSG[$this->alias]['id'];
        }
        return $this->id;
    }

    // Correct an issue that existed pre 2.4.49 where a pulled sharing group can end up not being visible to the sync user
    // This could happen if a sharing group visible to all organisations on the remote end gets pulled and for some reason (mismatch in the baseurl string for example)
    // the instance cannot be associated with a local sync link. This method checks all non-local sharing groups if the assigned sync user has access to it, if not
    // it adds the organisation of the sync user (as the only way for them to pull the event is if it is visible to them in the first place remotely).
    public function correctSyncedSharingGroups()
    {
        $sgs = $this->find('all', array(
                'recursive' => -1,
                'conditions' => array('local' => 0),
        ));
        $this->Log = ClassRegistry::init('Log');
        $this->User = ClassRegistry::init('User');
        $syncUsers = array();
        foreach ($sgs as $sg) {
            if (!isset($syncUsers[$sg['SharingGroup']['sync_user_id']])) {
                $syncUsers[$sg['SharingGroup']['sync_user_id']] = $this->User->getAuthUser($sg['SharingGroup']['sync_user_id']);
                if (empty($syncUsers[$sg['SharingGroup']['sync_user_id']])) {
                    $this->Log->create();
                    $entry = array(
                            'org' => 'SYSTEM',
                            'model' => 'SharingGroup',
                            'model_id' => $sg['SharingGroup']['id'],
                            'email' => 'SYSTEM',
                            'action' => 'error',
                            'user_id' => 0,
                            'title' => 'Tried to update a sharing group as part of the 2.4.49 update, but the user used for creating the sharing group locally doesn\'t exist any longer.'
                    );
                    $this->Log->save($entry);
                    unset($syncUsers[$sg['SharingGroup']['sync_user_id']]);
                    continue;
                }
            }
            if (!$this->checkIfAuthorised($syncUsers[$sg['SharingGroup']['sync_user_id']], $sg['SharingGroup']['id'], false)) {
                $sharingGroupOrg = array('sharing_group_id' => $sg['SharingGroup']['id'], 'org_id' => $syncUsers[$sg['SharingGroup']['sync_user_id']]['org_id'], 'extend' => 0);
                $result = $this->SharingGroupOrg->save($sharingGroupOrg);
                if (!$result) {
                    $this->Log->create();
                    $entry = array(
                            'org' => 'SYSTEM',
                            'model' => 'SharingGroup',
                            'model_id' => $sg['SharingGroup']['id'],
                            'email' => 'SYSTEM',
                            'action' => 'error',
                            'user_id' => 0,
                            'title' => 'Tried to update a sharing group as part of the 2.4.49 update, but saving the changes has resulted in the following error: ' . json_encode($this->SharingGroupOrg->validationErrors)
                    );
                    $this->Log->save($entry);
                }
            }
        }
    }

    public function updateRoaming()
    {
        $sgs = $this->find('all', array(
                'recursive' => -1,
                'conditions' => array('local' => 1, 'roaming' => 0),
                'contain' => array('SharingGroupServer')
        ));
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
            $id = $this->find('first', array(
                'conditions' => array('SharingGroup.uuid' => $id),
                'recursive' => -1,
                'fields' => array('SharingGroup.id')
            ));
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

    public function getSharingGroupIdByUuid($user, $data)
    {
        $sg = $this->find('first', array(
            'conditions' => array('SharingGroup.uuid' => $data['sharing_group_id']),
            'recursive' => -1,
            'fields' => array('SharingGroup.id')
        ));
        if (!empty($sg) && $this->checkIfAuthorised($user, $sg['SharingGroup']['id'])) {
            $data['sharing_group_id'] = $sg['SharingGroup']['id'];
            return $data;
        }
        return false;
    }
}
