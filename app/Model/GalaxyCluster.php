<?php
App::uses('AppModel', 'Model');
class GalaxyCluster extends AppModel
{
    public $useTable = 'galaxy_clusters';

    public $recursive = -1;

    public $actsAs = array(
            'Containable',
    );

    public $validate = array(
        'name' => array(
            'stringNotEmpty' => array(
                'rule' => array('stringNotEmpty')
            )
        ),
        'description' => array(
            'stringNotEmpty' => array(
                'rule' => array('stringNotEmpty')
            )
        ),
        'uuid' => array(
            'uuid' => array(
                'rule' => array('custom', '/^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$/'),
                'message' => 'Please provide a valid UUID'
            ),
            'unique' => array(
                'rule' => 'isUnique',
                'message' => 'The UUID provided is not unique',
                'required' => 'create'
            )
        ),
        'distribution' => array(
            'rule' => array('inList', array('0', '1', '2', '3', '4')),
            'message' => 'Options: Your organisation only, This community only, Connected communities, All communities, Sharing group',
            'required' => true
        )
    );

    public $belongsTo = array(
        'Galaxy' => array(
            'className' => 'Galaxy',
            'foreignKey' => 'galaxy_id',
        ),
        'Tag' => array(
            'foreignKey' => false,
            'conditions' => array('GalaxyCluster.tag_name = Tag.name')
        ),
        'Org' => array(
            'className' => 'Organisation',
            'foreignKey' => 'org_id'
        ),
        'Orgc' => array(
            'className' => 'Organisation',
            'foreignKey' => 'orgc_id'
        ),
        'SharingGroup' => array(
                'className' => 'SharingGroup',
                'foreignKey' => 'sharing_group_id'
        )
    );

    private $__clusterCache = array();

    public $hasMany = array(
        'GalaxyElement' => array('dependent' => true),
        'GalaxyClusterRelation' => array(
            'className' => 'GalaxyClusterRelation',
            'foreignKey' => 'galaxy_cluster_id',
            'dependent' => true,
        ),
        'TargettingClusterRelation' => array(
            'className' => 'GalaxyClusterRelation',
            'foreignKey' => 'referenced_galaxy_cluster_id',
        ),
    );

    public $validFormats = array(
        'json' => array('json', 'JsonExport', 'json'),
    );

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        if (!isset($this->data['GalaxyCluster']['description'])) {
            $this->data['GalaxyCluster']['description'] = '';
        }
        if ($this->data['GalaxyCluster']['distribution'] != 4) {
            $this->data['GalaxyCluster']['sharing_group_id'] = null;
        }
        if (is_array($this->data['GalaxyCluster']['authors'])) {
            $this->data['GalaxyCluster']['authors'] = json_encode($this->data['GalaxyCluster']['authors']);
        }
        return true;
    }

    public function afterFind($results, $primary = false)
    {
        foreach ($results as $k => $result) {
            if (isset($results[$k][$this->alias]['authors'])) {
                $results[$k][$this->alias]['authors'] = json_decode($results[$k][$this->alias]['authors'], true);
            }
            if (isset($results[$k][$this->alias]['distribution']) && $results[$k][$this->alias]['distribution'] != 4) {
                unset($results[$k]['SharingGroup']);
            }
            if (isset($results[$k][$this->alias]['org_id']) && $results[$k][$this->alias]['org_id'] == 0) {
                if (isset($results[$k]['Org'])) {
                    $results[$k]['Org'] = $this->Org->genericMISPOrganisation;
                }
            }
            if (isset($results[$k][$this->alias]['orgc_id']) && $results[$k][$this->alias]['orgc_id'] == 0) {
                if (isset($results[$k]['Orgc'])) {
                    $results[$k]['Orgc'] = $this->Org->genericMISPOrganisation;
                }
            }
        }
        return $results;
    }

    public function afterSave($results, $primary = false)
    {
       // update all relations IDs that was not set (UUID is set)
       // Can happen if the relations was saved while the cluster was not existing in this istance
    }

    public function beforeDelete($cascade = true)
    {
        $this->GalaxyElement->deleteAll(array('GalaxyElement.galaxy_cluster_id' => $this->id));
        $this->GalaxyClusterRelation->deleteAll(array('GalaxyClusterRelation.galaxy_cluster_uuid' => $this->uuid));
    }

    // Respecting ACL, save a cluster, its elements and set correct fields
    public function saveCluster($user, $cluster, $fromPull=false, $allowEdit=false)
    {
        if (!$user['Role']['perm_galaxy_editor'] && !$user['Role']['perm_site_admin']) {
            return false;
        }
        $galaxy = $this->Galaxy->find('first', array('conditions' => array(
            'id' => $cluster['GalaxyCluster']['galaxy_id']
        )));
        if (empty($galaxy)) {
            return false;
        } else {
            $galaxy = $galaxy['Galaxy'];
        }
        unset($cluster['GalaxyCluster']['id']);
        if (isset($cluster['GalaxyCluster']['uuid'])) {
            // check if the uuid already exists
            $existingGalaxyCluster = $this->find('first', array('conditions' => array('GalaxyCluster.uuid' => $cluster['GalaxyCluster']['uuid'])));
            if ($existingGalaxyCluster) {
                if ($existingGalaxyCluster['GalaxyCluster']['galaxy_id'] != $galaxy['id']) { // cluster already exists in another galaxy
                    return false;
                }
                if ($fromPull && !$existingGalaxyCluster['GalaxyCluster']['default'] && $allowEdit) {
                    $errors = $this->editCluster($user, $cluster, $fromPull);
                    return empty($errors);
                } else {
                    // Maybe redirect to the correct URL?
                }
                return false;
            }
        } else {
            $cluster['GalaxyCluster']['uuid'] = CakeText::uuid();
        }
        $forkedCluster = $this->find('first', array('conditions' => array('GalaxyCluster.uuid' => $cluster['GalaxyCluster']['extends_uuid'])));
        if (!empty($forkedCluster) && $forkedCluster['GalaxyCluster']['galaxy_id'] != $galaxy['id']) {
            return false; // cluster forks always have to belong to the same galaxy as the parent
        }
        if (!isset($cluster['GalaxyCluster']['orgc_id'])) {
            if (isset($cluster['Orgc']['uuid'])) {
                $orgc_id = $this->Orgc->find('first', array('conditions' => array('Orgc.uuid' => $user['Orgc']['uuid']), 'fields' => array('Orgc.id'), 'recursive' => -1));
            } else {
                $orgc_id = $user['org_id'];
            }
            $cluster['GalaxyCluster']['orgc_id'] = $orgc_id;
        }
        $cluster['GalaxyCluster']['type'] = $galaxy['type'];
        if (!$fromPull) {
            $date = new DateTime();
            $cluster['GalaxyCluster']['version'] = $date->getTimestamp();
        }
        $cluster['GalaxyCluster']['tag_name'] = sprintf('misp-galaxy:%s="%s"', $galaxy['type'], $cluster['GalaxyCluster']['uuid']);
        $this->create();
        $saveSuccess = $this->save($cluster);
        if ($saveSuccess) {
            $savedCluster = $this->find('first', array(
                'conditions' => array('id' =>  $this->id),
                'recursive' => -1
            ));
            $this->GalaxyElement->updateElements(-1, $savedCluster['GalaxyCluster']['id'], $cluster['GalaxyCluster']['elements']);
        }
        return $saveSuccess;
    }

    public function editCluster($user, $cluster, $fromPull = false, $fieldList = array())
    {
        $this->SharingGroup = ClassRegistry::init('SharingGroup');
        $errors = array();
        if (!$user['Role']['perm_galaxy_editor'] && !$user['Role']['perm_site_admin']) {
            $errors[] = __('Incorrect permission');
        }
        if (isset($cluster['GalaxyCluster']['uuid'])) {
            $existingCluster = $this->find('first', array('conditions' => array('GalaxyCluster.uuid' => $cluster['GalaxyCluster']['uuid'])));
        } else {
            $errors[] = __('UUID not provided');
        }
        if (empty($existingCluster)) {
            $errors[] = __('Unkown UUID');
        } else {
            // For users that are of the creating org of the cluster, always allow the edit
            // For users that are sync users, only allow the edit if the cluster is locked
            if ($existingCluster['GalaxyCluster']['orgc_id'] === $user['org_id']
            || ($user['Role']['perm_sync'] && $existingCluster['GalaxyCluster']['locked']) || $user['Role']['perm_site_admin']) {
                if ($user['Role']['perm_sync']) {
                    if (isset($cluster['GalaxyCluster']['distribution']) && $cluster['GalaxyCluster']['distribution'] == 4 && !$this->SharingGroup->checkIfAuthorised($user, $cluster['GalaxyCluster']['sharing_group_id'])) {
                        $errors[] = array(__('Galaxy Cluster could not be saved: The sync user has to have access to the sharing group in order to be able to edit it.'));
                    }
                }
            } else {
                $errors[] = array(__('Galaxy Cluster could not be saved: The user used to edit the cluster is not authorised to do so. This can be caused by the user not being of the same organisation as the original creator of the cluster whilst also not being a site administrator.'));
            }
            $cluster['GalaxyCluster']['id'] = $existingCluster['GalaxyCluster']['id'];

            if (empty($errors)) {
                $date = new DateTime();
                if (!$fromPull) {
                    $cluster['GalaxyCluster']['version'] = $date->getTimestamp();
                }
                $cluster['GalaxyCluster']['default'] = false;
                if (empty($fieldList)) {
                    $fieldList = array('value', 'description', 'version', 'source', 'authors', 'distribution', 'sharing_group_id', 'default');
                }
                $saveSuccess = $this->save($cluster, array('fieldList' => $fieldList));
                if ($saveSuccess) {
                    $elementsToSave = array();
                    foreach ($cluster['GalaxyCluster']['elements'] as $element) { // transform cluster into Galaxy meta format
                        $elementsToSave[$element['key']] = $element['value'];
                    }
                    $this->GalaxyElement->updateElements($cluster['GalaxyCluster']['id'], $cluster['GalaxyCluster']['id'], $elementsToSave);
                } else {
                    foreach($this->validationErrors as $validationError) {
                        $errors[] = $validationError[0];
                    }
                }
            }
        }
        return $errors;
    }

    public function captureClusters($user, $galaxy, $clusters, $forceUpdate=false, $orgId=0)
    {
        $importResult = array('success' => true, 'imported' => 0, 'ignored' => 0, 'failed' => 0,'errors' => array());
        foreach ($clusters as $k => $cluster) {
            $cluster['GalaxyCluster']['galaxy_id'] = $galaxy['Galaxy']['id'];
            $saveResult = $this->captureCluster($user, $cluster, $fromPull=true, $orgId=$orgId);
            $importResult['imported'] += $saveResult['imported'];
            $importResult['ignored'] += $saveResult['ignored'];
            $importResult['failed'] += $saveResult['failed'];
            $importResult['errors'] = array_merge($importResult['errors'], $saveResult['errors']);
        }
        if ($importResult['failed'] > 0 && $importResult['imported'] == 0 && $importResult['ignored'] == 0) {
            $importResult['success'] = false;
        }
        return $importResult;
    }

    /**
     * Gets a cluster then save it.
     *
     * @param $user
     * @param array $cluster Cluster to be saved
     * @param bool $fromPull If the current capture is performed from a PULL sync
     * @param int $orgId The organisation id that should own the cluster
     * @return array
     */
    public function captureCluster($user, $cluster, $fromPull=false, $orgId=0)
    {
        $results = array('success' => false, 'imported' => 0, 'ignored' => 0, 'failed' => 0, 'errors' => array());

        if ($fromPull) {
            $cluster['GalaxyCluster']['org_id'] = $orgId;
        } else {
            $cluster['GalaxyCluster']['org_id'] = $user['Organisation']['id'];
        }

        if (!isset($cluster['GalaxyCluster']['orgc_id']) && !isset($cluster['Orgc'])) {
            $cluster['GalaxyCluster']['orgc_id'] = $cluster['GalaxyCluster']['org_id'];
        } else {
            if (!isset($cluster['GalaxyCluster']['Orgc'])) {
                if (isset($cluster['GalaxyCluster']['orgc_id']) && $cluster['GalaxyCluster']['orgc_id'] != $user['org_id'] && !$user['Role']['perm_sync'] && !$user['Role']['perm_site_admin']) {
                    $results['errors'][] = __('Only sync user can create cluster on behalf of other users');
                    $results['failed']++;
                    return $results;
                }
            } else {
                if ($cluster['GalaxyCluster']['Orgc']['uuid'] != $user['Organisation']['uuid'] && !$user['Role']['perm_sync'] && !$user['Role']['perm_site_admin']) {
                    $results['errors'][] = __('Only sync user can create galaxy on behalf of other users');
                    $results['failed']++;
                    return $results;
                }
            }
            if (isset($cluster['GalaxyCluster']['orgc_id']) && $cluster['GalaxyCluster']['orgc_id'] != $user['org_id'] && !$user['Role']['perm_sync'] && !$user['Role']['perm_site_admin']) {
                $results['errors'][] = __('Only sync user can create galaxy on behalf of other users');
                $results['failed']++;
                return $results;
            }
        }

        if (!Configure::check('MISP.enableOrgBlacklisting') || Configure::read('MISP.enableOrgBlacklisting') !== false) {
            $this->OrgBlacklist = ClassRegistry::init('OrgBlacklist');
            if (!isset($cluster['GalaxyCluster']['Orgc']['uuid'])) {
                $orgc = $this->Orgc->find('first', array('conditions' => array('Orgc.id' => $cluster['GalaxyCluster']['orgc_id']), 'fields' => array('Orgc.uuid'), 'recursive' => -1));
            } else {
                $orgc = array('Orgc' => array('uuid' => $cluster['GalaxyCluster']['Orgc']['uuid']));
            }
            if ($cluster['GalaxyCluster']['orgc_id'] != 0 && $this->OrgBlacklist->hasAny(array('OrgBlacklist.org_uuid' => $orgc['Orgc']['uuid']))) {
                $results['failed']++; // Organisation blacklisted
                return $results;
            }
        }

        $cluster = $this->captureOrganisationAndSG($cluster, 'GalaxyCluster', $user);
        $existingGalaxyCluster = $this->find('first', array('conditions' => array(
            'GalaxyCluster.uuid' => $cluster['GalaxyCluster']['uuid']
        )));
        if (empty($existingGalaxyCluster)) {
            $this->create();
            $saveSuccess = $this->save($cluster);
        } else {
            if ($cluster['GalaxyCluster']['default']) {
                $results['errors'][] = __('Can only save non default clusters');
                $results['failed']++;
                return $results;
            }
            if ($cluster['GalaxyCluster']['version'] > $existingGalaxyCluster['GalaxyCluster']['version']) {
                $cluster['GalaxyCluster']['id'] = $existingGalaxyCluster['GalaxyCluster']['id'];
                $saveSuccess = $this->save($cluster);
            } else {
                $results['errors'][] = __('Remote version is not newer than local one');
                $results['ignored']++;
                return $results;
            }
        }
        if ($saveSuccess) {
            $results['imported']++;
            $savedCluster = $this->find('first', array(
                'conditions' => array('id' =>  $this->id),
                'recursive' => -1
            ));
            if (!empty($cluster['GalaxyElement'])) {
                $this->GalaxyElement->captureElements($user, $cluster['GalaxyElement'],  $savedCluster['GalaxyCluster']['id']);
            }
            if (!empty($cluster['GalaxyClusterRelation'])) {
                $saveResult = $this->GalaxyClusterRelation->captureRelations($user, $savedCluster, $cluster['GalaxyClusterRelation'],  $fromPull=true, $orgId=$orgId);
                if ($saveResult['failed'] > 0) {
                    $results['errors'][] = __('Issues while capturing relations have been logged.');
                }
            }
        } else {
            $results['failed']++;
            foreach($this->validationErrors as $validationError) {
                $results['errors'][] = $validationError[0];
            }
        }
        return $results;
    }

    public function captureOrganisationAndSG($element, $model, $user)
    {
        $this->Event = ClassRegistry::init('Event');
        if (isset($element[$model]['distribution']) && $element[$model]['distribution'] == 4) {
            $element[$model] = $this->Event->__captureSGForElement($element[$model], $user);
        }
        // first we want to see how the creator organisation is encoded
        // The options here are either by passing an organisation object along or simply passing a string along
        if (isset($element['Orgc'])) {
            $element[$model]['orgc_id'] = $this->Orgc->captureOrg($element['Orgc'], $user);
            unset($element['Orgc']);
        } else {
            // Can't capture the Orgc, default to the current user
            $element[$model]['orgc_id'] = $user['org_id'];
        }
        return $element;
    }

    public function attachExtendByInfo($user, $cluster)
    {
        $extensions = $this->fetchGalaxyClusters($user, array('conditions' => array('extends_uuid' => $cluster['GalaxyCluster']['uuid'])));
        $cluster['GalaxyCluster']['extended_by'] = $extensions;
        return $cluster;
    }

    public function attachExtendFromInfo($user, $cluster)
    {
        if (!empty($cluster['GalaxyCluster']['extends_uuid'])) {
            $extensions = $this->fetchGalaxyClusters($user, array('conditions' => array('uuid' => $cluster['GalaxyCluster']['extends_uuid'])));
            if (!empty($extensions)) {
                $cluster['GalaxyCluster']['extended_from'] = $extensions[0];
            } else {
                $cluster['GalaxyCluster']['extended_from'] = array();
            }
        }
        return $cluster;
    }

    // receive a full galaxy and add all new clusters, update existing ones contained in the new galaxy, cull old clusters that are removed from the galaxy
    public function update($id, $galaxy)
    {
        $existingClusters = $this->find('all', array(
            'conditions' => array('GalaxyCluster.galaxy_id' => $id),
            'recursive' => -1,
        ));
        foreach ($galaxy['values'] as $cluster) {
            $oldCluster = false;
            if (!empty($existingClusters)) {
                foreach ($existingClusters as $k => $existingCluster) {
                    if ($existingCluster['GalaxyCluster']['value'] == $cluster['value']) {
                        $oldCluster = true;
                        if ($cluster['description'] != $existingCluster['GalaxyCluster']['description']) {
                            $existingCluster['GalaxyCluster']['description'] = $cluster['description'];
                            $this->GalaxyElement->deleteAll('galaxy_cluster_id' == $existingCluster['GalaxyCluster']['id']);
                            $this->save($existingCluster);
                            $template = array('galaxy_cluster_id' => $this->id);
                            $toSave = array();
                            foreach ($cluster as $key => $value) {
                                if (in_array($key, array('value', 'description'))) {
                                    continue;
                                }
                                $tosave[] = array_merge($template, array('key' => $key, 'value' => $value));
                            }
                            $this->GalaxyElement->saveMany($toSave);
                        }
                        unset($existingClusters[$k]);
                    }
                }
            }
            if (!$oldCluster) {
                $newCluster = array_intersect_key($cluster, array_flip(array('value', 'description')));
                $newCluster['galaxy_id'] = $id;
                $newCluster['type'] = $galaxy['type'];
                $newCluster['collection_uuid'] = $newCluster['uuid'];
                $toSave[] = $newCluster;
            }
            $final = array();
            if (!empty($existingCluster)) {
                $fieldsToUpdate = array('description', '');
                $final = $existingCluster;
            }
        }
        $this->saveMany($toSave);
        // Let's retrieve the full list of clusters we have for the given galaxy and pass it to the element system
        $existingClusters = $this->find('all', array(
                'conditions' => array('GalaxyCluster.galaxy_id'),
                'contain' => array('GalaxyElement'/*, 'GalaxyReference'*/)
        ));
        $this->GalaxyElement->update($id, $existingClusters, $galaxy['values']);
    }

    /* Return a list of all tags associated with the cluster specific cluster within the galaxy (or all clusters if $clusterValue is false)
     * The counts are restricted to the event IDs that the user is allowed to see.
    */
    public function getTags($galaxyType, $clusterValue = false, $user)
    {
        $this->Event = ClassRegistry::init('Event');
        $event_ids = $this->Event->fetchEventIds($user, false, false, false, true);
        $tags = $this->Event->EventTag->Tag->find('list', array(
                'conditions' => array('name LIKE' => 'misp-galaxy:' . $galaxyType . '="' . ($clusterValue ? $clusterValue : '%') .'"'),
                'fields' => array('name', 'id'),
        ));
        $this->Event->EventTag->virtualFields['tag_count'] = 'COUNT(id)';
        $tagCounts = $this->Event->EventTag->find('list', array(
                'conditions' => array('EventTag.tag_id' => array_values($tags), 'EventTag.event_id' => $event_ids),
                'fields' => array('EventTag.tag_id', 'EventTag.tag_count'),
                'group' => array('EventTag.tag_id')
        ));
        foreach ($tags as $k => $v) {
            if (isset($tagCounts[$v])) {
                $tags[$k] = array('count' => $tagCounts[$v], 'tag_id' => $v);
            } else {
                unset($tags[$k]);
            }
        }
        return $tags;
    }

    /* Fetch a cluster along with all elements and the galaxy it belongs to
     *   - In the future, once we move to galaxy 2.0, pass a user along for access control
     *   - maybe in the future remove the galaxy itself once we have logos with each galaxy
    */
    public function getCluster($name, $user)
    {
        if (isset($this->__clusterCache[$name])) {
            return $this->__clusterCache[$name];
        }
        $conditions = $this->buildConditions($user);
        if (is_numeric($name)) {
            $conditions['AND'] = array('GalaxyCluster.id' => $name);
        } else {
            $conditions['AND'] = array('LOWER(GalaxyCluster.tag_name)' => strtolower($name));
        }

        $cluster = $this->find('first', array(
            'conditions' => $conditions,
            'contain' => array('Galaxy', 'GalaxyElement')
        ));

        if (!empty($cluster)) {
            $cluster = $this->postprocess($cluster);
        }
        if (!empty($cluster) && $cluster['GalaxyCluster']['default']) { // only cache default clusters
            $this->__clusterCache[$name] = $cluster;
        }
        return $cluster;
    }

    public function getClusters($names, $user, $postProcess=true)
    {
        $conditions = $this->buildConditions($user);
        if (count(array_filter($names, 'is_numeric' )) === count($names)) { // all elements are numeric
            $conditions['AND'] = array('GalaxyCluster.id' => $names);
        } else {
            $names = array_map('strtolower', $names);
            $conditions['AND'] = array('LOWER(GalaxyCluster.tag_name)' => $names);
        }

        $clusters = $this->find('all', array(
            'conditions' => $conditions,
            'contain' => array('Galaxy', 'GalaxyElement')
        ));

        if (!empty($clusters) && $postProcess) {
            $clusters = $this->postprocess($clusters);
        }

        return $clusters;
    }

    public function buildConditions($user)
    {
        $this->Event = ClassRegistry::init('Event');
        $conditions = array();
        if (!$user['Role']['perm_site_admin']) {
            $sgids = $this->Event->cacheSgids($user, true);
            $conditions['AND']['OR'] = array(
                'GalaxyCluster.org_id' => $user['org_id'],
                array(
                    'AND' => array(
                        'GalaxyCluster.distribution >' => 0,
                        'GalaxyCluster.distribution <' => 4
                    ),
                ),
                array(
                    'AND' => array(
                        'GalaxyCluster.sharing_group_id' => $sgids,
                        'GalaxyCluster.distribution' => 4
                    )
                )
            );
        }
        return $conditions;
    }

    // very flexible, it's basically a replacement for find, with the addition that it restricts access based on user
    // options:
    //     fields
    //     contain
    //     conditions
    //     group
    public function fetchGalaxyClusters($user, $options, $full=false)
    {
        $params = array(
            'conditions' => $this->buildConditions($user),
            'recursive' => -1
        );
        if ($full) {
            $params['contain'] = array(
                'Galaxy',
                'GalaxyElement',
                'GalaxyClusterRelation' => array('GalaxyClusterRelationTag' => array('Tag'), 'SharingGroup'),
                'TargettingClusterRelation' => array('GalaxyClusterRelationTag' => array('Tag'), 'SharingGroup'),
                'Orgc',
                'Org',
                'SharingGroup'
            );
        }
        if (!empty($options['contain'])) {
            $params['contain'] = $options['contain'];
        }
        if (isset($options['fields'])) {
            $params['fields'] = $options['fields'];
        }
        if (isset($options['conditions'])) {
            $params['conditions']['AND'][] = $options['conditions'];
        }
        if (isset($options['group'])) {
            $params['group'] = empty($options['group']) ? $options['group'] : false;
        }
        if (isset($options['page'])) {
            $params['page'] = $options['page'];
        }
        if (isset($options['limit'])) {
            $params['limit'] = $options['limit'];
        }
        $clusters = $this->find('all', $params);
        foreach ($clusters as $i => $cluster) {
            $clusters[$i] = $this->GalaxyClusterRelation->massageRelationTag($clusters[$i]);
        }
        return $clusters;
    }

    public function restSearch($user, $returnFormat, $filters, $paramsOnly=false)
    {
        if (!isset($this->validFormats[$returnFormat][1])) {
            throw new NotFoundException('Invalid output format.');
        }
        App::uses($this->validFormats[$returnFormat][1], 'Export');
        $exportTool = new $this->validFormats[$returnFormat][1]();
        $conditions = $this->buildFilterConditions($user, $filters);
        $params = array(
            'conditions' => $conditions,
        );

        if (isset($filters['limit'])) {
            $params['limit'] = $filters['limit'];
            if (!isset($filters['page'])) {
                $filters['page'] = 1;
            }
        }
        if (isset($filters['page'])) {
            $params['page'] = $filters['page'];
        }

        $default_cluster_memory_coefficient = 80;
        $params['full'] = false;
        if (!empty($filters['full'])) {
            $params['full'] = $filters['full'];
            $filters['minimal'] = false;
            $default_cluster_memory_coefficient = 1;
        }
        if (!empty($filters['minimal'])) {
            $default_cluster_memory_coefficient = 100;
            $params['fields'] = array('uuid', 'version');
        }

        if ($paramsOnly) {
            return $params;
        }
        if (method_exists($exportTool, 'modify_params')) {
            $params = $exportTool->modify_params($user, $params);
        }
        $exportToolParams = array(
            'user' => $user,
            'params' => $params,
            'returnFormat' => $returnFormat,
            'scope' => 'GalaxyCluster',
            'filters' => $filters
        );
        if (!empty($exportTool->additional_params)) {
            $params = array_merge_recursive(
                $params,
                $exportTool->additional_params
            );
        }
        
        $tmpfile = tmpfile();
        fwrite($tmpfile, $exportTool->header($exportToolParams));
        if (empty($params['limit'])) {
            $memory_in_mb = $this->convert_to_memory_limit_to_mb(ini_get('memory_limit'));
            $memory_scaling_factor = $default_cluster_memory_coefficient / 10;
            $params['limit'] = intval($memory_in_mb * $memory_scaling_factor);
            $params['page'] = 1;
        }
        $this->__iteratedFetch($user, $params, $tmpfile, $exportTool, $exportToolParams, $elementCounter);
        fwrite($tmpfile, $exportTool->footer($exportToolParams));
        fseek($tmpfile, 0);
        if (fstat($tmpfile)['size']) {
            $final = fread($tmpfile, fstat($tmpfile)['size']);
        } else {
            $final = '';
        }
        fclose($tmpfile);
        return $final;
    }

    private function __iteratedFetch($user, &$params, &$tmpfile, $exportTool, $exportToolParams, &$elementCounter = 0)
    {
        $params['limit'] = 10; // FIXME: Actually use an interated fetch
        $results = $this->fetchGalaxyClusters($user, $params, $full=$params['full']);
        $params['page'] += 1;
        $i = 0;
        $temp = '';
        foreach ($results as $cluster) {
            $elementCounter++;
            $handlerResult = $exportTool->handler($cluster, $exportToolParams);
            $temp .= $handlerResult;
            if ($handlerResult !== '') {
                if ($i != count($results) -1) {
                    $temp .= $exportTool->separator($exportToolParams);
                }
            }
            $i++;
        }
        fwrite($tmpfile, $temp);
        return true;
    }

    public function buildFilterConditions($user, $filters)
    {
        $conditions = array();
        if (isset($filters['org_id'])) {
            $this->Organisation = ClassRegistry::init('Organisation');
            if (!is_array($filters['org_id'])) {
                $filters['org_id'] = array($filters['org_id']);
            }
            foreach ($filters['org_id'] as $k => $org_id) {
                if (Validation::uuid($org_id)) {
                    $org = $this->Organisation->find('first', array('conditions' => array('Organisation.uuid' => $org_id), 'recursive' => -1, 'fields' => array('Organisation.id')));
                    if (empty($org)) {
                        $filters['org_id'][$k] = -1;
                    } else {
                        $filters['org_id'][$k] = $org['Organisation']['id'];
                    }
                }
            }
            $conditions['GalaxyCluster.org_id'] = $filters['org_id'];
        }
        if (isset($filters['orgc_id'])) {
            $this->Organisation = ClassRegistry::init('Organisation');
            if (!is_array($filters['orgc_id'])) {
                $filters['orgc_id'] = array($filters['orgc_id']);
            }
            foreach ($filters['orgc_id'] as $k => $orgc_id) {
                if (Validation::uuid($orgc_id)) {
                    $org = $this->Organisation->find('first', array('conditions' => array('Organisation.uuid' => $orgc_id), 'recursive' => -1, 'fields' => array('Organisation.id')));
                    if (empty($org)) {
                        $filters['orgc_id'][$k] = -1;
                    } else {
                        $filters['orgc_id'][$k] = $org['Organisation']['id'];
                    }
                }
            }
            $conditions['GalaxyCluster.orgc_id'] = $filters['orgc_id'];
        }

        if (isset($filters['galaxy_uuid'])) {
            $galaxy = $this->Galaxy->find('first', array(
                'recursive' => -1,
                'conditions' => array('Galaxy.uuid' => $filters['galaxy_uuid']),
                'fields' => array('uuid', 'id')
            ));
            if (!empty($galaxy)) {
                $filters['galaxy_id'] = $galaxy[0]['id'];
            } else {
                $filters['galaxy_id'] = -1;
            }
        }

        $simpleParams = array(
            'id', 'uuid', 'galaxy_id', 'version', 'distribution', 'tag',
        );
        foreach ($simpleParams as $k => $simpleParam) {
            if (isset($filters[$simpleParam])) {
                $conditions["GalaxyCluster.${$simpleParam}"] = $filters[$simpleParam];
            }
        }

        if (isset($filters['custom'])) {
            $conditions['GalaxyCluster.default'] = !$filters['custom'];
        }
        return $conditions;
    }

    /**
     * @param array $events
     * @param bool $replace
     * @return array
     */
    public function attachClustersToEventIndex($user, array $events, $replace = false)
    {
        $clusterTagNames = array();
        foreach ($events as $event) {
            foreach ($event['EventTag'] as $k2 => $eventTag) {
                if (substr($eventTag['Tag']['name'], 0, strlen('misp-galaxy:')) === 'misp-galaxy:') {
                    $clusterTagNames[] = $eventTag['Tag']['name'];
                }
            }
        }

        $clusters = $this->getClusters($clusterTagNames, $user, false);

        $clustersByTagName = array();
        foreach ($clusters as $cluster) {
            $clustersByTagName[strtolower($cluster['GalaxyCluster']['tag_name'])] = $cluster;
        }

        foreach ($events as $k => $event) {
            foreach ($event['EventTag'] as $k2 => $eventTag) {
                $tagName = strtolower($eventTag['Tag']['name']);
                if (isset($clustersByTagName[$tagName])) {
                    $cluster = $this->postprocess($clustersByTagName[$tagName], $eventTag['Tag']['id']);
                    $cluster['GalaxyCluster']['tag_id'] = $eventTag['Tag']['id'];
                    $cluster['GalaxyCluster']['local'] = $eventTag['local'];
                    $events[$k]['GalaxyCluster'][] = $cluster['GalaxyCluster'];
                    if ($replace) {
                        unset($events[$k]['EventTag'][$k2]);
                    }
                }
            }
        }
        return $events;
    }

    /**
     * @param array $cluster
     * @param int|null $tagId
     * @return array
     */
    private function postprocess(array $cluster, $tagId = null)
    {
        if (isset($cluster['Galaxy'])) {
            $cluster['GalaxyCluster']['Galaxy'] = $cluster['Galaxy'];
            unset($cluster['Galaxy']);
        }

        $elements = array();
        foreach ($cluster['GalaxyElement'] as $element) {
            if (!isset($elements[$element['key']])) {
                $elements[$element['key']] = array($element['value']);
            } else {
                $elements[$element['key']][] = $element['value'];
            }
        }
        unset($cluster['GalaxyElement']);
        $cluster['GalaxyCluster']['meta'] = $elements;

        if ($tagId) {
            $cluster['GalaxyCluster']['tag_id'] = $tagId;
        } else {
            $this->Tag = ClassRegistry::init('Tag');
            $tag_id = $this->Tag->find(
                'first',
                array(
                    'conditions' => array(
                        'LOWER(Tag.name)' => strtolower($cluster['GalaxyCluster']['tag_name'])
                    ),
                    'recursive' => -1,
                    'fields' => array('Tag.id')
                )
            );
            if (!empty($tag_id)) {
                $cluster['GalaxyCluster']['tag_id'] = $tag_id['Tag']['id'];
            }
        }

        return $cluster;
    }

    public function getClusterTagsFromMeta($galaxyElements, $user)
    {
        // AND operator between cluster metas
        $tmpResults = array();
        foreach ($galaxyElements as $galaxyElementKey => $galaxyElementValue) {
            $tmpResults[] = array_values($this->GalaxyElement->find('list', array(
                'conditions' => array(
                    'key' => $galaxyElementKey,
                    'value' => $galaxyElementValue,
                ),
                'fields' => array('galaxy_cluster_id'),
                'recursive' => -1
            )));
        }
        $clusterTags = array();
        if (!empty($tmpResults)) {
            // Get all Clusters matching all conditions
            $matchingClusters = $tmpResults[0];
            array_shift($tmpResults);
            foreach ($tmpResults as $tmpResult) {
                $matchingClusters = array_intersect($matchingClusters, $tmpResult);
            }
    
            $clusterTags = $this->find('list', array(
                'conditions' => array('id' => $matchingClusters),
                'fields' => array('GalaxyCluster.tag_name'),
                'recursive' => -1
            ));
            // TODO: Apply ACL
        }
        return array_values($clusterTags);
    }

    public function uploadClusterToServer($cluster, $server, $HttpSocket, $user)
    {
        $this->Server = ClassRegistry::init('Server');
        $this->Log = ClassRegistry::init('Log');
        $push = $this->Server->checkVersionCompatibility($server['Server']['id'], false, $HttpSocket);
        if (empty($push['canPush']) && empty($push['canPushGalaxyCluster'])) {
            return 'The remote user is not a sightings user - the upload of the galaxy clusters has been blocked.';
        }
        $updated = null;
        $newLocation = $newTextBody = '';
        $result = $this->__executeRestfulGalaxyClusterToServer($cluster, $server, null, $newLocation, $newTextBody, $HttpSocket, $user);
        if ($result !== true) {
            return $result;
        }
        if (strlen($newLocation)) { // HTTP/1.1 302 Found and Location: http://<newLocation>
            $result = $this->__executeRestfulGalaxyClusterToServer($cluster, $server, $newLocation, $newLocation, $newTextBody, $HttpSocket, $user);
            if ($result !== true) {
                return $result;
            }
        }
        $uploadFailed = false;
        try {
            $json = json_decode($newTextBody, true);
        } catch (Exception $e) {
            $uploadFailed = true;
        }
        if (!is_array($json) || $uploadFailed) {
            $this->Log->createLogEntry($user, 'push', 'GalaxyCluster', $cluster['GalaxyCluster']['id'], 'push', $newTextBody);
        }
        return 'Success';
    }

    private function __executeRestfulGalaxyClusterToServer($cluster, $server, $resourceId, &$newLocation, &$newTextBody, $HttpSocket, $user)
    {
        $result = $this->restfulGalaxyClusterToServer($cluster, $server, $resourceId, $newLocation, $newTextBody, $HttpSocket);
        if (is_numeric($result)) {
            $error = $this->__resolveErrorCode($result, $cluster, $server, $user);
            if ($error) {
                return $error . ' Error code: ' . $result;
            }
        }
        return true;
    }

    public function restfulGalaxyClusterToServer($cluster, $server, $urlPath, &$newLocation, &$newTextBody, $HttpSocket = null)
    {
        $url = $server['Server']['url'];
        $HttpSocket = $this->setupHttpSocket($server, $HttpSocket);
        $request = $this->setupSyncRequest($server);
        $scope = 'galaxies/pushCluster';
        $uri = $url . '/' . $scope;
        $clusters = array($cluster);
        $data = json_encode($clusters);
        if (!empty(Configure::read('Security.sync_audit'))) {
            $pushLogEntry = sprintf(
                "==============================================================\n\n[%s] Pushing Galaxy Cluster #%d to Server #%d:\n\n%s\n\n",
                date("Y-m-d H:i:s"),
                $cluster['GalaxyCluster']['id'],
                $server['Server']['id'],
                $data
            );
            file_put_contents(APP . 'files/scripts/tmp/debug_server_' . $server['Server']['id'] . '.log', $pushLogEntry, FILE_APPEND);
        }
        $response = $HttpSocket->post($uri, $data, $request);
        return $this->__handleRestfulGalaxyClusterToServerResponse($response, $newLocation, $newTextBody);
    }

    private function __handleRestfulGalaxyClusterToServerResponse($response, &$newLocation, &$newTextBody)
    {
        switch ($response->code) {
            case '200': // 200 (OK) + entity-action-result
                if ($response->isOk()) {
                    $newTextBody = $response->body();
                    return true;
                } else {
                    try {
                        $jsonArray = json_decode($response->body, true);
                    } catch (Exception $e) {
                        return true;
                    }
                    return $jsonArray['name'];
                }
                // no break
            case '302': // Found
                $newLocation = $response->headers['Location'];
                $newTextBody = $response->body();
                return true;
            case '404': // Not Found
                $newLocation = $response->headers['Location'];
                $newTextBody = $response->body();
                return 404;
            case '405':
                return 405;
            case '403': // Not authorised
                return 403;
        }
    }

    private function __resolveErrorCode($code, &$cluster, &$server, $user)
    {
        $this->Log = ClassRegistry::init('Log');
        $error = false;
        switch ($code) {
            case 403:
                return 'The distribution level of the cluster blocks it from being pushed.';
            case 405:
                $error = 'The sync user on the remote instance does not have the required privileges to handle this cluster.';
                break;
        }
        if ($error) {
            $newTextBody = 'Uploading GalaxyCluster (' . $cluster['GalaxyCluster']['id'] . ') to Server (' . $server['Server']['id'] . ')';
            $this->Log->createLogEntry($user, 'push', 'GalaxyCluster', $cluster['GalaxyCluster']['id'], 'push', $newTextBody);
        }
        return $error;
    }

    public function attachClusterToRelations($user, $cluster)
    {
        if (!empty($cluster['GalaxyClusterRelation'])) {
            foreach ($cluster['GalaxyClusterRelation'] as $k => $relation) {
                $conditions = array('conditions' => array('GalaxyCluster.uuid' => $relation['referenced_galaxy_cluster_uuid']));
                $relatedCluster = $this->fetchGalaxyClusters($user, $conditions, false);
                if (!empty($relatedCluster)) {
                    $cluster['GalaxyClusterRelation'][$k]['GalaxyCluster'] = $relatedCluster[0]['GalaxyCluster'];
                }
            }
        }
        if (!empty($cluster['TargettingClusterRelation'])) {
            foreach ($cluster['TargettingClusterRelation'] as $k => $relation) {
                $conditions = array('conditions' => array('GalaxyCluster.uuid' => $relation['galaxy_cluster_uuid']));
                $relatedCluster = $this->fetchGalaxyClusters($user, $conditions, false);
                if (!empty($relatedCluster)) {
                    $cluster['TargettingClusterRelation'][$k]['GalaxyCluster'] = $relatedCluster[0]['GalaxyCluster'];
                }
            }
        }
        return $cluster;
    }

    public function attachTargettingRelations($user, $cluster)
    {
        $targettingRelations = $this->GalaxyClusterRelation->fetchRelations($user, array(
            'conditions' => array(
                'referenced_galaxy_cluster_uuid' => $cluster['GalaxyCluster']['uuid']
            ),
            'contain' => array('GalaxyClusterRelationTag' => 'Tag')
        ));
        if (!empty($targettingRelations)) {
            foreach ($targettingRelations as $k => $relation) {
                if (!empty($relation['GalaxyClusterRelationTag'])) {
                    $relation['GalaxyClusterRelation']['Tag'] = $relation['GalaxyClusterRelationTag'][0]['Tag'];
                }
                $cluster['TargettingClusterRelation'][] = $relation['GalaxyClusterRelation'];
            }
        }
        return $cluster;
    }
}
