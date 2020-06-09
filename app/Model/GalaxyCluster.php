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
        if (!isset($this->data['GalaxyCluster']['authors']) || is_null($this->data['GalaxyCluster']['authors'])) {
            $this->data['GalaxyCluster']['authors'] = '';
        } elseif (is_array($this->data['GalaxyCluster']['authors'])) {
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

            if (!empty($results[$k]['GalaxyClusterRelation'])) {
                foreach ($results[$k]['GalaxyClusterRelation'] as $i => $relation) {
                    if (isset($relation['distribution']) && $relation['distribution'] != 4) {
                        unset($results[$k]['GalaxyClusterRelation'][$i]['SharingGroup']);
                    }
                }
            }
        }
        return $results;
    }

    public function afterSave($created, $options = array())
    {
        // Update all relations IDs that are unkown but saved (UUID is set)
        parent::afterSave($created, $options);
        $cluster = $this->data['GalaxyCluster'];
        $this->GalaxyClusterRelation->updateAll(
            array('GalaxyClusterRelation.referenced_galaxy_cluster_id' => $cluster['id']),
            array('GalaxyClusterRelation.referenced_galaxy_cluster_uuid' => $cluster['uuid'])
        );
    }

    public function afterDelete()
    {
        // Remove all relations IDs now that the cluster is unkown
        $cluster = $this->data['GalaxyCluster'];
        $this->GalaxyClusterRelation->updateAll(
            array('GalaxyClusterRelation.referenced_galaxy_cluster_id' => 0),
            array('GalaxyClusterRelation.referenced_galaxy_cluster_uuid' => $cluster['uuid'])
        );
    }

    public function beforeDelete($cascade = true)
    {
        $this->GalaxyElement->deleteAll(array('GalaxyElement.galaxy_cluster_id' => $this->id));
        $this->GalaxyClusterRelation->deleteAll(array('GalaxyClusterRelation.galaxy_cluster_uuid' => $this->uuid));
    }

    public function arrangeDataForExport($cluster)
    {
        $models = array('Galaxy', 'GalaxyElement', 'GalaxyClusterRelation', 'Org', 'Orgc', 'TargettingClusterRelation');
        foreach ($models as $model) {
            $cluster['GalaxyCluster'][$model] = $cluster[$model];
            unset($cluster[$model]);
        }
        return $cluster;
    }

    // Respecting ACL, save a cluster, its elements and set correct fields
    public function saveCluster($user, $cluster, $allowEdit=false)
    {
        if (!$user['Role']['perm_galaxy_editor'] && !$user['Role']['perm_site_admin']) {
            return false;
        }
        $errors = array();
        $galaxy = $this->Galaxy->find('first', array('conditions' => array(
            'id' => $cluster['GalaxyCluster']['galaxy_id']
        )));
        if (empty($galaxy)) {
            $errors[] = __('Galaxy not found');
            return $errors;
        } else {
            $galaxy = $galaxy['Galaxy'];
        }
        unset($cluster['GalaxyCluster']['id']);
        if (isset($cluster['GalaxyCluster']['uuid'])) {
            // check if the uuid already exists
            $existingGalaxyCluster = $this->find('first', array('conditions' => array('GalaxyCluster.uuid' => $cluster['GalaxyCluster']['uuid'])));
            if ($existingGalaxyCluster) {
                if ($existingGalaxyCluster['GalaxyCluster']['galaxy_id'] != $galaxy['id']) { // cluster already exists in another galaxy
                    $errors[] = __('Cluster already exists in another galaxy');
                return $errors;
                }
                if (!$existingGalaxyCluster['GalaxyCluster']['default']) {
                    $errors[] = __('Edit not allowed on default clusters');
                    return $errors;
                }
                if (!$allowEdit) {
                    $errors[] = __('Edit not allowed');
                    return $errors;
                }
                $errors = $this->editCluster($user, $cluster);
                return $errors;
            }
        } else {
            $cluster['GalaxyCluster']['uuid'] = CakeText::uuid();
        }
        $forkedCluster = $this->find('first', array('conditions' => array('GalaxyCluster.uuid' => $cluster['GalaxyCluster']['extends_uuid'])));
        if (!empty($forkedCluster) && $forkedCluster['GalaxyCluster']['galaxy_id'] != $galaxy['id']) {
            $errors[] = __('Cluster forks always have to belong to the same galaxy as the parent');
            return $errors;
        }
        $cluster['GalaxyCluster']['org_id'] = $user['Organisation']['id'];
        if (!isset($cluster['GalaxyCluster']['orgc_id'])) {
            if (isset($cluster['Orgc']['uuid'])) {
                $orgc_id = $this->Orgc->find('first', array('conditions' => array('Orgc.uuid' => $cluster['Orgc']['uuid']), 'fields' => array('Orgc.id'), 'recursive' => -1));
            } else {
                $orgc_id = $user['org_id'];
            }
            $cluster['GalaxyCluster']['orgc_id'] = $orgc_id;
        }

        if ($user['Role']['perm_sync']) {
            if (isset($cluster['GalaxyCluster']['distribution']) && $cluster['GalaxyCluster']['distribution'] == 4 && !$this->SharingGroup->checkIfAuthorised($user, $cluster['GalaxyCluster']['sharing_group_id'])) {
                $errors[] = __('The sync user has to have access to the sharing group in order to be able to edit it');
            return $errors;
            }
        }

        $cluster['GalaxyCluster']['type'] = $galaxy['type'];
        if (!isset($cluster['GalaxyCluster']['version'])) {
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

            if (!empty($cluster['GalaxyCluster']['GalaxyElement'])) {
                $elementsToSave = array();
                foreach ($cluster['GalaxyCluster']['GalaxyElement'] as $element) { // transform cluster into Galaxy meta format
                    $elementsToSave[$element['key']][] = $element['value'];
                }
                $this->GalaxyElement->updateElements(-1, $savedCluster['GalaxyCluster']['id'], $elementsToSave);
            }
            if (!empty($cluster['GalaxyCluster']['GalaxyClusterRelation'])) {
                $this->GalaxyClusterRelation->saveRelations($user, $cluster['GalaxyCluster'], $cluster['GalaxyCluster']['GalaxyClusterRelation'], $capture=true);
            }
        } else {
            foreach($this->validationErrors as $validationError) {
                $errors[] = $validationError[0];
            }
        }
        return $errors;
    }

    public function editCluster($user, $cluster, $fieldList = array(), $deleteOldElements=true)
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
                $cluster['GalaxyCluster']['version'] = $date->getTimestamp();
                $cluster['GalaxyCluster']['default'] = false;
                if (empty($fieldList)) {
                    $fieldList = array('value', 'description', 'version', 'source', 'authors', 'distribution', 'sharing_group_id', 'default');
                }
                $saveSuccess = $this->save($cluster, array('fieldList' => $fieldList));
                if ($saveSuccess) {
                    if (!empty($cluster['GalaxyCluster']['GalaxyElement'])) {
                        $elementsToSave = array();
                        foreach ($cluster['GalaxyCluster']['GalaxyElement'] as $element) { // transform cluster into Galaxy meta format
                            $elementsToSave[$element['key']][] = $element['value'];
                        }
                        $this->GalaxyElement->updateElements($cluster['GalaxyCluster']['id'], $cluster['GalaxyCluster']['id'], $elementsToSave, $delete=$deleteOldElements);
                    }
                    if (!empty($cluster['GalaxyCluster']['GalaxyClusterRelation'])) {
                        $this->GalaxyClusterRelation->saveRelations($user, $cluster['GalaxyCluster'], $cluster['GalaxyCluster']['GalaxyClusterRelation'], $capture=true, $force=true);
                    }

                } else {
                    foreach($this->validationErrors as $validationError) {
                        $errors[] = $validationError[0];
                    }
                }
            }
        }
        return $errors;
    }

    public function unsetFieldsForExport($clusters)
    {
        foreach ($clusters as $k => $cluster) {
            unset($clusters[$k]['GalaxyCluster']['galaxy_id']);
            $modelsToUnset = array('GalaxyCluster', 'Galaxy', 'Org', 'Orgc');
            forEach($modelsToUnset as $modelName) {
                unset($clusters[$k][$modelName]['id']);
            }
            $modelsToUnset = array('GalaxyClusterRelation', 'TargettingClusterRelation');
            forEach($modelsToUnset as $modelName) {
                forEach($cluster[$modelName] as $i => $relation) {
                    unset($clusters[$k][$modelName][$i]['id']);
                    unset($clusters[$k][$modelName][$i]['galaxy_cluster_id']);
                    unset($clusters[$k][$modelName][$i]['referenced_galaxy_cluster_id']);
                    if (isset($relation['Tag'])) {
                        forEach($relation['Tag'] as $j => $tags) {
                            unset($clusters[$k][$modelName][$i]['Tag'][$j]['id']);
                            unset($clusters[$k][$modelName][$i]['Tag'][$j]['org_id']);
                            unset($clusters[$k][$modelName][$i]['Tag'][$j]['user_id']);
                        }
                    }
                }
            }
            forEach($cluster['GalaxyElement'] as $i => $element) {
                unset($clusters[$k]['GalaxyElement'][$i]['id']);
                unset($clusters[$k]['GalaxyElement'][$i]['galaxy_cluster_id']);
            }
        }
        return $clusters;
    }

    /**
     * Gets a cluster then save it.
     *
     * @param $user
     * @param array $cluster Cluster to be saved
     * @param bool $fromPull If the current capture is performed from a PULL sync
     * @param int $orgId The organisation id that should own the cluster
     * @param array $server The server for which to capture is ongoing
     * @return array
     */
    public function captureCluster($user, $cluster, $fromPull=false, $orgId=0, $server=false)
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
        $cluster['GalaxyCluster']['tag_name'] = sprintf('misp-galaxy:%s="%s"', $cluster['GalaxyCluster']['type'], $cluster['GalaxyCluster']['uuid']);
        if (empty($existingGalaxyCluster)) {
            $this->create();
            $saveSuccess = $this->save($cluster);
        } else {
            if ($cluster['GalaxyCluster']['default']) {
                $results['errors'][] = __('Can only save non default clusters');
                $results['failed']++;
                return $results;
            }
            if ($fromPull && !$existingGalaxyCluster['GalaxyCluster']['locked'] && !$server['Server']['internal']) {
                $results['errors'][] = __('Blocked an edit to an cluster that was created locally. This can happen if a synchronised cluster that was created on this instance was modified by an administrator on the remote side.');
                $results['failed']++;
                return $results;
            }
            if ($cluster['GalaxyCluster']['version'] > $existingGalaxyCluster['GalaxyCluster']['version']) {
                $cluster['GalaxyCluster']['id'] = $existingGalaxyCluster['GalaxyCluster']['id'];
                $saveSuccess = $this->save($cluster);
            } else {
                $results['errors'][] = __('Remote version is not newer than local one for cluster (%s)', $cluster['GalaxyCluster']['uuid']);
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

    public function restSearch($user, $returnFormat, $filters, $paramsOnly=false, $jobId = false, &$elementCounter = 0)
    {
        if (!isset($this->validFormats[$returnFormat][1])) {
            throw new NotFoundException('Invalid output format.');
        }
        App::uses($this->validFormats[$returnFormat][1], 'Export');
        $exportTool = new $this->validFormats[$returnFormat][1]();
        $conditions = $this->buildFilterConditions($user, $filters);
        $params = array(
            'conditions' => $conditions,
            'full' => !empty($filters['full']) ? $filters['full'] : (!empty($filters['minimal']) ? !$filters['minimal'] : true),
            'minimal' => !empty($filters['minimal']) ? $filters['minimal'] : (!empty($filters['full']) ? !$filters['full'] : false),
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
        if ($params['full']) {
            $default_cluster_memory_coefficient = 0.5;
        }
        if ($params['minimal']) {
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
        $loop = false;
        if (empty($params['limit'])) {
            $memory_in_mb = $this->convert_to_memory_limit_to_mb(ini_get('memory_limit'));
            $memory_scaling_factor = $default_cluster_memory_coefficient / 10;
            $params['limit'] = intval($memory_in_mb * $memory_scaling_factor);
            $loop = true;
            $params['page'] = 1;
        }
        $this->__iteratedFetch($user, $params, $loop, $tmpfile, $exportTool, $exportToolParams, $elementCounter);
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

    private function __iteratedFetch($user, &$params, &$loop, &$tmpfile, $exportTool, $exportToolParams, &$elementCounter = 0)
    {
        $continue = true;
        while ($continue) {
            $temp = '';
            $results = $this->fetchGalaxyClusters($user, $params, $full=$params['full']);
            if (empty($results)) {
                $loop = false;
                return true;
            }
            if ($elementCounter !== 0 && !empty($results)) {
                $temp .= $exportTool->separator($exportToolParams);
            }
            $params['page'] += 1;
            $i = 0;
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
            if (!$loop) {
                $continue = false;
            }
            fwrite($tmpfile, $temp);
        }
        return true;
    }

    public function buildFilterConditions($user, $filters)
    {
        $conditions = $this->buildConditions($user);
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
            $conditions['AND']['GalaxyCluster.org_id'] = $filters['org_id'];
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
            $conditions['AND']['GalaxyCluster.orgc_id'] = $filters['orgc_id'];
        }

        if (isset($filters['galaxy_uuid'])) {
            $galaxyIds = $this->Galaxy->find('list', array(
                'recursive' => -1,
                'conditions' => array('Galaxy.uuid' => $filters['galaxy_uuid']),
                'fields' => array('id')
            ));
            if (!empty($galaxyIds)) {
                $filters['galaxy_id'] = array_values($galaxyIds);
            } else {
                $filters['galaxy_id'] = -1;
            }
        }

        $simpleParams = array(
            'uuid', 'galaxy_id', 'version', 'distribution', 'type', 'value', 'default', 'extends_uuid', 'tag_name'
        );
        foreach ($simpleParams as $k => $simpleParam) {
            if (isset($filters[$simpleParam])) {
                $conditions['AND']["GalaxyCluster.${simpleParam}"] = $filters[$simpleParam];
            }
        }

        if (isset($filters['custom'])) {
            $conditions['AND']['GalaxyCluster.default'] = !$filters['custom'];
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

    public function getElligibleClustersToPush($user)
    {
        $options = array(
            'conditions' => array(
                'GalaxyCluster.default' => 0,
            ),
            'fields' => array('uuid', 'version')
        );
        $clusters = $this->fetchGalaxyClusters($user, $options, $full=false);
        $clusterUuids = array();
        foreach($clusters as $cluster) {
            $clusterUuids[$cluster['GalaxyCluster']['uuid']] = $cluster['GalaxyCluster']['version'];
        }
        return $clusterUuids;
    }

    public function getElligibleClustersToPull($user)
    {
        $options = array(
            'conditions' => array(
                'GalaxyCluster.default' => 0,
                'GalaxyCluster.locked' => 1,
            ),
            'fields' => array('uuid', 'version')
        );
        $clusters = $this->fetchGalaxyClusters($user, $options, $full=false);
        $clusterUuids = array();
        foreach($clusters as $cluster) {
            $clusterUuids[$cluster['GalaxyCluster']['uuid']] = $cluster['GalaxyCluster']['version'];
        }
        return $clusterUuids;
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
        $cluster = $this->__prepareForPushToServer($cluster, $server);
        if (is_numeric($cluster)) {
            return $cluster;
        }
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

    private function __prepareForPushToServer($cluster, $server)
    {
        if ($cluster['GalaxyCluster']['distribution'] == 4) {
            if (!empty($cluster['SharingGroup']['SharingGroupServer'])) {
                $found = false;
                foreach ($event['SharingGroup']['SharingGroupServer'] as $sgs) {
                    if ($sgs['server_id'] == $server['Server']['id']) {
                        $found = true;
                    }
                }
                if (!$found) {
                    return 403;
                }
            } else if (empty($cluster['SharingGroup']['roaming'])) {
                return 403;
            }
        }
        $this->Event = ClassRegistry::init('Event');
        if ($this->Event->checkDistributionForPush($cluster, $server, 'GalaxyCluster')) {
            $cluster = $this->__updateClusterForSync($cluster, $server);
        } else {
            return 403;
        }
        return $cluster;
    }

    private function __updateClusterForSync($cluster, $server)
    {
        $this->Event = ClassRegistry::init('Event');
        // cleanup the array from things we do not want to expose
        foreach (array('org_id', 'orgc_id', 'id', 'galaxy_id') as $field) {
            unset($cluster['GalaxyCluster'][$field]);
        }
        // Add the local server to the list of instances in the SG
        if (isset($cluster['SharingGroup']) && isset($cluster['SharingGroup']['SharingGroupServer'])) {
            foreach ($cluster['SharingGroup']['SharingGroupServer'] as &$s) {
                if ($s['server_id'] == 0) {
                    $s['Server'] = array(
                        'id' => 0,
                        'url' => $this->Event->__getAnnounceBaseurl(),
                        'name' => $this->Event->__getAnnounceBaseurl()
                    );
                }
            }
        }
        $cluster = $this->__prepareElementsForSync($cluster, $server);
        $cluster = $this->__prepareRelationsForSync($cluster, $server);

        // Downgrade the event from connected communities to community only
        if (!$server['Server']['internal'] && $cluster['GalaxyCluster']['distribution'] == 2) {
            $cluster['GalaxyCluster']['distribution'] = 1;
        }
        return $cluster;
    }

    private function __prepareElementsForSync($cluster, $server)
    {
        if (!empty($cluster['GalaxyElement'])) {
            foreach($cluster['GalaxyElement'] as $k => $element) {
                $cluster['GalaxyElement'][$k] = $this->__updateElementForSync($element, $server);
            }
        }
        return $cluster;
    }

    private function __prepareRelationsForSync($cluster, $server)
    {
        $this->Event = ClassRegistry::init('Event');
        if (!empty($cluster['GalaxyClusterRelation'])) {
            foreach($cluster['GalaxyClusterRelation'] as $k => $relation) {
                $cluster['GalaxyClusterRelation'][$k] = $this->__updateRelationsForSync($relation, $server);
                if (empty($cluster['GalaxyClusterRelation'][$k])) {
                    unset($cluster['GalaxyClusterRelation'][$k]);
                } else {
                    $cluster['GalaxyClusterRelation'][$k] = $this->Event->__removeNonExportableTags($cluster['GalaxyClusterRelation'][$k], 'GalaxyClusterRelation');
                }
            }
            $cluster['GalaxyClusterRelation'] = array_values($cluster['GalaxyClusterRelation']);
        }
        return $cluster;
    }

    private function __updateElementForSync($element, $server)
    {
        unset($element['id']);
        unset($element['galaxy_cluster_id']);
        return $element;
    }

    private function __updateRelationsForSync($relation, $server)
    {
        // do not keep attributes that are private, nor cluster
        if (!$server['Server']['internal'] && $relation['distribution'] < 2) {
            return false;
        }
        // Downgrade the attribute from connected communities to community only
        if (!$server['Server']['internal'] && $relation['distribution'] == 2) {
            $relation['distribution'] = 1;
        }

        // If the attribute has a sharing group attached, make sure it can be transferred
        if ($relation['distribution'] == 4) {
            if (!$server['Server']['internal'] && $this->checkDistributionForPush(array('GalaxyClusterRelation' => $relation), $server, 'GalaxyClusterRelation') === false) {
                return false;
            }
            // Add the local server to the list of instances in the SG
            if (!empty($relation['SharingGroup']['SharingGroupServer'])) {
                foreach ($relation['SharingGroup']['SharingGroupServer'] as &$s) {
                    if ($s['server_id'] == 0) {
                        $s['Server'] = array(
                            'id' => 0,
                            'url' => $this->__getAnnounceBaseurl(),
                            'name' => $this->__getAnnounceBaseurl()
                        );
                    }
                }
            }
        }
        unset($relation['id']);
        unset($relation['galaxy_cluster_id']);
        unset($relation['referenced_galaxy_cluster_id']);
        return $relation;
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

    public function pullGalaxyClusters($user, $server)
    {
        $version = explode('.', $server['Server']['version']);
        if (
            ($version[0] == 2 && $version[1] == 4 && $version[2] < 111) // FIXME: Use correct version
        ) {
            return 0;
        }
        $clusterIds = $this->__getClusterIdListBasedOnPullTechnique($technique, $server, $serverModel);
        $server['Server']['version'] = $this->getRemoteVersion($id);
        $successes = array();
        $fails = array();
        // now process the $clusterIds to pull each of the events sequentially
        if (!empty($clusterIds)) {
            // download each cluster
            foreach ($clusterIds as $k => $clusterId) {
                $this->__pullGalaxyCluster($clusterId, $successes, $fails, $server, $user);
            }
        }
    }

    private function __getClusterIdListBasedOnPullTechnique($technique, $server)
    {
        $this->Server = ClassRegistry::init('Server');
        if ("full" === $technique) {
            $clusterIds = $this->Server->getClusterIdsFromServer($server, $performLocalDelta=false);
            if ($clusterIds === 403) {
                return array('error' => array(1, null));
            } elseif (is_string($clusterIds)) {
                return array('error' => array(2, $clusterIds));
            }
        } elseif ("update" === $technique) {
            $elligibleClusters = $this->GalaxyCluster->getElligibleClustersToPull($user);
            $clusterIds = $this->Server->getClusterIdsFromServer($server, $performLocalDelta=true, $elligibleClusters);
            if ($clusterIds === 403) {
                return array('error' => array(1, null));
            } elseif (is_string($clusterIds)) {
                return array('error' => array(2, $clusterIds));
            }
        } else {
            return array('error' => array(4, null));
        }
        return $clusterIds;
    }

    private function __pullGalaxyCluster($clusterId, &$successes, &$fails, $server, $user)
    {
        $cluster = $eventModel->downloadGalaxyClusterFromServer($clusterId, $server);

        if (!empty($cluster)) {
            $cluster = $this->__updatePulledClusterBeforeInsert($cluster, $server, $user);
            $result = $this->captureCluster($user, $cluster, $fromPull=true, $orgId=$server['Server']['org_id']);
            if ($result['success']) {
                $successes[] = $clusterId;
            } else {
                $fails[$clusterId] = __('Failed because of errors: ') . json_encode($result['errors']);
            }
        } else {
            $fails[$clusterId] = __('failed downloading the galaxy cluster');
        }
        return true;
    }

    private function __updatePulledClusterBeforeInsert($cluster, $server, $user)
    {
        // The cluster came from a pull, so it should be locked and distribution should be adapted.
        $cluster['GalaxyCluster']['locked'] = true;
        if (!isset($cluster['GalaxyCluster']['distribution'])) {
            $cluster['GalaxyCluster']['distribution'] = '1';
        }

        if (empty(Configure::read('MISP.host_org_id')) || !$server['Server']['internal'] || Configure::read('MISP.host_org_id') != $server['Server']['org_id']) {
            switch ($cluster['GalaxyCluster']['distribution']) {
                case 1:
                    $cluster['GalaxyCluster']['distribution'] = 0; // if community only, downgrade to org only after pull
                    break;
                case 2:
                    $cluster['GalaxyCluster']['distribution'] = 1; // if connected communities downgrade to community only
                    break;
            }

            if (!empty($cluster['GalaxyClusterRelation'])) {
                foreach ($cluster['GalaxyClusterRelation'] as $k => $relation) {
                    switch ($relation['distribution']) {
                        case 1:
                            $cluster['GalaxyClusterRelation'][$k]['distribution'] = 0;
                            break;
                        case 2:
                            $cluster['GalaxyClusterRelation'][$k]['distribution'] = 1;
                            break;
                    }
                }
            }
        }
        return $cluster;
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
