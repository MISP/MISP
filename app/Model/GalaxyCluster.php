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
        'GalaxyClusterRelation' => array('dependent' => true),
    );

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        if (!isset($this->data['GalaxyCluster']['description'])) {
            $this->data['GalaxyCluster']['description'] = '';
        }
        return true;
    }

    public function afterFind($results, $primary = false)
    {
        foreach ($results as $k => $result) {
            if (isset($results[$k]['GalaxyCluster']['authors'])) {
                $results[$k]['GalaxyCluster']['authors'] = json_decode($results[$k]['GalaxyCluster']['authors'], true);
            }
        }
        return $results;
    }

    public function beforeDelete($cascade = true)
    {
        $this->GalaxyElement->deleteAll(array('GalaxyElement.galaxy_cluster_id' => $this->id));
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
        $cluster['GalaxyCluster']['org_id'] = $user['org_id'];
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

    public function importClusters($user, $galaxy, $clusters, $updateExisting=false)
    {
        $importResult = array('success' => false, 'imported' => 0, 'ignored' => 0);
        foreach ($clusters as $k => $cluster) {
            if ($cluster['GalaxyCluster']['distribution'] != 4) {
                $cluster['GalaxyCluster']['sharing_group_id'] = null;
            }
            $cluster['GalaxyCluster']['galaxy_id'] = $galaxy['Galaxy']['id'];
            $saveResult = $this->saveCluster($user, $cluster, $fromPull=false, $allowEdit=$updateExisting);
            if ($saveResult) {
                $importResult['imported'] += 1;
            } else {
                $importResult['ignored'] += 1;
            }
        }
        if ($importResult['imported'] > 0) {
            $importResult['success'] = true;
        }
        return $importResult;
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
                'GalaxyElement',
                'GalaxyClusterRelation' => array('GalaxyClusterRelationTag' => array('Tag')),
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
        $clusters = $this->find('all', $params);
        foreach ($clusters as $i => $cluster) {
            if ($cluster['GalaxyCluster']['distribution'] != 4) {
                unset($clusters[$i]['SharingGroup']);
            }
            // if ($cluster['GalaxyCluster']['org_id'] == 0) {
            //     unset($clusters[$i]['Org']);
            // }
            // if ($cluster['GalaxyCluster']['orgc_id'] == 0) {
            //     unset($clusters[$i]['Orgc']);
            // }
            $clusters[$i] = $this->GalaxyClusterRelation->massageRelationTag($clusters[$i]);
        }
        return $clusters;
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

    public function attachClusterToRelations($user, $cluster)
    {
        if (!empty($cluster['GalaxyClusterRelation'])) {
            foreach ($cluster['GalaxyClusterRelation'] as $k => $relation) {
                $conditions = array('conditions' => array('GalaxyCluster.id' => $relation['referenced_galaxy_cluster_id']));
                $relatedCluster = $this->fetchGalaxyClusters($user, $conditions, false);
                if (!empty($relatedCluster)) {
                    $cluster['GalaxyClusterRelation'][$k]['GalaxyCluster'] = $relatedCluster[0]['GalaxyCluster'];
                }
            }
        }
        if (!empty($cluster['ReferencingGalaxyClusterRelation'])) {
            foreach ($cluster['ReferencingGalaxyClusterRelation'] as $k => $relation) {
                $conditions = array('conditions' => array('GalaxyCluster.id' => $relation['galaxy_cluster_id']));
                $relatedCluster = $this->fetchGalaxyClusters($user, $conditions, false);
                if (!empty($relatedCluster)) {
                    $cluster['ReferencingGalaxyClusterRelation'][$k]['GalaxyCluster'] = $relatedCluster[0]['GalaxyCluster'];
                }
            }
        }
        return $cluster;
    }

    public function attachReferencingRelations($user, $cluster)
    {
        $referencingRelations = $this->GalaxyClusterRelation->fetchRelations($user, array('conditions' => array(
            'referenced_galaxy_cluster_id' => $cluster['GalaxyCluster']['id']
        )));
        if (!empty($referencingRelations)) {
            foreach ($referencingRelations as $k => $relation) {
                $cluster['ReferencingGalaxyClusterRelation'][] = $relation['GalaxyClusterRelation'];
            }
        }
        return $cluster;
    }
}
