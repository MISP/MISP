<?php
App::uses('AppModel', 'Model');

class GalaxyClusterRelation extends AppModel
{
    public $useTable = 'galaxy_cluster_relations';

    public $recursive = -1;

    public $actsAs = array(
            'Containable',
    );

    public $validate = array(
        'referenced_galaxy_cluster_type' => array(
            'stringNotEmpty' => array(
                'rule' => array('stringNotEmpty')
            )
        ),
        'galaxy_cluster_uuid' => array(
            'uuid' => array(
                'rule' => array('custom', '/^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$/'),
                'message' => 'Please provide a valid UUID'
            ),
        ),
        'referenced_galaxy_cluster_uuid' => array(
            'uuid' => array(
                'rule' => array('custom', '/^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$/'),
                'message' => 'Please provide a valid UUID'
            ),
        ),
        'distribution' => array(
            'rule' => array('inList', array('0', '1', '2', '3', '4')),
            'message' => 'Options: Your organisation only, This community only, Connected communities, All communities, Sharing group',
            'required' => true
        )
    );

    public $belongsTo = array(
            'SourceCluster' => array(
                'className' => 'GalaxyCluster',
                'foreignKey' => 'galaxy_cluster_id',
            ),
            'TargetCluster' => array(
                'className' => 'GalaxyCluster',
                'foreignKey' => 'referenced_galaxy_cluster_id',
            ),
            'SharingGroup' => array(
                    'className' => 'SharingGroup',
                    'foreignKey' => 'sharing_group_id'
            ),
    );

    public $hasMany = array(
        'GalaxyClusterRelationTag' => array('dependent' => true),
    );

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        return true;
    }

    public function afterFind($results, $primary = false)
    {
        foreach ($results as $k => $result) {
            if (isset($results[$k]['TargetCluster']) && is_null($results[$k]['TargetCluster']['id'])) {
                $results[$k]['TargetCluster'] = array();
            }
        }
        return $results;
    }

    public function buildConditions($user)
    {
        $this->Event = ClassRegistry::init('Event');
        $conditions = array();
        if (!$user['Role']['perm_site_admin']) {
            $sgids = $this->Event->cacheSgids($user, true);
            $conditions['AND']['OR'] = array(
                array(
                    'AND' => array(
                        'GalaxyClusterRelation.distribution >' => 0,
                        'GalaxyClusterRelation.distribution <' => 4
                    ),
                ),
                array(
                    'AND' => array(
                        'GalaxyClusterRelation.sharing_group_id' => $sgids,
                        'GalaxyClusterRelation.distribution' => 4
                    )
                )
            );
        }
        return $conditions;
    }

    public function fetchRelations($user, $options, $full=false)
    {
        $params = array(
            'conditions' => $this->buildConditions($user),
            'recursive' => -1
        );
        if (!empty($options['contain'])) {
            $params['contain'] = $options['contain'];
        } elseif($full) {
            $params['contain'] = array('SharingGroup', 'SourceCluster', 'TargetCluster');
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
        $relations = $this->find('all', $params);
        foreach ($relations as $i => $relation) {
            if ($relation['GalaxyClusterRelation']['distribution'] != 4) {
                unset($relation[$i]['SharingGroup']);
            }
        }
        return $relations;
    }

    public function getExistingRelationships()
    {
        $existingRelationships = $this->find('list', array(
            'recursive' => -1,
            'fields' => array('referenced_galaxy_cluster_type'),
            'group' => array('referenced_galaxy_cluster_type')
        ), false, false);
        return $existingRelationships;
    }

    public function deleteRelations($conditions)
    {
        $this->deleteAll($conditions, false, false);
    }

    // public function addRelations($user, $relations, $capture=false)
    // {
    //     $fieldList = array(
    //         'galaxy_cluster_uuid',
    //         'referenced_galaxy_cluster_uuid',
    //         'referenced_galaxy_cluster_type',
    //         'default',
    //         'distribution',
    //         'sharing_group_id',
    //     );
    //     foreach ($relations as $k => $relation) {
    //         $sourceCluster = $this->SourceCluster->fetchGalaxyClusters($user, array('conditions' => array('uuid' => $relation['galaxy_cluster_uuid'])));
    //         if (empty($sourceCluster)) {
    //             throw new NotFoundException(__('Invalid galaxy cluster'));
    //         }
    //         $relation['galaxy_cluster_id'] = $sourceCluster['GalaxyCluster']['id'];
    //         if (!isset($relation['referenced_galaxy_cluster_uuid'])) {
    //             $targetCluster = $this->TargetCluster->fetchGalaxyClusters($user, array('conditions' => array('uuid' => $relation['referenced_galaxy_cluster_uuid'])));
    //             if (!empty($targetCluster)) { // do not save the relation if referenced cluster does not exists
    //                 $targetCluster = $targetCluster[0];
    //                 $relation['referenced_galaxy_cluster_uuid'] = $targetCluster['GalaxyCluster']['uuid'];
    //                 $relation['referenced_galaxy_cluster_id'] = $targetCluster['GalaxyCluster']['id'];
    //                 $this->create();
    //                 $saveResult = $this->save($relation, array('fieldList' => $fieldList));
    //                 if ($saveResult) {
    //                     $savedId = $this->id;
    //                     $this->GalaxyClusterRelationTag->attachTags($user, $savedId, $relation['tags'], $capture=$capture);
    //                 }
    //             } else {
    //                 throw new NotFoundException(__('Invalid referenced galaxy cluster'));
    //             }
    //         }
    //     }
    // }

    public function massageRelationTag($cluster)
    {
        if (!empty($cluster['GalaxyClusterRelation'])) {
            foreach ($cluster['GalaxyClusterRelation'] as $k => $relation) {
                if (!empty($relation['GalaxyClusterRelationTag'])) {
                    foreach ($relation['GalaxyClusterRelationTag'] as $relationTag) {
                        $cluster['GalaxyClusterRelation'][$k]['Tag'][] = $relationTag['Tag'];
                    }
                    unset($cluster['GalaxyClusterRelation'][$k]['GalaxyClusterRelationTag']);
                }
            }
        }
        if (!empty($cluster['TargettingClusterRelation'])) {
            foreach ($cluster['TargettingClusterRelation'] as $k => $relation) {
                if (!empty($relation['GalaxyClusterRelationTag'])) {
                    foreach ($relation['GalaxyClusterRelationTag'] as $relationTag) {
                        $cluster['TargettingClusterRelation'][$k]['Tag'][] = $relationTag['Tag'];
                    }
                    unset($cluster['TargettingClusterRelation'][$k]['GalaxyClusterRelationTag']);
                }
            }
        }
        return $cluster;
    }

    public function saveRelation($user, $relation, $capture=false, $force=false)
    {
        $errors = array();
        if (!$user['Role']['perm_galaxy_editor'] && !$user['Role']['perm_site_admin']) {
            $errors[] = __('Incorrect permission');
            return $errors;
        }

        if (!empty($relation['GalaxyClusterRelation']['tags'])) {
            $tags = explode(',', $relation['GalaxyClusterRelation']['tags']);
            $tags = array_map('trim', $tags);
            $relation['GalaxyClusterRelation' ]['tags'] = $tags;
        }

        $existingRelation = $this->find('first', array('conditions' => array(
            'GalaxyClusterRelation.galaxy_cluster_uuid' => $relation['GalaxyClusterRelation']['galaxy_cluster_uuid'],
            'GalaxyClusterRelation.referenced_galaxy_cluster_uuid' => $relation['GalaxyClusterRelation']['referenced_galaxy_cluster_uuid'],
            'GalaxyClusterRelation.referenced_galaxy_cluster_type' => $relation['GalaxyClusterRelation']['referenced_galaxy_cluster_type'],
        )));
        if (!empty($existingRelation)) {
            if (!$force) {
                $errors[] = __('Relation already exists');
                return $errors;
            } else {
                $relation['GalaxyClusterRelation']['id'] = $existingRelation['GalaxyClusterRelation']['id'];
            }
        } else {
            $this->create();
        }
        if (empty($errors)) {
            $relation = $this->syncUUIDsAndIDs($user, $relation);
            $saveSuccess = $this->save($relation);
            if ($saveSuccess) {
                $savedRelation = $this->find('first', array(
                    'conditions' => array('id' =>  $this->id),
                    'recursive' => -1
                ));
                $tagSaveResults = $this->GalaxyClusterRelationTag->attachTags($user, $this->id, $relation['GalaxyClusterRelation']['tags'], $capture=$capture);
                if (!$tagSaveSuccess) {
                    $errors[] = __('Tags could not be saved');
                }
            }
        }
        return $errors;
    }

    public function editRelation($user, $relation, $fieldList=array(), $capture=false)
    {
        $this->SharingGroup = ClassRegistry::init('SharingGroup');
        $errors = array();
        if (!$user['Role']['perm_galaxy_editor'] && !$user['Role']['perm_site_admin']) {
            $errors[] = __('Incorrect permission');
        }
        if (isset($relation['GalaxyClusterRelation']['id'])) {
            $existingRelation = $this->find('first', array('conditions' => array('GalaxyClusterRelation.id' => $relation['GalaxyClusterRelation']['id'])));
        } else {
            $errors[] = __('UUID not provided');
        }
        if (empty($existingRelation)) {
            $errors[] = __('Unkown ID');
        } else {
            $options = array('conditions' => array(
                'uuid' => $relation['GalaxyClusterRelation']['galaxy_cluster_uuid']
            ));
            $cluster = $this->SourceCluster->fetchGalaxyClusters($user, $options);
            if (empty($cluster)) {
                $errors[] = __('Invalid source galaxy cluster');
            }
            $cluster = $cluster[0];
            $relation['GalaxyClusterRelation']['id'] = $existingRelation['GalaxyClusterRelation']['id'];
            $relation['GalaxyClusterRelation']['galaxy_cluster_id'] = $cluster['SourceCluster']['id'];
            $relation['GalaxyClusterRelation']['galaxy_cluster_uuid'] = $cluster['SourceCluster']['uuid'];

            if (isset($relation['GalaxyClusterRelation']['distribution']) && $relation['GalaxyClusterRelation']['distribution'] == 4 && !$this->SharingGroup->checkIfAuthorised($user, $relation['GalaxyClusterRelation']['sharing_group_id'])) {
                $errors[] = array(__('Galaxy Cluster Relation could not be saved: The user has to have access to the sharing group in order to be able to edit it.'));
            }

            if ($cluster['SourceCluster']['org_id'] != $user['org_id'] && !$user['Role']['perm_site_admin']) {
                $errors[] = array(__('Relations can only be created by cluster\'s owner organisation'));
            }

            if (empty($errors)) {
                $targetCluster = $this->TargetCluster->fetchGalaxyClusters($user, array('conditions' => array('uuid' => $relation['GalaxyClusterRelation']['referenced_galaxy_cluster_uuid'])));
                if (empty($targetCluster)) { // do not save the relation if referenced cluster does not exists
                    $errors[] = array(__('Invalid referenced galaxy cluster'));
                } else {
                    $targetCluster = $targetCluster[0];
                    $relation['GalaxyClusterRelation']['referenced_galaxy_cluster_id'] = $targetCluster['TargetCluster']['id'];
                    $relation['GalaxyClusterRelation']['referenced_galaxy_cluster_uuid'] = $targetCluster['TargetCluster']['uuid'];
                    $relation['GalaxyClusterRelation']['default'] = false;
                    if (empty($fieldList)) {
                        $fieldList = array('galaxy_cluster_id', 'galaxy_cluster_uuid', 'referenced_galaxy_cluster_id', 'referenced_galaxy_cluster_uuid', 'referenced_galaxy_cluster_type', 'distribution', 'sharing_group_id', 'default');
                    }

                    $saveSuccess = $this->save($relation, array('fieldList' => $fieldList));
                    if (!$saveSuccess) {
                        foreach($this->validationErrors as $validationError) {
                            $errors[] = $validationError[0];
                        }
                    } else {
                        $this->GalaxyClusterRelationTag->deleteAll(array('GalaxyClusterRelationTag.galaxy_cluster_relation_id' => $relation['GalaxyClusterRelation']['id']));
                        $this->GalaxyClusterRelationTag->attachTags($user, $relation['GalaxyClusterRelation']['id'], $relation['GalaxyClusterRelation']['tags'], $capture=$capture);
                    }
                }
            }
        }
        return $errors;
    }

    /**
     * Gets a relation then save it.
     *
     * @param $user
     * @param array $relation Relation to be saved
     * @param bool $fromPull If the current capture is performed from a PULL sync
     * @return array
     */
    public function captureRelations($user, $cluster, $relations, $fromPull=false)
    {
        $results = array('success' => false, 'imported' => 0, 'failed' => 0);
        $this->Log = ClassRegistry::init('Log');
        $clusterUuid = $cluster['GalaxyCluster']['uuid'];

        foreach ($relations as $k => $relation) {
            if (!isset($relation['GalaxyClusterRelation'])) {
                $relation = array('GalaxyClusterRelation' => $relation);
            }
            $relation['GalaxyClusterRelation']['galaxy_cluster_uuid'] = $clusterUuid;
            $relation['GalaxyClusterRelation']['galaxy_cluster_id'] = $cluster['GalaxyCluster']['id'];
            
            if (empty($relation['GalaxyClusterRelation']['referenced_galaxy_cluster_uuid'])) {
                $this->Log->createLogEntry($user, 'captureRelations', 'GalaxyClusterRelation', 0, __('No referenced cluster UUID provided'), __('relation for cluster (%s)', $clusterUuid));
                $results['failed']++;
                continue;
            } else {
                $options = array(
                    'conditions' => array(
                        'uuid' => $relation['GalaxyClusterRelation']['referenced_galaxy_cluster_uuid'],
                    ),
                    'fields' => array(
                        'id', 'uuid',
                    )
                );
                $referencedCluster = $this->SourceCluster->fetchGalaxyClusters($user, $options);
                if (empty($referencedCluster)) {
                    $this->Log->createLogEntry($user, 'captureRelations', 'GalaxyClusterRelation', 0, __('Referenced cluster not found'), __('relation to (%s) for cluster (%s)', $relation['GalaxyClusterRelation']['referenced_galaxy_cluster_uuid'], $clusterUuid));
                    unset($relation['GalaxyClusterRelation']['referenced_galaxy_cluster_id']);
                } else {
                    $referencedCluster = $referencedCluster[0];
                    $relation['GalaxyClusterRelation']['referenced_galaxy_cluster_id'] = $referencedCluster['SourceCluster']['id'];
                }
            }

            if ($cluster['GalaxyCluster']['orgc_id'] != $user['org_id'] && !$user['Role']['perm_sync'] && !$user['Role']['perm_site_admin']) {
                $this->Log->createLogEntry($user, 'captureRelations', 'GalaxyClusterRelation', 0, __('Only sync user can create galaxy on behalf of other users'), __('relation (%s) for cluster (%s)', $relation['GalaxyClusterRelation']['id'], $clusterUuid));
                $results['failed']++;
                continue;
            }

            $existingRelation = $this->find('first', array('conditions' => array(
                'GalaxyClusterRelation.galaxy_cluster_uuid' => $relation['GalaxyClusterRelation']['galaxy_cluster_uuid'],
                'GalaxyClusterRelation.referenced_galaxy_cluster_uuid' => $relation['GalaxyClusterRelation']['referenced_galaxy_cluster_uuid'],
                'GalaxyClusterRelation.referenced_galaxy_cluster_type' => $relation['GalaxyClusterRelation']['referenced_galaxy_cluster_type'],
            )));
            if (!empty($existingRelation)) {
                if (!$fromPull) {
                    $this->Log->createLogEntry($user, 'captureRelations', 'GalaxyClusterRelation', 0, __('Relation already exists'), __('relation to (%s) for cluster (%s)', $relation['GalaxyClusterRelation']['referenced_galaxy_cluster_uuid'], $clusterUuid));
                    $results['failed']++;
                    continue;
                } else {
                    $relation['GalaxyClusterRelation']['id'] = $existingRelation['GalaxyClusterRelation']['id'];
                }
            } else {
                $this->create();
            }

            $this->Event = ClassRegistry::init('Event');
            if (isset($relation['GalaxyClusterRelation']['distribution']) && $relation['GalaxyClusterRelation']['distribution'] == 4) {
                $relation['GalaxyClusterRelation'] = $this->Event->__captureSGForElement($relation['GalaxyClusterRelation'], $user);
            }

            $saveSuccess = $this->save($relation);
            if ($saveSuccess) {
                $results['imported']++;
                $modelKey = false;
                if (!empty($relation['GalaxyClusterRelation']['GalaxyClusterRelationTag'])) {
                    $modelKey = 'GalaxyClusterRelationTag';
                } elseif (!empty($relation['GalaxyClusterRelation']['Tag'])) {
                    $modelKey = 'Tag';
                }
                if ($modelKey !== false) {
                    $tagNames = Hash::extract($relation['GalaxyClusterRelation'][$modelKey], '{n}.name');
                    // Here we only attach tags. If they were removed at some point it's not taken into account. Since we don't have tag soft-deletion, tags added by users will be kept.
                    $this->GalaxyClusterRelationTag->attachTags($user, $this->id, $tagNames, $capture=true);
                }
            } else {
                $results['failed']++;
                foreach($this->validationErrors as $validationError) {
                }
            }
        }

        $results['success'] = $results['imported'] > 0;
        return $results;
    }

    private function syncUUIDsAndIDs($user, $relation)
    {
        $options = array('conditions' => array(
            'uuid' => $relation['GalaxyClusterRelation']['galaxy_cluster_uuid']
        ));
        $sourceCluster = $this->SourceCluster->fetchGalaxyClusters($user, $options);
        if (!empty($sourceCluster)) {
            $sourceCluster = $sourceCluster[0];
            $relation['GalaxyClusterRelation']['galaxy_cluster_id'] = $sourceCluster['SourceCluster']['id'];
            $relation['GalaxyClusterRelation']['galaxy_cluster_uuid'] = $sourceCluster['SourceCluster']['uuid'];
        }
        $options = array('conditions' => array(
            'uuid' => $relation['GalaxyClusterRelation']['referenced_galaxy_cluster_uuid']
        ));
        $targetCluster = $this->TargetCluster->fetchGalaxyClusters($user, $options);
        if (!empty($targetCluster)) {
            $targetCluster = $targetCluster[0];
            $relation['GalaxyClusterRelation']['referenced_galaxy_cluster_id'] = $targetCluster['TargetCluster']['id'];
            $relation['GalaxyClusterRelation']['referenced_galaxy_cluster_uuid'] = $targetCluster['TargetCluster']['uuid'];
        }
        return $relation;
    }
}
