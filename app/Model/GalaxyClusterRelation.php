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
            $clusters[$i] = $this->GalaxyClusterRelation->massageRelationTag($clusters[$i]);
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

    public function addRelations($user, $relations)
    {
        $fieldList = array(
            'galaxy_cluster_uuid',
            'referenced_galaxy_cluster_uuid',
            'referenced_galaxy_cluster_type',
            'distribution',
            'sharing_group_id',
        );
        foreach ($relations as $k => $relation) {
            if (!isset($relation['referenced_galaxy_cluster_uuid'])) {
                $referencedCluster = $this->TargetCluster->fetchGalaxyClusters($user, array('conditions' => array('uuid' => $relation['referenced_galaxy_cluster_uuid'])));
                if (!empty($referencedCluster)) { // do not save the relation if referenced cluster does not exists
                    $referencedCluster = $referencedCluster[0];
                    $relation['referenced_galaxy_cluster_uuid'] = $referencedCluster['GalaxyCluster']['uuid'];
                    $this->create();
                    $saveResult = $this->save($relation, array('fieldList' => $fieldList));
                    if ($saveResult) {
                        $savedId = $this->id;
                        $this->GalaxyClusterRelationTag->attachTags($user, $savedId, $relation['tags']);
                    }
                }
            }
        }
    }

    public function massageRelationTag($cluster)
    {
        if (!empty($cluster['GalaxyClusterRelation'])) {
            foreach ($cluster['GalaxyClusterRelation'] as $k => $relation) {
                if (!empty($relation['GalaxyClusterRelationTag'])) {
                    foreach ($relation['GalaxyClusterRelationTag'] as $relationTag) {
                        $cluster['GalaxyClusterRelation'][$k]['Tag'] = $relationTag['Tag'];
                    }
                    unset($cluster['GalaxyClusterRelation'][$k]['GalaxyClusterRelationTag']);
                }
            }
        }
        return $cluster;
    }

    public function saveRelation($user, $relation)
    {
        $errors = array();
        if (!$user['Role']['perm_galaxy_editor'] && !$user['Role']['perm_site_admin']) {
            $errors[] = __('Incorrect permission');
            return $errors;
        }
        $existingRelation = $this->find('first', array('conditions' => array(
            'GalaxyClusterRelation.galaxy_cluster_uuid' => $relation['GalaxyClusterRelation']['galaxy_cluster_uuid'],
            'GalaxyClusterRelation.referenced_galaxy_cluster_uuid' => $relation['GalaxyClusterRelation']['referenced_galaxy_cluster_uuid'],
            'GalaxyClusterRelation.referenced_galaxy_cluster_type' => $relation['GalaxyClusterRelation']['referenced_galaxy_cluster_type'],
        )));
        if (!empty($existingRelation)) {
            $errors[] = __('Relation already exists');
            return $errors;
        }
        if (empty($errors)) {
            $this->create();
            $saveSuccess = $this->save($relation);
            if ($saveSuccess) {
                $savedRelation = $this->find('first', array(
                    'conditions' => array('id' =>  $this->id),
                    'recursive' => -1
                ));
                // TODO: save tags as well
            }
        }
        return $errors;
    }

    public function editRelation($user, $relation, $fieldList=array())
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
                'GalaxyCluster.uuid' => $relations['GalaxyClusterRelation']['galaxy_cluster_uuid']
            ));
            $cluster = $this->SourceCluster->fetchGalaxyClusters($user, $options);
            if (empty($cluster)) {
                $errors[] = __('Source cluster not found');
            }
            $cluster = $cluster[0];
            $relation['GalaxyClusterRelation']['id'] = $existingRelation['GalaxyClusterRelation']['id'];

            if (isset($relation['GalaxyClusterRelation']['distribution']) && $relation['GalaxyClusterRelation']['distribution'] == 4 && !$this->SharingGroup->checkIfAuthorised($user, $relation['GalaxyClusterRelation']['sharing_group_id'])) {
                $errors[] = array(__('Galaxy Cluster Relation could not be saved: The user has to have access to the sharing group in order to be able to edit it.'));
            }
            
            if (empty($errors)) {
                $relation['GalaxyClusterRelation']['default'] = false;
                if (empty($fieldList)) {
                    $fieldList = array('galaxy_cluster_uuid', 'referenced_galaxy_cluster_uuid', 'referenced_galaxy_cluster_type', 'distribution', 'sharing_group_id');
                }
                $saveSuccess = $this->save($relation, array('fieldList' => $fieldList));
                if (!$saveSuccess) {
                    foreach($this->validationErrors as $validationError) {
                        $errors[] = $validationError[0];
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
                $this->Log->createLogEntry($user, 'captureRelations', 'GalaxyClusterRelation', 0, __('No referenced cluster UUID provided'), __('relation (%s) for cluster (%s)', $relation['GalaxyClusterRelation']['id'], $clusterUuid));
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
                    $this->Log->createLogEntry($user, 'captureRelations', 'GalaxyClusterRelation', 0, __('Referenced cluster not found'), __('relation (%s) for cluster (%s)', $relation['GalaxyClusterRelation']['id'], $clusterUuid));
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

            $this->Event = ClassRegistry::init('Event');
            if (isset($relation['GalaxyClusterRelation']['distribution']) && $relation['GalaxyClusterRelation']['distribution'] == 4) {
                $relation['GalaxyClusterRelation'] = $this->Event->__captureSGForElement($relation['GalaxyClusterRelation'], $user);
            }

            $this->create();
            $saveSuccess = $this->save($relation);
            if ($saveSuccess) {
                $results['imported']++;
                if (!empty($relation['GalaxyClusterRelationTag'])) {
                    $tagNames = Hash::extract($relation['GalaxyClusterRelationTag'], '{n}.name');
                    $this->GalaxyClusterRelationTag->attachTags($user, $this->id, $tagNames);
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
}
