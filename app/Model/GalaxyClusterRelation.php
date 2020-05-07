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
        'galaxy_cluster_id' => array(
            'stringNotEmpty' => array(
                'rule' => array('stringNotEmpty')
            )
        ),
        'referenced_galaxy_cluster_id' => array(
            'stringNotEmpty' => array(
                'rule' => array('stringNotEmpty')
            )
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
            'GalaxyCluster' => array(
                'className' => 'GalaxyCluster',
                'foreignKey' => 'galaxy_cluster_id',
            ),
            'ReferencedGalaxyCluster' => array(
                'className' => 'GalaxyCluster',
                'foreignKey' => 'referenced_galaxy_cluster_id',
            ),
            'Org' => array(
                'className' => 'Organisation',
                'foreignKey' => 'org_id',
                'conditions' => array('GalaxyClusterRelation.org_id !=' => 0),
            ),
            'Orgc' => array(
                'className' => 'Organisation',
                'foreignKey' => 'orgc_id',
                'conditions' => array('GalaxyClusterRelation.orgc_id !=' => 0),
            ),
            'SharingGroup' => array(
                    'className' => 'SharingGroup',
                    'foreignKey' => 'sharing_group_id'
            )
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
                'GalaxyClusterRelation.org_id' => $user['org_id'],
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

    public function fetchRelations($user, $options)
    {
        $params = array(
            'conditions' => $this->buildConditions($user),
            'recursive' => -1
        );
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
        $relations = $this->find('all', $params);
        foreach ($relations as $i => $relation) {
            if ($relation['GalaxyClusterRelation']['distribution'] != 4) {
                unset($relation[$i]['SharingGroup']);
            }
            // if ($cluster['GalaxyCluster']['org_id'] == 0) {
            //     unset($clusters[$i]['Org']);
            // }
            // if ($cluster['GalaxyCluster']['orgc_id'] == 0) {
            //     unset($clusters[$i]['Orgc']);
            // }
            // $clusters[$i] = $this->GalaxyClusterRelation->massageRelationTag($clusters[$i]);
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
            'galaxy_cluster_id',
            'galaxy_cluster_uuid',
            'referenced_galaxy_cluster_id',
            'referenced_galaxy_cluster_uuid',
            'referenced_galaxy_cluster_type'
        );
        foreach ($relations as $k => $relation) {
            if (!isset($relation['referenced_galaxy_cluster_id'])) {
                $referencedCluster = $this->GalaxyCluster->fetchGalaxyClusters($user, array('conditions' => array('GalaxyCluster.uuid' => $relation['referenced_galaxy_cluster_uuid'])));
                if (!empty($referencedCluster)) { // do not save the relation if referenced cluster does not exists
                    $referencedCluster = $referencedCluster[0];
                    $relation['referenced_galaxy_cluster_id'] = $referencedCluster['GalaxyCluster']['id'];
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
        $relation['GalaxyClusterRelation']['org_id'] = $user['org_id'];
        if (!isset($relation['GalaxyClusterRelation']['orgc_id'])) {
            if (isset($relation['Orgc']['uuid'])) {
                $orgc_id = $this->Orgc->find('first', array('conditions' => array('Orgc.uuid' => $user['Orgc']['uuid']), 'fields' => array('Orgc.id'), 'recursive' => -1));
            } else {
                $orgc_id = $user['org_id'];
            }
            $relation['GalaxyClusterRelation']['orgc_id'] = $orgc_id;
        }
        $existingRelation = $this->find('first', array('conditions' => array(
            'GalaxyClusterRelation.galaxy_cluster_id' => $relation['GalaxyClusterRelation']['galaxy_cluster_id'],
            'GalaxyClusterRelation.referenced_galaxy_cluster_id' => $relation['GalaxyClusterRelation']['referenced_galaxy_cluster_id'],
            'GalaxyClusterRelation.referenced_galaxy_cluster_type' => $relation['GalaxyClusterRelation']['referenced_galaxy_cluster_type'],
            'GalaxyClusterRelation.org_id' => $relation['GalaxyClusterRelation']['org_id'],
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
            // For users that are of the creating org of the cluster, always allow the edit
            // For users that are sync users, only allow the edit if the cluster is locked
            if ($existingRelation['GalaxyClusterRelation']['orgc_id'] === $user['org_id']
            || ($user['Role']['perm_sync'] && $existingRelation['GalaxyClusterRelation']['locked']) || $user['Role']['perm_site_admin']) {
                if ($user['Role']['perm_sync']) {
                    if (isset($relation['GalaxyClusterRelation']['distribution']) && $relation['GalaxyClusterRelation']['distribution'] == 4 && !$this->SharingGroup->checkIfAuthorised($user, $relation['GalaxyClusterRelation']['sharing_group_id'])) {
                        $errors[] = array(__('Galaxy Cluster Relation could not be saved: The sync user has to have access to the sharing group in order to be able to edit it.'));
                    }
                }
            } else {
                $errors[] = array(__('Galaxy Cluster Relation could not be saved: The user used to edit the cluster relation is not authorised to do so. This can be caused by the user not being of the same organisation as the original creator of the cluster relation whilst also not being a site administrator.'));
            }
            $relation['GalaxyClusterRelation']['id'] = $existingRelation['GalaxyClusterRelation']['id'];
            
            if (empty($errors)) {
                $relation['GalaxyClusterRelation']['default'] = false;
                if (empty($fieldList)) {
                    $fieldList = array('galaxy_cluster_id', 'referenced_galaxy_cluster_id', 'referenced_galaxy_cluster_type', 'distribution', 'sharing_group_id');
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
}
