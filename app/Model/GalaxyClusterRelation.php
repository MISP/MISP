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
    );

    public $belongsTo = array(
            'GalaxyCluster' => array(
                'className' => 'GalaxyCluster',
                'foreignKey' => 'galaxy_cluster_id',
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

    public function getExistingRelationships()
    {
        $existingRelationships = $this->find('all', array(
            'recursive' => -1,
            'fields' => array('referenced_galaxy_cluster_type')
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
}
