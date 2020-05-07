<?php
App::uses('AppModel', 'Model');

class GalaxyClusterRelationTag extends AppModel
{
    public $useTable = 'galaxy_cluster_relation_tags';
    public $actsAs = array('Containable');

    public $validate = array(
        'galaxy_cluster_relation_id' => array(
            'valueNotEmpty' => array(
                'rule' => array('valueNotEmpty'),
            ),
        ),
        'tag_id' => array(
            'valueNotEmpty' => array(
                'rule' => array('valueNotEmpty'),
            ),
        ),
    );

    public $belongsTo = array(
        'GalaxyClusterRelation' => array(
            'className' => 'GalaxyClusterRelation',
        ),
        'Tag' => array(
            'className' => 'Tag',
        ),
    );

    public function afterSave($created, $options = array())
    {
        parent::afterSave($created, $options);
    }

    public function beforeDelete($cascade = true)
    {
        parent::beforeDelete($cascade);
    }

    public function softDelete($id)
    {
        $this->delete($id);
    }

    public function attachTags($user, $galaxyClusterRelationId, $tags)
    {
        $allSaved = true;
        foreach ($tags as $tagName) {
            $tagId = $this->Tag->captureTag(array('name' => $tagName), $user);
            $existingAssociation = $this->find('first', array(
                'recursive' => -1,
                'conditions' => array(
                    'tag_id' => $tagId,
                    'galaxy_cluster_relation_id' => $galaxyClusterRelationId
                )
            ));
            if (empty($existingAssociation)) {
                $this->create();
                $saveResult = $this->save(array('galaxy_cluster_relation_id' => $galaxyClusterRelationId, 'tag_id' => $tagId));
                $allSaved = $allSaved && $saveResult;
                if (!$saveResult) {
                    debug($saveResult);
                }
            }
        }
        return $saveResult;
    }
}
