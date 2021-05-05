<?php
App::uses('AppModel', 'Model');

class GalaxyClusterRelationTag extends AppModel
{
    public $useTable = 'galaxy_cluster_relation_tags';
    public $actsAs = array('AuditLog', 'Containable');

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

    /**
     * attachTags
     *
     * @param  array $user
     * @param  int   $galaxyClusterRelationId
     * @param  array $tags list of tag names to be saved
     * @param  bool  $capture
     * @return void
     */
    public function attachTags(array $user, $galaxyClusterRelationId, array $tags, $capture=false)
    {
        $allSaved = true;
        $saveResult = false;
        foreach ($tags as $tagName) {
            if ($capture) {
                $tagId = $this->Tag->captureTag(array('name' => $tagName), $user);
            } else {
                $tagId = $this->Tag->lookupTagIdFromName($tagName);
            }
            $existingAssociation = $this->find('first', array(
                'recursive' => -1,
                'conditions' => array(
                    'tag_id' => $tagId,
                    'galaxy_cluster_relation_id' => $galaxyClusterRelationId
                )
            ));
            if (empty($existingAssociation) && $tagId != -1) {
                $this->create();
                $saveResult = $this->save(array('galaxy_cluster_relation_id' => $galaxyClusterRelationId, 'tag_id' => $tagId));
                $allSaved = $allSaved && $saveResult;
                if (!$saveResult) {
                    $this->Log->createLogEntry($user, 'attachTags', 'GalaxyClusterRelationTag', 0, __('Could not attach tag %s', $tagName), __('relation (%s)', $galaxyClusterRelationId));
                }
            }
        }
        return $allSaved;
    }

    public function detachTag($user, $relationTagId)
    {
        $this->delete(array('GalaxyClusterRelationTag.relationTagId' => $relationTagId));
    }
}
