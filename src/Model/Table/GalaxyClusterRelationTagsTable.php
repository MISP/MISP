<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;
use Cake\Validation\Validator;

/**
 * @property TagsTable $Tags
 */
class GalaxyClusterRelationTagsTable extends AppTable
{
    public $useTable = 'galaxy_cluster_relation_tags';
    public $actsAs = array('AuditLog', 'Containable');

    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->requirePresence(['galaxy_cluster_relation_id', 'tag_id'])
            ->notEmptyString('galaxy_cluster_relation_id')
            ->notEmptyString('tag_id');

        return $validator;
    }

    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('AuditLog');

        $this->belongsTo('GalaxyClusterRelations');
        $this->belongsTo('Tags');
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
     * @return bool
     */
    public function attachTags(array $user, $galaxyClusterRelationId, array $tags, $capture = false)
    {
        $allSaved = true;
        $saveResult = false;
        foreach ($tags as $tagName) {
            if ($capture) {
                $tagId = $this->Tags->captureTag(array('name' => $tagName), $user);
            } else {
                $tagId = $this->Tags->lookupTagIdFromName($tagName);
            }
            $existingAssociation = $this->find('all', array(
                'recursive' => -1,
                'conditions' => array(
                    'tag_id' => $tagId,
                    'galaxy_cluster_relation_id' => $galaxyClusterRelationId
                )
            ))->first();
            if (empty($existingAssociation) && $tagId != -1) {
                $saveResult = $this->save($this->newEntity(array('galaxy_cluster_relation_id' => $galaxyClusterRelationId, 'tag_id' => $tagId)));
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
