<?php
App::uses('AppModel', 'Model');

/**
 * @property Tag $Tag
 */
class TagRelationTag extends AppModel
{
    public $useTable = 'tag_relation_tags';
    public $actsAs = array('AuditLog', 'Containable');

    public $validate = array(
        'scope' => array(
            'valueNotEmpty' => array(
                'rule' => array('valueNotEmpty'),
            ),
        ),
        'tag_relation_id' => array(
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

    public $belongsTo = ['Tag',];


    /**
     * attachTags
     *
     * @param  array  $user
     * @param  string $scope
     * @param  int    $galaxyClusterRelationId
     * @param  array  $tags list of tag names to be saved
     * @param  bool   $capture
     * @return bool
     */
    public function attachTags(array $user, $scope, $tagConnectorId, array $tags, $capture=false)
    {
        $allSaved = true;
        $saveResult = false;
        foreach ($tags as $tagName) {
            if ($capture) {
                $tagId = $this->Tag->captureTag(['name' => $tagName], $user);
            } else {
                $tagId = $this->Tag->lookupTagIdFromName($tagName);
            }
            $existingAssociation = $this->find('first', [
                'recursive' => -1,
                'conditions' => [
                    'scope' => $scope,
                    'tag_id' => $tagId,
                    'tag_relation_id' => $tagConnectorId
                ]
            ]);
            if (empty($existingAssociation) && $tagId != -1) {
                $this->create();
                $saveResult = $this->save([
                    'scope' => $scope,
                    'tag_relation_id' => $tagConnectorId,
                    'tag_id' => $tagId
                ]);
                $allSaved = $allSaved && $saveResult;
                if (!$saveResult) {
                    $this->Log->createLogEntry($user, 'attachTags', 'TagRelationTag', 0, __('Could not attach tag %s', $tagName), __('relation %s(%s)', $scope, $tagConnectorId));
                }
            }
        }
        return $allSaved;
    }

    public function detachTags($user, $scope, $tagConnectorId)
    {
        $this->deleteAll([
            'TagRelationTag.scope' => $scope,
            'TagRelationTag.tag_relation_id' => $tagConnectorId,
        ]);
    }
}
