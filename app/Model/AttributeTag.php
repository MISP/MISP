<?php
App::uses('AppModel', 'Model');

/**
 * @property Tag $Tag
 * @property MispAttribute $Attribute
 */
class AttributeTag extends AppModel
{
    public $actsAs = array('AuditLog', 'Containable');

    public $validate = [
        'attribute_id' => [
            'rule' => 'numeric',
            'required' => true,
        ],
        'event_id' => [
            'rule' => 'numeric',
            'required' => true,
        ],
        'tag_id' => [
            'rule' => 'numeric',
            'required' => true,
        ],
    ];

    public $belongsTo = array(
        'Attribute' => [
            'className' => 'MispAttribute',
            'foreignKey' => 'attribute_id'
        ],
        'Tag' => array(
            'className' => 'Tag',
        ),
    );

    public function afterSave($created, $options = array())
    {
        $pubToZmq = Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_tag_notifications_enable');
        $kafkaTopic = $this->kafkaTopic('tag');
        $triggerCallable = $this->isTriggerCallable('tag-attached-after-save');
        if ($pubToZmq || $kafkaTopic || $triggerCallable) {
            $tag = $this->find('first', array(
                'recursive' => -1,
                'conditions' => array('AttributeTag.id' => $this->id),
                'contain' => array('Tag')
            ));
            $tag['Tag']['attribute_id'] = $tag['AttributeTag']['attribute_id'];
            $tag['Tag']['event_id'] = $tag['AttributeTag']['event_id'];
            $tag = array('Tag' => $tag['Tag']);
            if ($pubToZmq) {
                $pubSubTool = $this->getPubSubTool();
                $pubSubTool->tag_save($tag, 'attached to attribute');
            }
            if ($kafkaTopic) {
                $kafkaPubTool = $this->getKafkaPubTool();
                $kafkaPubTool->publishJson($kafkaTopic, $tag, 'attached to attribute');
            }
            if ($triggerCallable) {
                $workflowErrors = [];
                $logging = [
                    'model' => 'AttributeTag',
                    'action' => 'add',
                    'id' => $this->id,
                ];
                $this->executeTrigger('tag-attached-after-save', $tag, $workflowErrors, $logging);
            }
        }
    }

    public function beforeDelete($cascade = true)
    {
        $pubToZmq = Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_tag_notifications_enable');
        $kafkaTopic = $this->kafkaTopic('tag');
        if ($pubToZmq || $kafkaTopic) {
            if (!empty($this->id)) {
                $tag = $this->find('first', array(
                    'recursive' => -1,
                    'conditions' => array('AttributeTag.id' => $this->id),
                    'contain' => array('Tag')
                ));
                $tag['Tag']['attribute_id'] = $tag['AttributeTag']['attribute_id'];
                $tag['Tag']['event_id'] = $tag['AttributeTag']['event_id'];
                $tag = array('Tag' => $tag['Tag']);
                if ($pubToZmq) {
                    $pubSubTool = $this->getPubSubTool();
                    $pubSubTool->tag_save($tag, 'detached from attribute');
                }
                if ($kafkaTopic) {
                    $kafkaPubTool = $this->getKafkaPubTool();
                    $kafkaPubTool->publishJson($kafkaTopic, $tag, 'detached from attribute');
                }
            }
        }
    }

    public function softDelete($id)
    {
        $this->delete($id);
    }

    /**
     * handleAttributeTags
     *
     * @param  array $attribute
     * @param  int   $event_id
     * @param  bool  $capture
     * @return void
     */
    public function handleAttributeTags($user, array $attribute, $event_id, $capture = false)
    {
        if ($user['Role']['perm_tagger']) {
            if (isset($attribute['Tag'])) {
                foreach ($attribute['Tag'] as $tag) {
                    if (!isset($tag['id'])) {
                        if ($capture) {
                            $tag_id = $this->Tag->captureTag($tag, $user);
                        } else {
                            $tag_id = $this->Tag->lookupTagIdFromName($tag['name']);
                        }
                        $tag['id'] = $tag_id;
                    }
                    if ($tag['id'] > 0) {
                        $this->handleAttributeTag($attribute['id'], $event_id, $tag);
                    }
                }
            }
        }
    }

    public function handleAttributeTag($attribute_id, $event_id, array $tag, $mock = false)
    {
        if (empty($tag['deleted'])) {
            $local = isset($tag['local']) ? $tag['local'] : false;
            $relationship_type = isset($tag['relationship_type']) ? $tag['relationship_type'] : false;
            if ($mock) {
                return [
                    'attach' => [
                        'attribute_id' => $attribute_id,
                        'event_id' => $event_id,
                        'tag_id' => $tag['id'],
                        'local' => $local,
                        'relationship_type' => $relationship_type
                    ]
                ];
            } else {
                $this->attachTagToAttribute($attribute_id, $event_id, $tag['id'], $local, $relationship_type);
            }
        } else {
            if ($mock) {
                return [
                    'detach' => [
                        'attribute_id' => $attribute_id,
                        'event_id' => $event_id,
                        'tag_id' => $tag['id']
                    ]
                ];
            } else {
                $this->detachTagFromAttribute($attribute_id, $event_id, $tag['id'], null);
            }
        }
    }

    /**
     * @param int $attribute_id
     * @param int $event_id
     * @param int $tag_id
     * @param bool $local
     * @return bool
     * @throws Exception
     */
    public function attachTagToAttribute($attribute_id, $event_id, $tag_id, $local = false, $relationship_type = false, &$nothingToChange = false)
    {
        $existingAssociation = $this->find('first', [
            'conditions' => [
                'tag_id' => $tag_id,
                'attribute_id' => $attribute_id,
            ],
            'recursive' => -1
        ]);
        if (empty($existingAssociation)) {
            $data = [
                'attribute_id' => $attribute_id,
                'event_id' => $event_id,
                'tag_id' => $tag_id,
                'local' => $local ? 1 : 0,
                'relationship_type' => $relationship_type ? $relationship_type : null,
            ];
            $this->create();
            if (!$this->save($data)) {
                return false;
            }
        } else {
            if ($existingAssociation['AttributeTag']['relationship_type'] != $relationship_type) {
                $existingAssociation['AttributeTag']['relationship_type'] = $relationship_type;
                $this->save($existingAssociation);
            }
            $nothingToChange = true;
        }
        return true;
    }

    public function detachTagFromAttribute($attribute_id, $event_id, $tag_id, $local, &$nothingToChange = false)
    {
        $conditions = [
            'tag_id' => $tag_id,
            'event_id' => $event_id,
            'attribute_id' => $attribute_id,
        ];
        if (!is_null($local)) {
            $conditions['local'] = !empty($local);
        }
        $existingAssociation = $this->find('first', array(
            'recursive' => -1,
            'fields' => ['id'],
            'conditions' => $conditions
        ));

        if (!empty($existingAssociation)) {
            $result = $this->delete($existingAssociation['AttributeTag']['id']);
            if ($result) {
                return true;
            }
        } else {
            $nothingToChange = true;
        }
        return false;
    }

    // This function help mirroring the tags at attribute level. It will delete tags that are not present on the remote attribute
    public function pruneOutdatedAttributeTagsFromSync($newerTags, $originalAttributeTags)
    {
        $newerTagsName = array();
        foreach ($newerTags as $tag) {
            $newerTagsName[] = strtolower($tag['name']);
        }
        foreach ($originalAttributeTags as $k => $attributeTag) {
            if (!$attributeTag['local']) { //
                if (!in_array(strtolower($attributeTag['Tag']['name']), $newerTagsName)) {
                    $this->softDelete($attributeTag['id']);
                }
            }
        }
    }

    /**
     * @param array $tagIds
     * @param array $user - Currently ignored for performance reasons
     * @return array
     */
    public function countForTags(array $tagIds, array $user)
    {
        if (empty($tagIds)) {
            return [];
        }
        $this->virtualFields['attribute_count'] = 'COUNT(AttributeTag.id)';
        $counts = $this->find('list', [
            'recursive' => -1,
            'fields' => ['AttributeTag.tag_id', 'attribute_count'],
            'conditions' => ['AttributeTag.tag_id' => $tagIds],
            'group' => ['AttributeTag.tag_id'],
        ]);
        unset($this->virtualFields['attribute_count']);
        return $counts;
    }

    // Fetch all tags attached to attribute belonging to supplied event. No ACL if user not provided
    public function getTagScores($user=false, $eventId=0, $allowedTags=array())
    {
        if ($user === false) {
            $conditions = array('Tag.id !=' => null);
            if ($eventId != 0) {
                $conditions['event_id'] = $eventId;
            }
            $attribute_tag_scores = $this->find('all', array(
                'recursive' => -1,
                'conditions' => $conditions,
                'contain' => array(
                    'Tag' => array(
                        'conditions' => array('name' => $allowedTags)
                    )
                ),
                'fields' => array('Tag.name', 'AttributeTag.event_id')
            ));
            $scores = array('scores' => array(), 'maxScore' => 0);
            foreach ($attribute_tag_scores as $attribute_tag_score) {
                $tag_name = $attribute_tag_score['Tag']['name'];
                if (!isset($scores['scores'][$tag_name])) {
                    $scores['scores'][$tag_name] = 0;
                }
                $scores['scores'][$tag_name]++;
                $scores['maxScore'] = $scores['scores'][$tag_name] > $scores['maxScore'] ? $scores['scores'][$tag_name] : $scores['maxScore'];
            }
        } else {
            $allowed_tag_lookup_table = array_flip($allowedTags);
            $attributes = $this->Attribute->fetchAttributes($user, array(
                'conditions' => array(
                    'Attribute.event_id' => $eventId
                ),
                'flatten' => 1
            ));
            $scores = array('scores' => array(), 'maxScore' => 0);
            foreach ($attributes as $attribute) {
                foreach ($attribute['AttributeTag'] as $tag) {
                    $tag_name = $tag['Tag']['name'];
                    if (isset($allowed_tag_lookup_table[$tag_name])) {
                        if (!isset($scores['scores'][$tag_name])) {
                            $scores['scores'][$tag_name] = 0;
                        }
                        $scores['scores'][$tag_name]++;
                        $scores['maxScore'] = $scores['scores'][$tag_name] > $scores['maxScore'] ? $scores['scores'][$tag_name] : $scores['maxScore'];
                    }
                }
            }
        }
        return $scores;
    }


    // find all tags that belong to a list of attributes (contained in the same event)
    public function getAttributesTags(array $attributes, $includeGalaxies=false)
    {
        if (empty($attributes)) {
            return array();
        }

        $clusterTagIds = array_flip($this->Tag->find('column', array(
            'conditions' => ['Tag.is_galaxy' => 1],
            'fields' => ['Tag.id'],
        )));
        $allTags = array();
        foreach ($attributes as $attribute) {
            $attributeTags = $attribute['AttributeTag'];
            foreach ($attributeTags as $attributeTag) {
                if ($includeGalaxies || !isset($clusterTagIds[$attributeTag['Tag']['id']])) {
                    $allTags[$attributeTag['Tag']['id']] = $attributeTag['Tag'];
                }
            }
        }
        return $allTags;
    }

    /**
     * Find all galaxies that belong to a list of attributes (contains in the same event)
     * @param array $user
     * @param array $attributes
     * @return array
     */
    public function getAttributesClusters(array $user, array $attributes)
    {
        if (empty($attributes)) {
            return array();
        }

        $clusterTagIds = array_flip($this->Tag->find('column', array(
            'conditions' => ['Tag.is_galaxy' => 1],
            'fields' => ['Tag.id'],
        )));
        $this->GalaxyCluster = ClassRegistry::init('GalaxyCluster');

        $allClusters = array();
        foreach ($attributes as $attribute) {
            $attributeTags = $attribute['AttributeTag'];

            foreach ($attributeTags as $attributeTag) {
                if (isset($clusterTagIds[$attributeTag['Tag']['id']])) {
                    $cluster = $this->GalaxyCluster->fetchGalaxyClusters($user, array(
                        'conditions' => array('GalaxyCluster.tag_name' => $attributeTag['Tag']['name']),
                        'fields' => array('value', 'description', 'type'),
                        'contain' => array(
                            'GalaxyElement' => array(
                                'conditions' => array('GalaxyElement.key' => 'synonyms')
                            )
                        ),
                        'first' => true
                    ));
                    if (empty($cluster)) {
                        continue;
                    }
                    // create synonym string
                    $cluster['GalaxyCluster']['synonyms_string'] = array();
                    foreach ($cluster['GalaxyCluster']['GalaxyElement'] as $element) {
                        $cluster['GalaxyCluster']['synonyms_string'][] = $element['value'];
                    }
                    $cluster['GalaxyCluster']['synonyms_string'] = implode(', ', $cluster['GalaxyCluster']['synonyms_string']);
                    unset($cluster['GalaxyCluster']['GalaxyElement']);
                    $allClusters[$cluster['GalaxyCluster']['id']] = $cluster['GalaxyCluster'];
                }
            }
        }
        return $allClusters;
    }

    /**
     * @param array $event
     * @return array|array[]
     */
    public function extractAttributeTagsNameFromEvent(array $event)
    {
        $extractedTags = [];
        $extractedClusters = [];

        foreach ($event['Attribute'] as $attribute) {
            foreach ($attribute['AttributeTag'] as $tag) {
                $extractedTags[$tag['Tag']['id']] = $tag['Tag']['name'];
            }
            foreach ($attribute['Galaxy'] as $galaxy) {
                foreach ($galaxy['GalaxyCluster'] as $cluster) {
                    $extractedClusters[$cluster['tag_id']] = $cluster['tag_name'];
                }
            }
        }
        foreach ($event['Object'] as $object) {
            if (!empty($object['Attribute'])) {
                foreach ($object['Attribute'] as $object_attribute) {
                    foreach ($object_attribute['AttributeTag'] as $tag) {
                        $extractedTags[$tag['Tag']['id']] = $tag['Tag']['name'];
                    }
                    foreach ($object_attribute['Galaxy'] as $galaxy) {
                        foreach ($galaxy['GalaxyCluster'] as $cluster) {
                            $extractedClusters[$cluster['tag_id']] = $cluster['tag_name'];
                        }
                    }
                }
            }
        }
        $extractedTags = array_diff_key($extractedTags, $extractedClusters); // de-dup if needed.
        return ['tags' => $extractedTags, 'clusters' => $extractedClusters];
    }
}
