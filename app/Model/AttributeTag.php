<?php
App::uses('AppModel', 'Model');

class AttributeTag extends AppModel
{
    public $actsAs = array('Containable');

    public $validate = array(
        'attribute_id' => array(
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
        'Attribute' => array(
            'className' => 'Attribute',
        ),
        'Tag' => array(
            'className' => 'Tag',
        ),
    );

    public function afterSave($created, $options = array())
    {
        parent::afterSave($created, $options);
        $pubToZmq = Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_tag_notifications_enable');
        $kafkaTopic = Configure::read('Plugin.Kafka_tag_notifications_topic');
        $pubToKafka = Configure::read('Plugin.Kafka_enable') && Configure::read('Plugin.Kafka_tag_notifications_enable') && !empty($kafkaTopic);
        if ($pubToZmq || $pubToKafka) {
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
            if ($pubToKafka) {
                $kafkaPubTool = $this->getKafkaPubTool();
                $kafkaPubTool->publishJson($kafkaTopic, $tag, 'attached to attribute');
            }
        }
    }

    public function beforeDelete($cascade = true)
    {
        $pubToZmq = Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_tag_notifications_enable');
        $kafkaTopic = Configure::read('Plugin.Kafka_tag_notifications_topic');
        $pubToKafka = Configure::read('Plugin.Kafka_enable') && Configure::read('Plugin.Kafka_tag_notifications_enable') && !empty($kafkaTopic);
        if ($pubToZmq || $pubToKafka) {
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
                if ($pubToKafka) {
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

    public function attachTagToAttribute($attribute_id, $event_id, $tag_id)
    {
        $existingAssociation = $this->find('first', array(
            'recursive' => -1,
            'conditions' => array(
                'tag_id' => $tag_id,
                'attribute_id' => $attribute_id
            )
        ));
        if (empty($existingAssociation)) {
            $this->create();
            if (!$this->save(array('attribute_id' => $attribute_id, 'event_id' => $event_id, 'tag_id' => $tag_id))) {
                return false;
            }
        }
        return true;
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

    public function countForTag($tag_id, $user)
    {
        return $this->find('count', array(
            'recursive' => -1,
            'conditions' => array('AttributeTag.tag_id' => $tag_id)
        ));
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
            $attributes = $this->Attribute->fetchAttributes($user, array('conditions' => array(
                'Attribute.event_id' => $eventId
            )));
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
    public function getAttributesTags($user, $requestedEventId, $attributeIds=false, $includeGalaxies=false) {
        $conditions = array('Attribute.event_id' => $requestedEventId);
        if (is_array($attributeIds) && $attributeIds !== false) {
            $conditions['Attribute.id'] = $attributeIds;
        }

        $allTags = array();
        $attributes = $this->Attribute->fetchAttributes($user, array(
            'conditions' => $conditions,
            'flatten' => 1,
            'includeAllTags' => 1
        ));

        if (empty($attributes)) {
            return array();
        }
        $this->GalaxyCluster = ClassRegistry::init('GalaxyCluster');
        $cluster_names = $this->GalaxyCluster->find('list', array(
                'recursive' => -1,
                'fields' => array('GalaxyCluster.tag_name', 'GalaxyCluster.id'),
        ));
        $allTags = array();
        foreach ($attributes as $attribute) {
            $attributeTags = $attribute['AttributeTag'];
            foreach ($attributeTags as $k => $attributeTag) {
                if ($includeGalaxies || !isset($cluster_names[$attributeTag['Tag']['name']])) {
                    $allTags[$attributeTag['Tag']['id']] = $attributeTag['Tag'];
                }
            }
        }
        return $allTags;
    }

    // find all galaxies that belong to a list of attributes (contains in the same event)
    public function getAttributesClusters($user, $requestedEventId, $attributeIds=false) {
        $conditions = array('Attribute.event_id' => $requestedEventId);
        if (is_array($attributeIds) && $attributeIds !== false) {
            $conditions['Attribute.id'] = $attributeIds;
        }

        $attributes = $this->Attribute->fetchAttributes($user, array(
            'conditions' => $conditions,
            'flatten' => 1,
        ));
        if (empty($attributes)) {
            return array();
        }

        $this->GalaxyCluster = ClassRegistry::init('GalaxyCluster');
        $cluster_names = $this->GalaxyCluster->find('list', array(
                'recursive' => -1,
                'fields' => array('GalaxyCluster.tag_name', 'GalaxyCluster.id'),
        ));

        $allClusters = array();
        foreach ($attributes as $attribute) {
            $attributeTags = $attribute['AttributeTag'];

            foreach ($attributeTags as $k => $attributeTag) {
                if (isset($cluster_names[$attributeTag['Tag']['name']])) {
                    $cluster = $this->GalaxyCluster->find('first', array(
                            'conditions' => array('GalaxyCluster.tag_name' => $attributeTag['Tag']['name']),
                            'fields' => array('value', 'description', 'type'),
                            'contain' => array(
                                'GalaxyElement' => array(
                                    'conditions' => array('GalaxyElement.key' => 'synonyms')
                                )
                            ),
                            'recursive' => -1
                    ));

                    // create synonym string
                    $cluster['GalaxyCluster']['synonyms_string'] = array();
                    foreach ($cluster['GalaxyElement'] as $element) {
                        $cluster['GalaxyCluster']['synonyms_string'][] = $element['value'];
                    }
                    $cluster['GalaxyCluster']['synonyms_string'] = implode(', ', $cluster['GalaxyCluster']['synonyms_string']);
                    unset($cluster['GalaxyElement']);
                    $allClusters[$cluster['GalaxyCluster']['id']] = $cluster['GalaxyCluster'];
                }
            }
        }
        return $allClusters;
    }

    public function extractAttributeTagsNameFromEvent(&$event, $to_extract='both')
    {
        $attribute_tags_name = array('tags' => array(), 'clusters' => array());
        foreach ($event['Attribute'] as $i => $attribute) {
            if ($to_extract == 'tags' || $to_extract == 'both') {
                foreach ($attribute['AttributeTag'] as $tag) {
                    $attribute_tags_name['tags'][] = $tag['Tag']['name'];
                }
            }
            if ($to_extract == 'clusters' || $to_extract == 'both') {
                foreach ($attribute['Galaxy'] as $galaxy) {
                    foreach ($galaxy['GalaxyCluster'] as $cluster) {
                        $attribute_tags_name['clusters'][] = $cluster['tag_name'];
                    }
                }
            }
        }
        foreach ($event['Object'] as $i => $object) {
            if (!empty($object['Attribute'])) {
                foreach ($object['Attribute'] as $j => $object_attribute) {
                    if ($to_extract == 'tags' || $to_extract == 'both') {
                        foreach ($object_attribute['AttributeTag'] as $tag) {
                            $attribute_tags_name['tags'][] = $tag['Tag']['name'];
                        }
                    }
                    if ($to_extract == 'clusters' || $to_extract == 'both') {
                        foreach ($object_attribute['Galaxy'] as $galaxy) {
                            foreach ($galaxy['GalaxyCluster'] as $cluster) {
                                $attribute_tags_name['clusters'][] = $cluster['tag_name'];
                            }
                        }
                    }
                }
            }
        }
        $attribute_tags_name['tags'] = array_diff_key($attribute_tags_name['tags'], $attribute_tags_name['clusters']); // de-dup if needed.
        return $attribute_tags_name;
    }

}
