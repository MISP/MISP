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

    public function countForTag($tag_id, $user)
    {
        return $this->find('count', array(
            'recursive' => -1,
            'conditions' => array('AttributeTag.tag_id' => $tag_id)
        ));
    }

    public function getTagScores($eventId=0, $allowedTags=array())
    {
        // get score of galaxy
        $db = $this->getDataSource();
        $statementArray = array(
            'fields' => array('attr_tag.tag_id as id', 'count(attr_tag.tag_id) as value'),
            'table' => $db->fullTableName($this),
            'alias' => 'attr_tag',
            'group' => 'tag_id'
        );
        if ($eventId != 0) {
            $statementArray['conditions'] = array('event_id' => $eventId);
        }
        // tag along with its occurence in the event
        $subQuery = $db->buildStatement(
            $statementArray,
            $this
        );
        $subQueryExpression = $db->expression($subQuery)->value;
        // get related galaxies
        $attributeTagScores = $this->query("SELECT name, value FROM (" . $subQueryExpression . ") AS score, tags WHERE tags.id=score.id;");

        // arrange data
        $scores = array();
        $maxScore = 0;
        foreach ($attributeTagScores as $item) {
            $score = $item['score']['value'];
            $name = $item['tags']['name'];
            if (in_array($name, $allowedTags)) {
                $maxScore = $score > $maxScore ? $score : $maxScore;
                $scores[$name] = $score;
            }
        }
        return array('scores' => $scores, 'maxScore' => $maxScore);
    }


    // find all tags that belong to a list of attributes (contained in the same event)
    public function getAttributesTags($user, $requestedEventId, $attributeIds=false) {
        $conditions = array('Attribute.event_id' => $requestedEventId);
        if (is_array($attributeIds) && $attributeIds !== false) {
            $conditions['Attribute.id'] = $attributeIds;
        }

        $allTags = array();
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

        $allTags = array();
        foreach ($attributes as $attribute) {
            $attributeTags = $attribute['AttributeTag'];
            foreach ($attributeTags as $k => $attributeTag) {
                if (!isset($cluster_names[$attributeTag['Tag']['name']])) {
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
                $new_tags = Hash::combine($attribute['AttributeTag'], '{n}.Tag.name', '{n}.Tag.name');
                $attribute_tags_name['tags'] = array_merge($attribute_tags_name['tags'], $new_tags);
            }
            if ($to_extract == 'clusters' || $to_extract == 'both') {
                $new_tags = Hash::combine($attribute['Galaxy'], '{n}.GalaxyCluster.{n}.tag_name', '{n}.GalaxyCluster.{n}.tag_name');
                $attribute_tags_name['clusters'] = array_merge($attribute_tags_name['clusters'], $new_tags);
            }
        }
        foreach ($event['Object'] as $i => $object) {
            foreach ($object['Attribute'] as $j => $object_attribute) {
                if ($to_extract == 'tags' || $to_extract == 'both') {
                    $new_tags = Hash::combine($object_attribute['AttributeTag'], '{n}.Tag.name', '{n}.Tag.name');
                    $attribute_tags_name['tags'] = array_merge($attribute_tags_name['tags'], $new_tags);
                }
                if ($to_extract == 'clusters' || $to_extract == 'both') {
                    $new_tags = Hash::combine($object_attribute['Galaxy'], '{n}.GalaxyCluster.{n}.tag_name', '{n}.GalaxyCluster.{n}.tag_name');
                    $attribute_tags_name['clusters'] = array_merge($attribute_tags_name['clusters'], $new_tags);
                }
            }
        }
        $attribute_tags_name['tags'] = array_diff_key($attribute_tags_name['tags'], $attribute_tags_name['clusters']);
        return $attribute_tags_name;
    }

}
