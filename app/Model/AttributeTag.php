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
        if (Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_tag_notifications_enable')) {
            $pubSubTool = $this->getPubSubTool();
            $tag = $this->find('first', array(
                'recursive' => -1,
                'conditions' => array('AttributeTag.id' => $this->id),
                'contain' => array('Tag')
            ));
            $tag['Tag']['attribute_id'] = $tag['AttributeTag']['attribute_id'];
            $tag['Tag']['event_id'] = $tag['AttributeTag']['event_id'];
            $tag = array('Tag' => $tag['Tag']);
            $pubSubTool->tag_save($tag, 'attached to attribute');
        }
    }

    public function beforeDelete($cascade = true)
    {
        if (Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_tag_notifications_enable')) {
            if (!empty($this->id)) {
                $pubSubTool = $this->getPubSubTool();
                $tag = $this->find('first', array(
                    'recursive' => -1,
                    'conditions' => array('AttributeTag.id' => $this->id),
                    'contain' => array('Tag')
                ));
                $tag['Tag']['attribute_id'] = $tag['AttributeTag']['attribute_id'];
                $tag['Tag']['event_id'] = $tag['AttributeTag']['event_id'];
                $tag = array('Tag' => $tag['Tag']);
                $pubSubTool->tag_save($tag, 'detached from attribute');
            }
        }
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


    // find all tags that belong to a list of attributes (contains in the same event)
    public function getAttributesTags($user, $requestedEventId, $attributeIds) {
        if ($attributeIds === null) {
            throw new NotFoundException(__('Invalid attributes'));
        }

        $allTags = array();
        foreach ($attributeIds as $id) {
            $attribute = $this->Attribute->fetchAttributes($user, array('conditions' => array('Attribute.id' => $id)));
            if (empty($attribute)) {
                throw new MethodNotAllowedException('Invalid attribute.');
            }

            $eventId = $attribute[0]['Attribute']['event_id'];
            if ($eventId != $requestedEventId) { // only takes tags of attributes belonging to the same event
                continue;
            }
            $attributeTags = $this->find('all', array(
                'conditions' => array(
                    'attribute_id' => $id
                ),
                'contain' => array('Tag'),
                'fields' => array('Tag.id', 'Tag.colour', 'Tag.name'),
            ));
            $this->GalaxyCluster = ClassRegistry::init('GalaxyCluster');
            $cluster_names = $this->GalaxyCluster->find('list', array('fields' => array('GalaxyCluster.tag_name'), 'group' => array('GalaxyCluster.tag_name', 'GalaxyCluster.id')));
            foreach ($attributeTags as $k => $attributeTag) {
                if (in_array($attributeTag['Tag']['name'], $cluster_names)) {
                    unset($attributeTags[$k]);
                }
            }
            foreach ($attributeTags as $k => $attributeTag) {
                $allTags[$attributeTag['Tag']['id']] = $attributeTag['Tag'];
            }
        }
        return $allTags;
    }

    // find all galaxies that belong to a list of attributes (contains in the same event)
    public function getAttributesClusters($user, $requestedEventId, $attributeIds) {
        if ($attributeIds === null) {
            throw new NotFoundException(__('Invalid attributes'));
        }

        $allClusters = array();
        foreach ($attributeIds as $id) {
            $attribute = $this->Attribute->fetchAttributes($user, array('conditions' => array('Attribute.id' => $id)));
            if (empty($attribute)) {
                throw new MethodNotAllowedException('Invalid attribute.');
            }
            $eventId = $attribute[0]['Attribute']['event_id'];
            if ($eventId != $requestedEventId) { // only takes tags of attributes belonging to the same event
                continue;
            }
            $attributeTags = $this->find('all', array(
                'conditions' => array(
                    'attribute_id' => $id
                ),
                'contain' => array('Tag'),
                'fields' => array('Tag.id', 'Tag.colour', 'Tag.name'),
            ));

            $this->GalaxyCluster = ClassRegistry::init('GalaxyCluster');
            $cluster_names = $this->GalaxyCluster->find('list', array('fields' => array('GalaxyCluster.tag_name'), 'group' => array('GalaxyCluster.tag_name', 'GalaxyCluster.id')));

            foreach ($attributeTags as $k => $attributeTag) {
                if (in_array($attributeTag['Tag']['name'], $cluster_names)) {
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

}
