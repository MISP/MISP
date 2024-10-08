<?php
App::uses('AppModel', 'Model');

/**
 * @property Event $Event
 * @property Tag $Tag
 */
class EventTag extends AppModel
{
    public $actsAs = array('AuditLog', 'Containable');

    public $validate = array(
        'event_id' => [
            'rule' => 'numeric',
            'required' => true,
        ],
        'tag_id' => [
            'rule' => 'numeric',
            'required' => true,
        ],
    );

    public $belongsTo = array(
        'Event',
        'Tag'
    );

    public function afterSave($created, $options = array())
    {
        parent::afterSave($created, $options);
        $pubToZmq = Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_tag_notifications_enable');
        $kafkaTopic = $this->kafkaTopic('tag');
        $triggerCallable = $this->isTriggerCallable('tag-attached-after-save');
        if ($pubToZmq || $kafkaTopic) {
            $tag = $this->find('first', array(
                'recursive' => -1,
                'conditions' => array('EventTag.id' => $this->id),
                'contain' => array('Tag')
            ));
            $tag['Tag']['event_id'] = $tag['EventTag']['event_id'];
            $tag['Tag']['local'] = $tag['EventTag']['local'];
            $tag = array('Tag' => $tag['Tag']);
            if ($pubToZmq) {
                $pubSubTool = $this->getPubSubTool();
                $pubSubTool->tag_save($tag, 'attached to event');
            }
            if ($kafkaTopic) {
                $kafkaPubTool = $this->getKafkaPubTool();
                $kafkaPubTool->publishJson($kafkaTopic, $tag, 'attached to event');
            }
            if ($triggerCallable) {
                $workflowErrors = [];
                $logging = [
                    'model' => 'EventTag',
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
                    'conditions' => array('EventTag.id' => $this->id),
                    'contain' => array('Tag')
                ));
                $tag['Tag']['event_id'] = $tag['EventTag']['event_id'];
                $tag = array('Tag' => $tag['Tag']);
                if ($pubToZmq) {
                    $pubSubTool = $this->getPubSubTool();
                    $pubSubTool->tag_save($tag, 'detached from event');
                }
                if ($kafkaTopic) {
                    $kafkaPubTool = $this->getKafkaPubTool();
                    $kafkaPubTool->publishJson($kafkaTopic, $tag, 'detached from event');
                }
            }
        }
    }

    public function softDelete($id)
    {
        $this->delete($id);
    }

    public function handleEventTag($event_id, $tag, &$nothingToChange = false)
    {
        if (empty($tag['deleted'])) {
            $result = $this->attachTagToEvent($event_id, $tag, $nothingToChange);
        } else {
            $result = $this->detachTagFromEvent($event_id, $tag['id'], null, $nothingToChange);
        }
        return $result;
    }

    /**
     * @param int $event_id
     * @param array $tag
     * @param bool $nothingToChange
     * @return bool
     * @throws Exception
     */
    public function attachTagToEvent($event_id, array $tag, &$nothingToChange = false)
    {
        $existingAssociation = $this->find('first', [
            'conditions' => [
                'tag_id' => $tag['id'],
                'event_id' => $event_id,
            ],
            'recursive' => -1
        ]);
        if (!$existingAssociation) {
            $this->create();
            if (
                !$this->save(
                    [
                        'event_id' => $event_id,
                        'tag_id' => $tag['id'],
                        'relationship_type' => !empty($tag['relationship_type']) ? $tag['relationship_type'] : null,
                        'local' => !empty($tag['local'])
                    ]
                )
            ) {
                return false;
            }
        } else {
            if (isset($tag['relationship_type']) && $existingAssociation['EventTag']['relationship_type'] != $tag['relationship_type']) {
                $existingAssociation['EventTag']['relationship_type'] = $tag['relationship_type'];
                $this->save($existingAssociation);
            }
            $nothingToChange = true;
        }
        return true;
    }

    /**
     * @param int $event_id
     * @param int $tag_id
     * @param bool $nothingToChange
     * @return bool
     */
    public function detachTagFromEvent($event_id, $tag_id, $local, &$nothingToChange = false)
    {
        $conditions = [
            'tag_id' => $tag_id,
            'event_id' => $event_id,
        ];
        if (!is_null($local)) {
            $conditions['local'] = !empty($local);
        }
        $existingAssociation = $this->find('first', array(
            'recursive' => -1,
            'fields' => ['id'],
            'conditions' => $conditions,
        ));

        if ($existingAssociation) {
            $result = $this->delete($existingAssociation['EventTag']['id']);
            if ($result) {
                return true;
            }
        } else {
            $nothingToChange = true;
        }
        return false;
    }

    /**
     * Find all of the event Ids that belong to the accepted tags and the rejected tags
     * @param array $accept
     * @param array $reject
     * @return array[]
     */
    public function fetchEventTagIds(array $accept = array(), array $reject = array())
    {
        $acceptIds = array();
        $rejectIds = array();
        if (!empty($accept)) {
            $acceptIds = $this->findEventIdsByTagNames($accept);
            if (empty($acceptIds)) {
                $acceptIds = [-1];
            }
        }
        if (!empty($reject)) {
            $rejectIds = $this->findEventIdsByTagNames($reject);
        }
        return array($acceptIds, $rejectIds);
    }

    /**
     * @param array $tagIdsOrNames
     * @return array|int|null
     */
    private function findEventIdsByTagNames(array $tagIdsOrNames)
    {
        $conditions = [];
        foreach ($tagIdsOrNames as $tagIdOrName) {
            if (is_numeric($tagIdOrName)) {
                $conditions[] = array('Tag.id' => $tagIdOrName);
            } else {
                $conditions[] = array('LOWER(Tag.name)' => mb_strtolower($tagIdOrName));
            }
        }
        return $this->find('column', array(
            'recursive' => -1,
            'contain' => 'Tag',
            'conditions' => ['OR' => $conditions],
            'fields' => ['EventTag.event_id'],
        ));
    }

    public function getSortedTagList($context = false)
    {
        $tag_counts = $this->find('all', array(
            'recursive' => -1,
            'fields' => array('tag_id', 'count(*)'),
            'group' => array('tag_id'),
            'contain' => array('Tag.name')
        ));
        $temp = array();
        $tags = array();
        foreach ($tag_counts as $tag_count) {
            $temp[$tag_count['Tag']['name']] = array(
                'tag_id' => $tag_count['Tag']['id'],
                'eventCount' => $tag_count[0]['count(*)'],
                'name' => $tag_count['Tag']['name'],
            );
            $tags[$tag_count['Tag']['name']] = $tag_count[0]['count(*)'];
        }
        arsort($tags);
        foreach ($tags as $k => $v) {
            $tags[$k] = $temp[$k];
        }
        return $tags;
    }

    /**
     * @param int $tagId
     * @param array $user
     * @return int
     */
    public function countForTag($tagId, array $user)
    {
        $count = $this->countForTags([$tagId], $user);
        return isset($count[$tagId]) ? (int)$count[$tagId] : 0;
    }

    /**
     * @param array $tagIds
     * @param array $user
     * @return array Key is tag ID, value is event count that user can see
     */
    public function countForTags(array $tagIds, array $user)
    {
        if (empty($tagIds)) {
            return [];
        }
        $conditions = $this->Event->createEventConditions($user);
        $conditions['AND']['EventTag.tag_id'] = $tagIds;
        $this->virtualFields['event_count'] = 'COUNT(EventTag.id)';
        $counts = $this->find('list', [
            'recursive' => -1,
            'contain' => ['Event'],
            'fields' => ['EventTag.tag_id', 'event_count'],
            'conditions' => $conditions,
            'group' => ['EventTag.tag_id'],
        ]);
        unset($this->virtualFields['event_count']);
        return $counts;
    }

    public function getTagScores($eventId=0, $allowedTags=array(), $propagateToAttribute=false)
    {
        if ($propagateToAttribute) {
            $eventTagScores = $this->find('all', array(
                'recursive' => -1,
                'conditions' => array('Tag.id !=' => null),
                'contain' => array(
                    'Event',
                    'Tag' => array(
                        'conditions' => array('name' => $allowedTags)
                    )
                ),
                'fields' => array('Tag.name', 'Event.attribute_count')
            ));
        } else {
            $conditions = array('Tag.id !=' => null);
            if ($eventId != 0) {
                $conditions['event_id'] = $eventId;
            }
            $eventTagScores = $this->find('all', array(
                'recursive' => -1,
                'conditions' => $conditions,
                'contain' => array(
                    'Tag' => array(
                        'conditions' => array('name' => $allowedTags)
                    )
                ),
                'group' => array('tag_id', 'Tag.name', 'Tag.id'),
                'fields' => array('Tag.name', 'EventTag.tag_id', 'count(EventTag.tag_id) as score')
            ));
        }

        // arrange data
        $scores = array();
        $maxScore = 0;
        foreach ($eventTagScores as $item) {
            $score = isset($item['Event']) ? $item['Event']['attribute_count'] : $item[0]['score'];
            $name = $item['Tag']['name'];
            if (in_array($name, $allowedTags)) {
                $maxScore = $score > $maxScore ? $score : $maxScore;
                if (!isset($scores[$name])) {
                    $scores[$name] = 0;
                }
                $scores[$name] += $score;
            }
        }
        return array('scores' => $scores, 'maxScore' => $maxScore);
    }

    // Fetch all tags contained in an event (both event and attributes) ignoring the occurrence. No ACL
    public function getTagScoresUniform($eventId=0, $allowedTags=array())
    {
        $conditions = array('Tag.id !=' => null);
        if ($eventId != 0) {
            $conditions['event_id'] = $eventId;
        }
        $event_tag_scores = $this->find('all', array(
            'recursive' => -1,
            'conditions' => $conditions,
            'contain' => array(
                'Tag' => array(
                    'conditions' => array('name' => $allowedTags)
                )
            ),
            'fields' => array('Tag.name', 'EventTag.event_id')
        ));
        $attribute_tag_scores = $this->Event->Attribute->AttributeTag->find('all', array(
            'recursive' => -1,
            'conditions' => $conditions,
            'contain' => array(
                'Tag' => array(
                    'conditions' => array('name' => $allowedTags)
                )
            ),
            'fields' => array('Tag.name', 'AttributeTag.event_id')
        ));

        $score_aggregation = array();
        foreach ($event_tag_scores as $event_tag_score) {
            $score_aggregation[$event_tag_score['Tag']['name']][$event_tag_score['EventTag']['event_id']] = 1;
        }
        foreach ($attribute_tag_scores as $attribute_tag_score) {
            $score_aggregation[$attribute_tag_score['Tag']['name']][$attribute_tag_score['AttributeTag']['event_id']] = 1;
        }
        $scores = array('scores' => array(), 'maxScore' => 0);
        foreach ($score_aggregation as $name => $array_ids) {
            $event_count = count($array_ids);
            $scores['scores'][$name] = $event_count;
            $scores['maxScore'] = $event_count > $scores['maxScore'] ? $event_count : $scores['maxScore'];
        }
        return $scores;
    }
}
