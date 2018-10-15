<?php
App::uses('AppModel', 'Model');

class EventTag extends AppModel
{
    public $actsAs = array('Containable');

    public $validate = array(
        'event_id' => array(
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
        'Event',
        'Tag'
    );

    public function afterSave($created, $options = array())
    {
        parent::afterSave($created, $options);
        if (Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_tag_notifications_enable')) {
            $pubSubTool = $this->getPubSubTool();
            $tag = $this->find('first', array(
                'recursive' => -1,
                'conditions' => array('EventTag.id' => $this->id),
                'contain' => array('Tag')
            ));
            $tag['Tag']['event_id'] = $tag['EventTag']['event_id'];
            $tag = array('Tag' => $tag['Tag']);
            $pubSubTool->tag_save($tag, 'attached to event');
        }
    }

    public function beforeDelete($cascade = true)
    {
        if (Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_tag_notifications_enable')) {
            if (!empty($this->id)) {
                $pubSubTool = $this->getPubSubTool();
                $tag = $this->find('first', array(
                    'recursive' => -1,
                    'conditions' => array('EventTag.id' => $this->id),
                    'contain' => array('Tag')
                ));
                $tag['Tag']['event_id'] = $tag['EventTag']['event_id'];
                $tag = array('Tag' => $tag['Tag']);
                $pubSubTool->tag_save($tag, 'detached from event');
            }
        }
    }

    // take an array of tag names to be included and an array with tagnames to be excluded and find all event IDs that fit the criteria
    public function getEventIDsFromTags($includedTags, $excludedTags)
    {
        $conditions = array();
        if (!empty($includedTags)) {
            $conditions['OR'] = array('name' => $includedTags);
        }
        if (!empty($excludedTags)) {
            $conditions['NOT'] = array('name' => $excludedTags);
        }
        $tags = $this->Tag->find('all', array(
            'recursive' => -1,
            'fields' => array('id', 'name'),
            'conditions' => $conditions
        ));
        $tagIDs = array();
        foreach ($tags as $tag) {
            $tagIDs[] = $tag['Tag']['id'];
        }
        $eventTags = $this->find('all', array(
            'recursive' => -1,
            'conditions' => array('tag_id' => $tagIDs)
        ));
        $eventIDs = array();
        foreach ($eventTags as $eventTag) {
            $eventIDs[] = $eventTag['EventTag']['event_id'];
        }
        $eventIDs = array_unique($eventIDs);
        return $eventIDs;
    }

    public function attachTagToEvent($event_id, $tag_id)
    {
        $existingAssociation = $this->find('first', array(
            'recursive' => -1,
            'conditions' => array(
                'tag_id' => $tag_id,
                'event_id' => $event_id
            )
        ));
        if (empty($existingAssociation)) {
            $this->create();
            if (!$this->save(array('event_id' => $event_id, 'tag_id' => $tag_id))) {
                return false;
            }
        }
        return true;
    }

    public function getSortedTagList($context = false)
    {
        $conditions = array();
        $tag_counts = $this->find('all', array(
                'recursive' => -1,
                'fields' => array('tag_id', 'count(*)'),
                'group' => array('tag_id'),
                'conditions' => $conditions,
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
    
    public function countForTag($tag_id, $user)
    {
        return $this->find('count', array(
            'recursive' => -1,
            'conditions' => array('EventTag.tag_id' => $tag_id)
        ));
    }

    public function getTagScores($eventId=0, $allowedTags=array())
    {
        // get score of galaxy
        $db = $this->getDataSource();
        $statementArray = array(
            'fields' => array('event_tag.tag_id as id', 'count(event_tag.tag_id) as value'),
            'table' => $db->fullTableName($this),
            'alias' => 'event_tag',
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
}
