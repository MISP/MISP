<?php
App::uses('AppModel', 'Model');

class Tag extends AppModel
{
    public $useTable = 'tags';

    public $displayField = 'name';

    public $actsAs = array(
            'SysLogLogable.SysLogLogable' => array( // TODO Audit, logable
                    'roleModel' => 'Tag',
                    'roleKey' => 'tag_id',
                    'change' => 'full'
            ),
            'Containable'
    );

    public $validate = array(
            'name' => array(
                    'required' => array(
                        'rule' => array('notBlank', 'name'),
                        'message' => 'This field is required.'
                    ),
                    'valueNotEmpty' => array(
                        'rule' => array('valueNotEmpty', 'name'),
                    ),
                    'unique' => array(
                            'rule' => 'isUnique',
                            'message' => 'A similar name already exists.',
                    ),
            ),
            'colour' => array(
                    'valueNotEmpty' => array(
                        'rule' => array('valueNotEmpty', 'colour'),
                    ),
                    'userdefined' => array(
                            'rule' => 'validateColour',
                            'message' => 'Colour has to be in the RGB format (#FFFFFF)',
                    ),
            ),
    );

    public $hasMany = array(
        'EventTag' => array(
            'className' => 'EventTag',
            'dependent' => true
        ),
        'TemplateTag',
        'FavouriteTag' => array(
            'dependent' => true
        ),
        'AttributeTag' => array(
            'dependent' => true
        ),
        'TagCollectionTag' => array(
            'dependent' => true
        )
    );

    public $belongsTo = array(
        'Organisation' => array(
            'className' => 'Organisation',
            'foreignKey' => 'org_id',
        ),
        'User' => array(
            'className' => 'User',
            'foreignKey' => 'user_id',
        )
    );

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        if (!isset($this->data['Tag']['org_id'])) {
            $this->data['Tag']['org_id'] = 0;
        }
        if (!isset($this->data['Tag']['user_id'])) {
            $this->data['Tag']['user_id'] = 0;
        }
        if (!isset($this->data['Tag']['hide_tag'])) {
            $this->data['Tag']['hide_tag'] = Configure::read('MISP.incoming_tags_disabled_by_default') ? 1 : 0;
        }
        if (!isset($this->data['Tag']['exportable'])) {
            $this->data['Tag']['exportable'] = 1;
        }
        return true;
    }

    public function afterSave($created, $options = array())
    {
        parent::afterSave($created, $options);
        $pubToZmq = Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_tag_notifications_enable');
        $kafkaTopic = Configure::read('Plugin.Kafka_tag_notifications_topic');
        $pubToKafka = Configure::read('Plugin.Kafka_enable') && Configure::read('Plugin.Kafka_tag_notifications_enable') && !empty($kafkaTopic);
        if ($pubToZmq || $pubToKafka) {
            $tag = $this->find('first', array(
                'recursive' => -1,
                'conditions' => array('Tag.id' => $this->id)
            ));
            $action = $created ? 'add' : 'edit';
            if ($pubToZmq) {
                $pubSubTool = $this->getPubSubTool();
                $pubSubTool->tag_save($tag, $action);
            }
            if ($pubToKafka) {
                $kafkaPubTool = $this->getKafkaPubTool();
                $kafkaPubTool->publishJson($kafkaTopic, $tag, $action);
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
                    'conditions' => array('Tag.id' => $this->id)
                ));
                if ($pubToZmq) {
                    $pubSubTool = $this->getPubSubTool();
                    $pubSubTool->tag_save($tag, 'delete');
                }
                if ($pubToKafka) {
                    $kafkaPubTool = $this->getKafkaPubTool();
                    $kafkaPubTool->publishJson($kafkaTopic, $tag, 'delete');
                }
            }
        }
    }

    public function validateColour($fields)
    {
        if (!preg_match('/^#[0-9a-f]{6}$/i', $fields['colour'])) {
            return false;
        }
        return true;
    }

    public function lookupTagIdFromName($tagName)
    {
        $tagId = $this->find('first', array(
            'conditions' => array('LOWER(Tag.name)' => strtolower($tagName)),
            'recursive' => -1,
            'fields' => array('Tag.id')
        ));
        if (empty($tagId)) {
            return -1;
        } else {
            return $tagId['Tag']['id'];
        }
    }

    // find all of the tag ids that belong to the accepted tag names and the rejected tag names
    public function fetchTagIdsFromFilter($accept = array(), $reject = array())
    {
        $results = array(0 => array(), 1 => array());
        if (!empty($accept)) {
            foreach ($accept as $tag) {
                $temp = $this->lookupTagIdFromName($tag);
                if (!in_array($temp, $results[0])) {
                    $results[0][] = $temp;
                }
            }
        }
        if (!empty($reject)) {
            foreach ($reject as $tag) {
                $temp = $this->lookupTagIdFromName($tag);
                if (!in_array($temp, $results[1])) {
                    $results[1][] = $temp;
                }
            }
        }
        return $results;
    }

    // find all of the event Ids that belong to the accepted tags and the rejected tags
    public function fetchEventTagIds($accept = array(), $reject = array())
    {
        $acceptIds = array();
        $rejectIds = array();
        if (!empty($accept)) {
            $acceptIds = $this->findEventIdsByTagNames($accept);
            if (empty($acceptIds)) {
                $acceptIds[] = -1;
            }
        }
        if (!empty($reject)) {
            $rejectIds = $this->findEventIdsByTagNames($reject);
        }
        return array($acceptIds, $rejectIds);
    }

    // find all of the tag Ids that belong to the accepted tags and the rejected tags
    public function fetchTagIdsSimple($tags = array())
    {
        $results = array();
        if (!empty($tags)) {
            $results = $this->findTagIdsByTagNames($tags);
            if (empty($results)) {
                $results[] = -1;
            }
        }
        return $results;
    }

    // find all of the tag Ids that belong to the accepted tags and the rejected tags
    public function fetchTagIds($accept = array(), $reject = array())
    {
        $acceptIds = array();
        $rejectIds = array();
        if (!empty($accept)) {
            $acceptIds = $this->findTagIdsByTagNames($accept);
            if (empty($acceptIds)) {
                $acceptIds[] = -1;
            }
        }
        if (!empty($reject)) {
            $rejectIds = $this->findTagIdsByTagNames($reject);
        }
        return array($acceptIds, $rejectIds);
    }

    // pass a list of tag names to receive a list of matched tag IDs
    public function findTagIdsByTagNames($array)
    {
        $ids = array();
        $tag_ids = array();
        if (!is_array($array)) {
            $array = array($array);
        }
        foreach ($array as $k => $tag) {
            if (is_numeric($tag)) {
                $tag_ids[] = $tag;
                unset($array[$k]);
            }
        }
        $array = array_values($array);
        if (!empty($array)) {
            foreach ($array as $a) {
                $conditions['OR'][] = array('Tag.name like' => $a);
            }
            $params = array(
                    'recursive' => 1,
                    'conditions' => $conditions,
                    'fields' => array('Tag.id', 'Tag.id')
            );
            $result = $this->find('list', $params);
            $tag_ids = array_merge($result, $tag_ids);
        }
        return array_values($tag_ids);
    }

    public function findEventIdsByTagNames($array)
    {
        $ids = array();
        foreach ($array as $a) {
            if (is_numeric($a)) {
                $conditions['OR'][] = array('id' => $a);
            } else {
                $conditions['OR'][] = array('LOWER(name) like' => strtolower($a));
            }
        }
        $params = array(
                'recursive' => 1,
                'contain' => 'EventTag',
                'conditions' => $conditions
        );
        $result = $this->find('all', $params);
        foreach ($result as $tag) {
            foreach ($tag['EventTag'] as $eventTag) {
                $ids[] = $eventTag['event_id'];
            }
        }
        return $ids;
    }

    public function findAttributeIdsByAttributeTagNames($array)
    {
        $ids = array();
        foreach ($array as $a) {
            $conditions['OR'][] = array('LOWER(name) LIKE' => strtolower($a));
        }
        $params = array(
                'recursive' => 1,
                'contain' => 'AttributeTag',
                'conditions' => $conditions
        );
        $result = $this->find('all', $params);
        foreach ($result as $tag) {
            foreach ($tag['AttributeTag'] as $attributeTag) {
                $ids[] = $attributeTag['attribute_id'];
            }
        }
        return $ids;
    }

    public function captureTag($tag, $user)
    {
        $existingTag = $this->find('first', array(
                'recursive' => -1,
                'conditions' => array('LOWER(name)' => strtolower($tag['name']))
        ));
        if (empty($existingTag)) {
            if ($user['Role']['perm_tag_editor']) {
                $this->create();
                if (!isset($tag['colour']) || empty($tag['colour'])) {
                    $tag['colour'] = $this->random_color();
                }
                $tag = array(
                        'name' => $tag['name'],
                        'colour' => $tag['colour'],
                        'exportable' => isset($tag['exportable']) ? $tag['exportable'] : 1,
                        'org_id' => 0,
                        'user_id' => 0,
                        'hide_tag' => Configure::read('MISP.incoming_tags_disabled_by_default') ? 1 : 0
                );
                $this->save($tag);
                return $this->id;
            } else {
                return false;
            }
        } else {
            if (
                !$user['Role']['perm_site_admin'] &&
                (
                    (
                        $existingTag['Tag']['org_id'] != 0 &&
                        $existingTag['Tag']['org_id'] != $user['org_id']
                    ) ||
                    (
                        $existingTag['Tag']['user_id'] != 0 &&
                        $existingTag['Tag']['user_id'] != $user['id']
                    )
                )
            ) {
                return false;
            }
        }
        return $existingTag['Tag']['id'];
    }

    // find all tags that belong to a given eventId
    public function findEventTags($eventId)
    {
        $tags = array();
        $params = array(
                'recursive' => 1,
                'contain' => 'EventTag',
        );
        $result = $this->find('all', $params);
        foreach ($result as $tag) {
            foreach ($tag['EventTag'] as $eventTag) {
                if ($eventTag['event_id'] == $eventId) {
                    $tags[] = $tag['Tag'];
                }
            }
        }
        return $tags;
    }

    public function random_color()
    {
        $colour = '#';
        for ($i = 0; $i < 3; $i++) {
            $colour .= str_pad(dechex(mt_rand(0, 255)), 2, '0', STR_PAD_LEFT);
        }
        return $colour;
    }

    public function quickAdd($name, $colour = false, $numerical_value = null)
    {
        $this->create();
        if ($colour === false) {
            $colour = $this->random_color();
        }
        $data = array(
            'name' => $name,
            'colour' => $colour,
            'exportable' => 1
        );
        if (!is_null($numerical_value)) {
            $data['numerical_value'] = $numerical_value;
        }
        return ($this->save($data));
    }

    public function quickEdit($tag, $name, $colour, $hide = false, $numerical_value = null)
    {
        if ($tag['Tag']['colour'] !== $colour || $tag['Tag']['name'] !== $name || $hide !== false || $tag['Tag']['numerical_value'] !== $numerical_value) {
            $tag['Tag']['name'] = $name;
            $tag['Tag']['colour'] = $colour;
            if ($hide !== false) {
                $tag['Tag']['hide_tag'] = $hide;
            }
            if (!is_null($numerical_value)) {
                $tag['Tag']['numerical_value'] = $numerical_value;
            }
            return ($this->save($tag['Tag']));
        }
        return true;
    }

    public function disableTags($tags)
    {
        foreach ($tags as $k => $v) {
            $tags[$k]['Tag']['hide_tag'] = 1;
        }
        return ($this->saveAll($tags));
    }

    public function getTagsByName($tag_names, $containTagConnectors = true)
    {
        $contain = array('EventTag', 'AttributeTag');
        $tag_params = array(
                'recursive' => -1,
                'conditions' => array('name' => $tag_names)
        );
        if ($containTagConnectors) {
            $tag_params['contain'] = $contain;
        }
        $tags_temp = $this->find('all', $tag_params);
        $tags = array();
        foreach ($tags_temp as $temp) {
            $tags[strtoupper($temp['Tag']['name'])] = $temp;
        }
        return $tags;
    }

    public function getTagsForNamespace($namespace, $containTagConnectors = true)
    {

        $contain = array('EventTag', 'AttributeTag');
        $tag_params = array(
                'recursive' => -1,
                'conditions' => array('UPPER(name) LIKE' => strtoupper($namespace) . '%'),
        );
        if ($containTagConnectors) {
            $tag_params['contain'] = $contain;
        }
        $tags_temp = $this->find('all', $tag_params);
        $tags = array();
        foreach ($tags_temp as $temp) {
            $tags[strtoupper($temp['Tag']['name'])] = $temp;
        }
        return $tags;
    }

    public function fetchSimpleEventsForTag($id, $user, $useTagName = false)
    {
        if ($useTagName) {
            $tag = $this->find('first', array(
                'recursive' => -1,
                'fields' => array('Tag.id'),
                'conditions' => array('Tag.name' => $id)
            ));
            if (empty($tag)) {
                return array();
            }
            $id = $tag['Tag']['id'];
        }
        $event_ids = $this->EventTag->find('list', array(
            'recursive' => -1,
            'conditions' => array('EventTag.tag_id' => $id),
            'fields'  => array('EventTag.event_id', 'EventTag.event_id'),
            'order' => array('EventTag.event_id')
        ));
        $params = array('conditions' => array('Event.id' => array_values($event_ids)));
        $events = $this->EventTag->Event->fetchSimpleEvents($user, $params, true);
        foreach ($events as $k => $event) {
            $event['Event']['Orgc'] = $event['Orgc'];
            $events[$k] = $event['Event'];
        }
        return $events;
    }

    public function fixMitreTags($user)
    {
        $full_print_buffer = '';
        $this->GalaxyCluster = Classregistry::init('GalaxyCluster');
        // first find all tags that are the bad tags:
        // - the enterprise-, pre- and mobile-attack
        // - the old version of the MITRE tag (without Txx, Pxx, ...)
        $mitre_categories = array('attack-pattern', 'course-of-action', 'intrusion-set', 'malware', 'mitre-tool');
        $mitre_stages = array('enterprise-attack', 'pre-attack', 'mobile-attack');
        $cluster_names = $this->GalaxyCluster->find('list',
            array('fields' => array('GalaxyCluster.tag_name'),
                  'group' => array('GalaxyCluster.id', 'GalaxyCluster.tag_name'),
                  'conditions' => array('GalaxyCluster.tag_name LIKE' => 'misp-galaxy:mitre-%')
              ));
        // this is a mapping to keep track of what old tag we need to change (key) to what new tag(value)
        // key = old_tag_id, value = new_tag_name
        $mappings = array();
        // First find all tags which are the old format, but who's string needs to be updated
        // Example: mitre-malware="XAgentOSX" => mitre-malware="XAgentOSX - S0161"
        // Once found we will add these to a mapping
        foreach ($mitre_categories as $category) {
            $tag_start = 'misp-galaxy:mitre-' . $category;
            // print("<h2>### Searching for $category</h2>");
            $tags = $this->find('all', array(
                'conditions' => array('Tag.name LIKE' => $tag_start . '=%'),
                'recursive' => -1));
            // print_r($tags);
            foreach ($tags as $tag) {
                $old_tag_name = $tag['Tag']['name'];
                $old_tag_id = $tag['Tag']['id'];
                $old_tag_name_without_quote = rtrim($old_tag_name, '"') . ' -';
                foreach ($cluster_names as $cluster_name) {
                    // print("Searching for $old_tag_name in $cluster_name<br>");
                    if (strstr($cluster_name, $old_tag_name_without_quote)) {
                        // print("FOUND - $old_tag_name - $cluster_name<br/>");
                        $mappings[$old_tag_id] = $cluster_name;
                        break;
                    }
                }
            }
        }
        // Now find all tags that are from the enterprise, pre-attack and mobile-attack galaxies
        foreach ($mitre_stages as $stage) {
            foreach ($mitre_categories as $category) {
                $tag_start = 'misp-galaxy:mitre-' . $stage . '-' . $category;
                // print("<h2>### Searching for $stage-$category</h2>");
                $tags = $this->find('all', array(
                    'conditions' => array('Tag.name LIKE' => $tag_start . '=%'),
                    'recursive' => -1));
                // print_r($tags);
                foreach ($tags as $tag) {
                    $old_tag_name = $tag['Tag']['name'];
                    $old_tag_id = $tag['Tag']['id'];
                    $new_tag_name = str_replace($stage.'-', '', $old_tag_name);
                    // print("Changing $old_tag_name to $new_tag_name<br/>");
                    if (in_array($new_tag_name, $cluster_names)) {
                        // valid tag as it exists in the galaxies, add to mapping
                        $mappings[$old_tag_id] = $new_tag_name;
                    } else {
                        // invalid tag, do some more magic
                        // print("Invalid new tag ! $old_tag_name to $new_tag_name<br/>");
                        $old_tag_name_without_quote = rtrim($new_tag_name, '"');
                        $found = false;
                        foreach ($cluster_names as $cluster_name) {
                            // print("Searching for $old_tag_name in $cluster_name<br>");
                            if (strstr($cluster_name, $old_tag_name_without_quote)) {
                                // print("-> FOUND - $old_tag_name - $cluster_name<br/>");
                                $mappings[$old_tag_id] = $cluster_name;
                                $found = true;
                                break;
                            }
                        }
                        if (!$found) {
                            print("Issue with tag, could not find a substitution, skipping: $old_tag_name<br/>");
                        }
                    }

                }
            }
        }
        $full_print_buffer .= "<h2>Mappings</h2>";
        $full_print_buffer .= "<pre>". print_r($mappings, true) . "</pre>";
        // now we know which tags (they keys of the mapping) need to be changed
        // find all events and attributes using these tags and update them with the new version
        $this->EventTag = Classregistry::init('EventTag');
        $this->AttributeTag = Classregistry::init('AttributeTag');
        $this->Event = Classregistry::init('Event');
        $this->Attribute = Classregistry::init('Attribute');
        $full_print_buffer .= "<h2>Conversion</h2>";
        foreach ($mappings as $old_tag_id => $new_tag_name) {
            $print_buffer = "";
            $print_buffer .= "$old_tag_id => $new_tag_name<br/>";
            $changed = False;
            $new_tag = array(
                'name' => $new_tag_name,
                'colour' => '#0088cc');
            $new_tag_id = $this->captureTag($new_tag, $user);
            $print_buffer .= "&nbsp; New tag id $new_tag_id<br>";
            //
            // Events
            //
            $ets = $this->EventTag->find('all', array(
                'recursive' => -1,
                'conditions' => array('tag_id' => $old_tag_id),
                'contain' => array('Event')
            ));
            foreach ($ets as $et) {
                $event = $et['Event'];
                // skip events that are not from this instance or are locked (coming form another MISP)
                if ($event['locked'] || $event['org_id'] != $event['orgc_id']) {
                    $print_buffer .= "&nbsp; Skipping event ".$event['id']."... not from here<br>";
                    continue;
                }
                $changed = True;

                // remove the old EventTag
                $print_buffer .= "&nbsp; Deleting event_tag ".$et['EventTag']['id']." for event ".$event['id']."<br>";
                $this->EventTag->softDelete($et['EventTag']['id']);

                // add the new Tag to the event
                $new_et = array('EventTag' => array(
                    'event_id' => $event['id'],
                    'tag_id' => $new_tag_id
                ));

                // check if the tag is already attached to the event - WARNING if data structures change this might break
                $exists = $this->EventTag->find('first', array(
                    'recursive' => -1,
                    'conditions' => $new_et['EventTag']));
                if (empty($exists)) {
                    // tag not yet associated with event
                    $print_buffer .= "&nbsp; Saving new tag association: event_id=".$event['id']." tag_id=".$new_tag_id."<br>";
                    $this->EventTag->save($new_et);
                    // increment the Event timestamp and save the event
                    $print_buffer .= "&nbsp; Saving the event with incremented timestamp<br>";
                    $event['timestamp'] += 1;
                    $this->Event->save($event);
                } else {
                    $print_buffer .= "&nbsp; Not adding new tag as it's already associated to the event:  event_id=".$event['id']." tag_id=".$new_tag_id."<br>";
                }
            }

            //
            // Attributes with tags
            //
            // find all AttributeTags for this specific tag. We do not load the attribute immediately as it's faster/better to only do this additional lookup when needed. (data we need to change)
            $ats = $this->AttributeTag->find('all', array(
                'recursive' => -1,
                'conditions' => array('tag_id' => $old_tag_id),
            ));
            foreach ($ats as $at) {
                // $print_buffer .= "&nbsp; ".print_r($at, true)."<br>";
                $event = $this->Event->find('first', array(
                    'recursive' => -1,
                    'conditions' => array('id' => $at['AttributeTag']['event_id'])
                ))['Event'];
                // $print_buffer .= "<pre>".print_r($event, true)."</pre>";
                // skip events that are not from this instance or are locked (coming form another MISP)
                if ($event['locked'] || $event['org_id'] != $event['orgc_id']) {
                    $print_buffer .= "&nbsp; Skipping attribute for event ".$event['id']."... not from here<br>";
                    continue;
                }
                $attribute = $this->Attribute->find('first', array(
                    'recursive' => -1,
                    'conditions' => array('id' => $at['AttributeTag']['attribute_id'])
                ))['Attribute'];
                $changed = True;

                // remove the old AttributeTag
                $print_buffer .= "&nbsp; Deleting attribute_tag ".$at['AttributeTag']['id']." for attribute ".$attribute['id']." for event ".$event['id']."<br>";
                $this->AttributeTag->softDelete($at['AttributeTag']['id']);

                // add the new Tag to the event
                $new_at = array('AttributeTag' => array(
                    'event_id' => $event['id'],
                    'attribute_id' => $attribute['id'],
                    'tag_id' => $new_tag_id
                ));
                // check if the tag is already attached to the event - WARNING if data structures change this might break
                $exists = $this->AttributeTag->find('first', array(
                    'recursive' => -1,
                    'conditions' => $new_at['AttributeTag']));
                if (empty($exists)) {
                    // tag not yet associated with attribute
                    $print_buffer .= "&nbsp; Saving new tag association: attribute_id=".$attribute['id']." event_id=".$event['id']." tag_id=".$new_tag_id."<br>";
                    $this->AttributeTag->save($new_at);
                    // increment the Attribute/Event timestamp and save them
                    $print_buffer .= "&nbsp; Saving the attribute/event with incremented timestamp<br>";
                    $attribute['timestamp'] += 1;
                    $this->Attribute->save($attribute);
                    $event['timestamp'] += 1;
                    $this->Event->save($event);
                } else {
                    $print_buffer .= "&nbsp; Not adding new tag as it's already associated to the attribute: attribute_id=".$attribute['id']."  event_id=".$event['id']." tag_id=".$new_tag_id."<br>";
                }
            }

            if ($changed) {
                $full_print_buffer .= $print_buffer;
            } else {
                // print("Tag has no 'unlocked' events or attributes: $old_tag_id => $new_tag_name<br/>");
                // $full_print_buffer .= $print_buffer;
            }
        }
        return $full_print_buffer;
    }
}
