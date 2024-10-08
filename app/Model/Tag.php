<?php
App::uses('AppModel', 'Model');

/**
 * @property EventTag $EventTag
 * @property User $User
 * @property AttributeTag $AttributeTag
 * @property FavouriteTag $FavouriteTag
 * @property Organisation $Organisation
 */
class Tag extends AppModel
{
    public $useTable = 'tags';

    public $displayField = 'name';

    public $actsAs = array(
        'AuditLog',
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
        ),
        'GalaxyClusterRelationTag' => array(
            'dependent' => true
        ),
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

    const RE_GALAXY = '/misp-galaxy:[^:="]+="[^:="]+/i';
    const RE_CUSTOM_GALAXY = '/misp-galaxy:[^:="]+="[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}"/i';
    private $tagOverrides = false;

    public function beforeValidate($options = array())
    {
        $tag = &$this->data['Tag'];
        if (!isset($tag['org_id'])) {
            $tag['org_id'] = 0;
        }
        if (!isset($tag['user_id'])) {
            $tag['user_id'] = 0;
        }
        if (!isset($tag['hide_tag'])) {
            $tag['hide_tag'] = Configure::read('MISP.incoming_tags_disabled_by_default') ? 1 : 0;
        }
        if (!isset($tag['exportable'])) {
            $tag['exportable'] = 1;
        }
        if (!isset($tag['local_only'])) {
            $tag['local_only'] = 0;
        }
        if (isset($tag['name']) && strlen($tag['name']) >= 255) {
            $tag['name'] = substr($tag['name'], 0, 255);
        }
        $tag['is_galaxy'] = preg_match(self::RE_GALAXY, $tag['name']);
        $tag['is_custom_galaxy'] = preg_match(self::RE_CUSTOM_GALAXY, $tag['name']);
        return true;
    }

    public function afterSave($created, $options = array())
    {
        $pubToZmq = Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_tag_notifications_enable');
        $kafkaTopic = $this->kafkaTopic('tag');
        if ($pubToZmq || $kafkaTopic) {
            $tag = $this->find('first', array(
                'recursive' => -1,
                'conditions' => array('Tag.id' => $this->id)
            ));
            $action = $created ? 'add' : 'edit';
            if ($pubToZmq) {
                $pubSubTool = $this->getPubSubTool();
                $pubSubTool->tag_save($tag, $action);
            }
            if ($kafkaTopic) {
                $kafkaPubTool = $this->getKafkaPubTool();
                $kafkaPubTool->publishJson($kafkaTopic, $tag, $action);
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
                    'conditions' => array('Tag.id' => $this->id)
                ));
                if ($pubToZmq) {
                    $pubSubTool = $this->getPubSubTool();
                    $pubSubTool->tag_save($tag, 'delete');
                }
                if ($kafkaTopic) {
                    $kafkaPubTool = $this->getKafkaPubTool();
                    $kafkaPubTool->publishJson($kafkaTopic, $tag, 'delete');
                }
            }
        }
    }

    public function afterFind($results, $primary = false)
    {
        return $this->checkForOverride($results);
    }

    public function validateColour($fields)
    {
        if (!preg_match('/^#[0-9a-f]{6}$/i', $fields['colour'])) {
            return false;
        }
        return true;
    }

    /**
     * @param array $user
     * @param string $tagName
     * @return mixed|null
     */
    public function lookupTagIdForUser(array $user, $tagName)
    {
        $conditions = $this->createConditions($user);
        $conditions['LOWER(Tag.name)'] = mb_strtolower($tagName);

        $tagId = $this->find('first', array(
            'conditions' => $conditions,
            'recursive' => -1,
            'fields' => array('Tag.id'),
            'callbacks' => false,
        ));
        if (empty($tagId)) {
            return null;
        }
        return $tagId['Tag']['id'];
    }

    /**
     * @param string $tagName
     * @return int|mixed
     */
    public function lookupTagIdFromName($tagName)
    {
        $tagId = $this->find('first', array(
            'conditions' => array('LOWER(Tag.name)' => mb_strtolower($tagName)),
            'recursive' => -1,
            'fields' => array('Tag.id'),
            'callbacks' => false,
        ));
        if (empty($tagId)) {
            return -1;
        } else {
            return $tagId['Tag']['id'];
        }
    }

    /**
     * @param array $user
     * @param bool|null $isGalaxy
     * @return array|int|null
     */
    public function fetchUsableTags(array $user, $isGalaxy = null)
    {
        $conditions = array();
        if (!$user['Role']['perm_site_admin']) {
            $conditions['Tag.org_id'] = array(0, $user['org_id']);
            $conditions['Tag.user_id'] = array(0, $user['id']);
            $conditions['Tag.hide_tag'] = 0;
        }
        if ($isGalaxy !== null) {
            $conditions['Tag.is_galaxy'] = $isGalaxy;
        }
        return $this->find('all', array('conditions' => $conditions, 'recursive' => -1));
    }

    /**
     * @param array $accept
     * @param array $reject
     * @deprecated Use EventTag::fetchEventTagIds instead
     */
    public function fetchEventTagIds($accept, $reject)
    {
        $this->EventTag->fetchEventTagIds($accept, $reject);
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

    /**
     * pass a list of tag names to receive a list of matched tag IDs
     * @param string|array $array
     * @return array|int|null
     */
    public function findTagIdsByTagNames($array)
    {
        if (!is_array($array)) {
            $array = array($array);
        }
        $tagIds = [];
        $tagNames = [];
        foreach ($array as  $tag) {
            if (is_numeric($tag)) {
                $tagIds[] = $tag;
            } else {
                $tagNames[] = $tag;
            }
        }
        if (!empty($tagNames)) {
            $conditions = [];
            foreach ($tagNames as $tagName) {
                $conditions[] = array('Tag.name LIKE' => $tagName);
            }
            $result = $this->find('column', array(
                'recursive' => -1,
                'conditions' => ['OR' => $conditions],
                'fields' => array('Tag.id')
            ));
            $tagIds = array_merge($result, $tagIds);
        }
        return $tagIds;
    }

    /**
     * @param array $tag
     * @param array $user
     * @param bool $force
     * @return false|int
     * @throws Exception
     */
    public function captureTag(array $tag, array $user, $force=false)
    {
        $existingTag = $this->find('first', array(
            'recursive' => -1,
            'conditions' => array('LOWER(name)' => mb_strtolower($tag['name'])),
            'fields' => ['id', 'org_id', 'user_id'],
            'callbacks' => false,
        ));
        if (empty($existingTag)) {
            if ($force || $user['Role']['perm_tag_editor']) {
                $this->create();
                if (empty($tag['colour'])) {
                    $tag['colour'] = $this->tagColor($tag['name']);
                }
                $tag = array(
                    'name' => $tag['name'],
                    'colour' => $tag['colour'],
                    'exportable' => isset($tag['exportable']) ? $tag['exportable'] : 1,
                    'local_only' => $tag['local_only'] ?? 0,
                    'org_id' => 0,
                    'user_id' => 0,
                    'hide_tag' => Configure::read('MISP.incoming_tags_disabled_by_default') ? 1 : 0
                );
                $this->save($tag);
                return $this->id;
            } else {
                return false;
            }
        }
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
        return $existingTag['Tag']['id'];
    }

    /**
     * Generate tag color according to name. So color will be same on all instances.
     * @param string $tagName
     * @return string
     */
    public function tagColor($tagName)
    {
        return '#' . substr(md5($tagName), 0, 6);
    }

    /**
     * @param string $name
     * @param string|false $colour
     * @param null $numerical_value
     * @return int|false Created tag ID or false on error
     * @throws Exception
     */
    public function quickAdd($name, $colour = false, $numerical_value = null)
    {
        $this->create();
        if ($colour === false) {
            $colour = $this->tagColor($name);
        }
        $data = array(
            'name' => $name,
            'colour' => $colour,
            'exportable' => 1,
        );
        if ($numerical_value !== null) {
            $data['numerical_value'] = $numerical_value;
        }
        if ($this->save(['Tag' => $data])) {
            return $this->id;
        } else {
            return false;
        }
    }

    public function quickEdit($tag, $name, $colour, $hide = false, $numerical_value = null, $local_only = -1)
    {
        if ($tag['Tag']['colour'] !== $colour || $tag['Tag']['name'] !== $name || $hide !== false || $tag['Tag']['numerical_value'] !== $numerical_value || ($tag['Tag']['local_only'] !== $local_only && $local_only !== -1)) {
            $tag['Tag']['name'] = $name;
            $tag['Tag']['colour'] = $colour;
            if ($local_only !== -1) {
                $tag['Tag']['local_only'] = $local_only;
            }
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
        return $this->saveAll($tags);
    }

    /**
     * Recover user_id from the session and override numerical_values from userSetting.
     *
     * @param array $tags
     * @return array
     */
    private function checkForOverride($tags)
    {
        $userId = Configure::read('CurrentUserId');
        if ($this->tagOverrides === false && $userId > 0) {
            $this->UserSetting = ClassRegistry::init('UserSetting');
            $this->tagOverrides = $this->UserSetting->getTagNumericalValueOverride($userId);
        }
        if (empty($this->tagOverrides)) {
            return $tags;
        }
        foreach ($tags as $k => $tag) {
            if (isset($tag['Tag']['name'])) {
                $tagName = $tag['Tag']['name'];
                if (isset($this->tagOverrides[$tagName]) && is_numeric($this->tagOverrides[$tagName])) {
                    $tags[$k]['Tag']['original_numerical_value'] = isset($tags[$k]['Tag']['numerical_value']) ? $tags[$k]['Tag']['numerical_value'] : '';
                    $tags[$k]['Tag']['numerical_value'] = $this->tagOverrides[$tagName];
                }
            }
        }
        return $tags;
    }

    public function getTagsByName($tag_names, $containTagConnectors = true)
    {
        $tag_params = array(
            'recursive' => -1,
            'conditions' => array('name' => $tag_names)
        );
        if ($containTagConnectors) {
            $tag_params['contain'] = array('EventTag', 'AttributeTag');
        }
        $tags_temp = $this->find('all', $tag_params);
        $tags = array();
        foreach ($tags_temp as $temp) {
            $tags[mb_strtolower($temp['Tag']['name'])] = $temp;
        }
        return $tags;
    }

    /**
     * @param string $namespace
     * @param bool $containTagConnectors
     * @return array Uppercase tag name in key
     */
    public function getTagsForNamespace($namespace, $containTagConnectors = true)
    {
        $tag_params = array(
            'recursive' => -1,
            'conditions' => array('LOWER(name) LIKE' => strtolower($namespace) . '%'),
        );
        if ($containTagConnectors) {
            $tag_params['contain'] = array('EventTag', 'AttributeTag');
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
        $event_ids = $this->EventTag->find('column', array(
            'conditions' => array('EventTag.tag_id' => $id),
            'fields'  => array('EventTag.event_id'),
        ));
        $params = array('conditions' => array('Event.id' => $event_ids));
        $events = $this->EventTag->Event->fetchSimpleEvents($user, $params, true);
        foreach ($events as $k => $event) {
            $event['Event']['Orgc'] = $event['Orgc'];
            $events[$k] = $event['Event'];
        }
        return $events;
    }

    /**
     * @return array
     */
    public function duplicateTags()
    {
        $tags = $this->find('list', [
            'fields' => ['id', 'name'],
            'order' => ['id'],
        ]);
        $duplicates = [];
        $tagsByNormalizedName = [];
        foreach ($tags as $tagId => $tagName) {
            $tagId = (int)$tagId;
            $normalizedName = mb_strtolower(trim($tagName));
            if (isset($tagsByNormalizedName[$normalizedName])) {
                $duplicates[$tagId] = $tagsByNormalizedName[$normalizedName];
            } else {
                $tagsByNormalizedName[$normalizedName] = $tagId;
            }
        }
        $output = [];
        foreach ($duplicates as $sourceId => $destinationId) {
            $output[] = [
                'source_id' => $sourceId,
                'source_name' => $tags[$sourceId],
                'destination_id' => $destinationId,
                'destination_name' => $tags[$destinationId],
            ];
        }
        return $output;
    }

    /**
     * Merge tag $source into $destination. Destination tag will be deleted.
     * @param int|string $source Tag name or tag ID
     * @param int|string $destination Tag name or tag ID
     * @throws Exception
     */
    public function mergeTag($source, $destination)
    {
        $sourceConditions = is_numeric($source) ? ['Tag.id' => $source] : ['Tag.name' => $source];
        $destinationConditions = is_numeric($destination) ? ['Tag.id' => $destination] : ['Tag.name' => $destination];

        $sourceTag = $this->find('first', [
            'conditions' => $sourceConditions,
            'recursive' => -1,
            'fields' => ['Tag.id', 'Tag.name'],
        ]);
        if (empty($sourceTag)) {
            throw new Exception("Tag `$source` not found.");
        }

        $destinationTag = $this->find('first', [
            'conditions' => $destinationConditions,
            'recursive' => -1,
            'fields' => ['Tag.id', 'Tag.name'],
        ]);
        if (empty($destinationTag)) {
            throw new Exception("Tag `$destination` not found.");
        }

        if ($sourceTag['Tag']['id'] === $destinationTag['Tag']['id']) {
            throw new Exception("Source and destination tags are same.");
        }

        $this->AttributeTag->updateAll(['tag_id' => $destinationTag['Tag']['id']], ['tag_id' => $sourceTag['Tag']['id']]);
        $changedTags = $this->AttributeTag->getAffectedRows();
        $this->EventTag->updateAll(['tag_id' => $destinationTag['Tag']['id']], ['tag_id' => $sourceTag['Tag']['id']]);
        $changedTags += $this->EventTag->getAffectedRows();
        $this->GalaxyClusterRelationTag->updateAll(['tag_id' => $destinationTag['Tag']['id']], ['tag_id' => $sourceTag['Tag']['id']]);
        $changedTags += $this->GalaxyClusterRelationTag->getAffectedRows();
        $this->delete($sourceTag['Tag']['id']);

        return [
            'source_tag' => $sourceTag,
            'destination_tag' => $destinationTag,
            'changed' => $changedTags,
        ];
    }

    /**
     * @deprecated Not used anywhere
     * @param $user
     * @return string
     * @throws Exception
     */
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
        $this->Attribute = ClassRegistry::init('MispAttribute');
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

    /**
     * Similar method as `Event::massageTags`, but just removes tags that are part of existing galaxy
     * @param array $user
     * @param array $data
     * @param string $dataType
     * @return array
     */
    public function removeGalaxyClusterTags(array $user, array $data, $dataType = 'Event')
    {
        $possibleGalaxyClusterTag = [];
        foreach ($data[$dataType . 'Tag'] as $k => &$dataTag) {
            if (empty($dataTag['Tag'])) {
                unset($data[$dataType . 'Tag'][$k]);
                continue;
            }
            $dataTag['Tag']['local'] = empty($dataTag['local']) ? 0 : 1;
            if (str_starts_with($dataTag['Tag']['name'], 'misp-galaxy:')) {
                $possibleGalaxyClusterTag[] = $dataTag['Tag']['name'];
            }
        }
        unset($dataTag);

        if (empty($possibleGalaxyClusterTag)) {
            return $data;
        }

        $this->GalaxyCluster = ClassRegistry::init('GalaxyCluster');
        $conditions = $this->GalaxyCluster->buildConditions($user);
        $conditions['GalaxyCluster.tag_name'] = $possibleGalaxyClusterTag;
        $galaxyClusterTags = $this->GalaxyCluster->find('column', [
            'conditions' => $conditions,
            'fields' => ['GalaxyCluster.tag_name'],
        ]);

        foreach ($data[$dataType . 'Tag'] as $k => $dataTag) {
            if (in_array($dataTag['Tag']['name'], $galaxyClusterTags, true)) {
                unset($data[$dataType . 'Tag'][$k]);
            }
        }

        return $data;
    }

    /**
     * @param array $user
     * @return array
     */
    public function createConditions(array $user)
    {
        $conditions = [];
        if (!$user['Role']['perm_site_admin']) {
            $conditions['Tag.org_id'] = [0, $user['org_id']];
            $conditions['Tag.user_id'] = [0, $user['id']];
        }
        return $conditions;
    }

    /**
     * @param string $tagName
     * @return bool
     */
    public function isCustomGalaxyClusterTag($tagName)
    {
        return (bool)preg_match(self::RE_CUSTOM_GALAXY, $tagName);
    }
}
