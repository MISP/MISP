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

    /** @var array Cache for tag name pattern → IDs lookups */
    private $tagNameToIdsCache = [];

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
        'EventReportTag' => array(
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

    const RE_GALAXY = '/misp-galaxy:[^:="]+="[^"]+"/i';
    const RE_CUSTOM_GALAXY = '/misp-galaxy:[^:="]+="[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}"/i';
    const RE_CUSTOM_CLUSTER_FROM_DEFAULT_GALAXY = '/misp-galaxy:(?:(?![a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}).)+="[^"]+"/i';
    private $tagOverrides = false;

    private $cachedTagsByName = [];

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
     * The condition matching tag names the way the unique index does.
     *
     * tags.name is case-insensitive. On MySQL that is the column's collation
     * (utf8mb4_unicode_ci), so a plain equality matches every casing straight
     * off the unique key, and wrapping the column in LOWER() would throw that
     * key away and scan the table per lookup (#11114). PostgreSQL has no
     * collation that does this; there the uniqueness is a unique index over
     * lower(name), and the comparison is spelled through LOWER() so the
     * planner takes that index instead.
     *
     * @param string|array $names One name, or a list of them for an IN.
     * @param string|null $operator An operator to append CakePHP-style, such
     *   as 'LIKE'; a pattern is lower-cased with the column on PostgreSQL.
     * @return array One condition, keyed on the field expression.
     */
    public function nameCondition($names, $operator = null)
    {
        $field = 'Tag.name';
        if (!$this->isMysql()) {
            $field = 'LOWER(Tag.name)';
            $names = is_array($names)
                ? array_map('mb_strtolower', $names)
                : mb_strtolower((string)$names);
        }
        if ($operator !== null) {
            $field .= ' ' . $operator;
        }
        return array($field => $names);
    }

    /**
     * @param array $user
     * @param string $tagName
     * @return mixed|null
     */
    public function lookupTagIdForUser(array $user, $tagName)
    {
        $conditions = $this->createConditions($user);
        $conditions = array_merge($conditions, $this->nameCondition($tagName));

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
            'conditions' => $this->nameCondition($tagName),
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
        $uncachedTagNames = [];

        foreach ($array as $tag) {
            if (is_numeric($tag)) {
                $tagIds[] = $tag;
            } else {
                $tagNames[] = $tag;
                // Check if this tag name pattern is already cached
                if (isset($this->tagNameToIdsCache[$tag])) {
                    $tagIds = array_merge($tagIds, $this->tagNameToIdsCache[$tag]);
                } else {
                    $uncachedTagNames[] = $tag;
                }
            }
        }

        // Only query DB for uncached tag names
        if (!empty($uncachedTagNames)) {
            // Query each uncached tag name individually to enable per-pattern caching
            foreach ($uncachedTagNames as $tagName) {
                $result = $this->find('column', array(
                    'recursive' => -1,
                    'conditions' => ['Tag.name LIKE' => $tagName],
                    'fields' => array('Tag.id')
                ));
                $this->tagNameToIdsCache[$tagName] = $result;
                $tagIds = array_merge($tagIds, $result);
            }
        }

        return array_values(array_unique($tagIds));
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
        // Every casing of the name matches, off the unique index - see
        // nameCondition() for how each engine spells that.
        $existingTag = $this->find('first', array(
            'recursive' => -1,
            'conditions' => $this->nameCondition($tag['name']),
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
     * The two ai-computer-assisted provenance tags the AI module puts on
     * everything it produces (Module::AI_PROVENANCE_TAGS), guaranteed to
     * exist before an AI write: a name the taxonomy knows is enabled through
     * the Taxonomy model (its colour, linked to the taxonomy, the taxonomy
     * itself left as it is); a name it does not know (taxonomy not loaded,
     * or an older version) is created as a plain tag. No perm_tag_editor is
     * needed for these two names. An existing row reserved for another
     * organisation or user stays unusable and comes back as false.
     *
     * @param array $user
     * @return array tag name => tag id, or false when the tag cannot be used
     */
    public function captureAiProvenanceTags(array $user)
    {
        App::uses('Module', 'Model');
        $names = Module::AI_PROVENANCE_TAGS;
        // Every casing matches, off the unique index - see nameCondition().
        $existing = $this->find('list', array(
            'conditions' => $this->nameCondition($names),
            'fields' => array('Tag.name', 'Tag.id'),
            'recursive' => -1,
        ));
        $existingLower = array_map('mb_strtolower', array_keys($existing));
        $missing = array();
        foreach ($names as $name) {
            if (!in_array(mb_strtolower($name), $existingLower, true)) {
                $missing[] = $name;
            }
        }
        if (!empty($missing)) {
            // Creates only the listed names the taxonomy knows; false when
            // the taxonomy is not loaded. captureTag() below covers the rest.
            $Taxonomy = ClassRegistry::init('Taxonomy');
            $Taxonomy->addTags(Module::AI_PROVENANCE_TAXONOMY, $missing);
        }
        $ids = array();
        foreach ($names as $name) {
            $ids[$name] = $this->captureTag(array('name' => $name), $user, true);
        }
        return $ids;
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

    public function countRelationships(): array
    {
        $sources = ['EventTag', 'AttributeTag', 'EventReportTag'];
        $counts = [];
        foreach ($sources as $source) {
            $this->{$source}->virtualFields['tag_type_count'] = "COUNT({$source}.id)";
            $counts[$source] = $this->{$source}->find('list', [
                'recursive' => -1,
                'fields' => ["{$source}.relationship_type", 'tag_type_count'],
                'group' => ["{$source}.relationship_type"],
                'conditions' => [
                    'relationship_type !=' => '',
                ]
            ]);
            unset($this->{$source}->virtualFields['tag_type_count']);
        }
        $counts['all'] = [];
        foreach ($counts as $scope => $scopedCounts) {
            foreach ($scopedCounts as $type => $scopedCount) {
                if (!isset($counts['all'][$type])) {
                    $counts['all'][$type] = 0;
                }
                $counts['all'][$type] += $scopedCount;
            }
        }
        return $counts;
    }

    public function getCachedTags($includeClusters=false): array
    {
        $conditions = [
            'Tag.is_galaxy' => !empty($includeClusters),
        ];
        if (empty($this->cachedTagsByName)) {
            $this->cachedTagsByName = $this->find('all', [
                'conditions' => $conditions,
                'recursive' => -1,
                'order' => ['name asc'],
                'fields' => ['Tag.id', 'Tag.name']
            ]);
        }
        return $this->cachedTagsByName;
    }


    public function getAllTagsForSelect($user)
    {
        $conditions = $this->createConditions($user);
        $conditions['Tag.is_galaxy'] = 0;
        $conditions['Tag.hide_tag'] = 0;
        $conditions['Tag.local_only'] = 0;

        $tags = $this->find('all', [
            'conditions' => $conditions,
            'recursive' => -1,
            'order' => ['Tag.name ASC'],
            'fields' => ['Tag.id', 'Tag.name']
        ]);

        return Hash::combine($tags, '{n}.Tag.id', '{n}.Tag.name');
    }

    /**
     * The "All Tags" category of the BS5 tag picker: the same universe as
     * getAllTagsForSelect(), but shaped as a list carrying the colour, which
     * the picker needs to draw a tag exactly like Badges/tag.ctp does.
     *
     * @param array $user
     * @return array [['id' => int, 'name' => string, 'colour' => string], ...]
     */
    public function getAllTagsForPicker($user)
    {
        $conditions = $this->createConditions($user);
        $conditions['Tag.is_galaxy'] = 0;
        $conditions['Tag.hide_tag'] = 0;
        $conditions['Tag.local_only'] = 0;

        $tags = $this->find('all', [
            'conditions' => $conditions,
            'recursive' => -1,
            'order' => ['Tag.name ASC'],
            'fields' => ['Tag.id', 'Tag.name', 'Tag.colour']
        ]);

        return array_map(function (array $tag) {
            return $this->pickerTagEntry($tag['Tag']);
        }, $tags);
    }

    /**
     * The "Custom Tags" category of the BS5 tag picker: the tags that belong
     * to no taxonomy.
     *
     * @param array $user
     * @return array [['id' => int, 'name' => string, 'colour' => string], ...]
     */
    public function getCustomTagsForPicker($user)
    {
        $taxonomy = ClassRegistry::init('Taxonomy');
        $customRaw = $taxonomy->getAllTaxonomyTags(true, $user, true, true, false);

        $tags = [];
        foreach ($customRaw as $entry) {
            $tag = $entry['Tag'];
            if (!empty($tag['hide_tag']) || !empty($tag['is_galaxy'])) {
                continue;
            }
            $tags[] = $this->pickerTagEntry($tag);
        }
        return $tags;
    }

    /**
     * One picker entry, with the colour fallback the picker and
     * Badges/tag.ctp both use for a tag whose colour was never set.
     *
     * @param array $tag a Tag row (unwrapped)
     * @return array
     */
    public function pickerTagEntry(array $tag)
    {
        return [
            'id' => (int)$tag['id'],
            'name' => $tag['name'],
            'colour' => !empty($tag['colour']) ? $tag['colour'] : '#0088cc',
        ];
    }
}
