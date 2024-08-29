<?php
declare(strict_types=1);

namespace App\Model\Table;

use App\Lib\Tools\CidrTool;
use App\Lib\Tools\FileAccessTool;
use App\Lib\Tools\RedisTool;
use App\Model\Entity\Warninglist;
use Cake\Core\Configure;
use Cake\ORM\RulesChecker;
use Cake\Validation\Validator;
use Exception;

class WarninglistsTable extends AppTable
{
    /**
     * @var array
     */
    private $entriesCache = [];

    /**
     * @var array|null
     */
    private $enabledCache = null;

    private $showForAll;

    /**
     * initialize
     *
     * @param  mixed $config the config
     * @return void
     */
    public function initialize(array $config): void
    {
        parent::initialize($config);

        $this->showForAll = Configure::read('MISP.warning_for_all');
        $this->hasMany(
            'WarninglistEntries',
            [
                'dependent' => true,
                'propertyName' => 'WarninglistEntry',
            ]
        );
        $this->hasMany(
            'WarninglistTypes',
            [
                'dependent' => true,
                'propertyName' => 'WarninglistType',
            ]
        );

        $this->setTable('warninglists');
        $this->setDisplayField('name');
        $this->setPrimaryKey('id');
    }

    /**
     * buildRules
     *
     * @param  \Cake\ORM\RulesChecker $rules the rules
     * @return \Cake\ORM\RulesChecker
     */
    public function buildRules(RulesChecker $rules): RulesChecker
    {
        $rules->add($rules->isUnique(['name']));

        return $rules;
    }

    /**
     * validationDefault
     *
     * @param  \Cake\Validation\Validator $validator the validator
     * @return \Cake\Validation\Validator
     */
    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->notEmptyString('name')
            ->add('version', 'numeric')
            ->notEmptyString('description')
            ->notBlank('entries')
            ->add(
                'type',
                'inList',
                [
                    'rule' => ['cidr', 'hostname', 'string', 'substring', 'regex'],
                ]
            )
            ->add(
                'category',
                'inList',
                [
                    'rule' => ['false_positive', 'known'],
                ]
            )
            ->requirePresence(['name', 'description', 'entries'], 'create');

        return $validator;
    }

    // TODO: [3.x-MIGRATION] re-implement this as a custom validation rule
    // public function beforeValidate($options = [])
    // {
    //     if (isset($this->data['WarninglistEntry'])) {
    //         if ($this->data['Warninglist']['type'] === 'cidr') {
    //             foreach ($this->data['WarninglistEntry'] as $entry) {
    //                 if (!CidrTool::validate($entry['value'])) {
    //                     $this->validationErrors['entries'][] = __('`%s` is not valid CIDR', $entry['value']);
    //                 }
    //             }
    //         } else if ($this->data['Warninglist']['type'] === 'regex') {
    //             foreach ($this->data['WarninglistEntry'] as $entry) {
    //                 if (@preg_match($entry['value'], '') === false) {
    //                     $this->validationErrors['entries'][] = __('`%s` is not valid regular expression', $entry['value']);
    //                 }
    //             }
    //         }

    //         if (!empty($this->validationErrors['entries'])) {
    //             return false;
    //         }
    //     }

    //     return true;
    // }

    /**
     * Attach warninglist matches to attributes or proposals with IDS mark.
     *
     * @param array $attributes the attributes to attach to
     * @return array Warninglist ID => name
     */
    public function attachWarninglistToAttributes(array &$attributes)
    {
        if (empty($attributes)) {
            return [];
        }

        $enabledWarninglists = $this->getEnabled();
        if (empty($enabledWarninglists)) {
            return []; // no warninglist is enabled
        }

        try {
            $redis = RedisTool::init();
        } catch (Exception $e) {
            // fallback to default implementation when redis is not available
            $eventWarnings = [];
            foreach ($attributes as $pos => $attribute) {
                $attributes[$pos] = $this->checkForWarning($attribute, $enabledWarninglists);
                if (isset($attributes[$pos]['warnings'])) {
                    foreach ($attribute['warnings'] as $match) {
                        $eventWarnings[$match['warninglist_id']] = $match['warninglist_name'];
                    }
                }
            }
            if (!empty($eventWarnings)) {
                $this->assignComments($attributes);
            }

            return $eventWarnings;
        }

        $warninglists = [];
        $enabledTypes = [];
        foreach ($enabledWarninglists as $warninglist) {
            $warninglists[$warninglist['Warninglist']['id']] = $warninglist['Warninglist'];
            foreach ($warninglist['types'] as $type) {
                $enabledTypes[$type] = true;
            }
        }

        $redisResultToAttributePos = [];
        $keysToGet = [];
        foreach ($attributes as $pos => $attribute) {
            if (($attribute['to_ids'] || $this->showForAll) && (isset($enabledTypes[$attribute['type']]) || isset($enabledTypes['ALL']))) {
                $redisResultToAttributePos[] = $pos;
                // Use hash as binary string to save memory and CPU time
                // Hash contains just attribute type and value, so can be reused in another event attributes
                $keysToGet[] = 'misp:wlc:' . md5($attribute['type'] . ':' . $attribute['value'], true);
            }
        }

        if (empty($keysToGet)) {
            return []; // no attribute suitable for warninglist check
        }

        $eventWarnings = [];
        $saveToCache = [];
        foreach ($redis->mget($keysToGet) as $pos => $result) {
            if ($result === false) { // not in cache
                $attribute = $attributes[$redisResultToAttributePos[$pos]];
                $attribute = $this->checkForWarning($attribute, $enabledWarninglists);

                $store = [];
                if (isset($attribute['warnings'])) {
                    foreach ($attribute['warnings'] as $match) {
                        $warninglistId = $match['warninglist_id'];
                        $attributes[$redisResultToAttributePos[$pos]]['warnings'][] = [
                            'value' => $match['value'],
                            'match' => $match['match'],
                            'warninglist_id' => $warninglistId,
                            'warninglist_name' => $warninglists[$warninglistId]['name'],
                            'warninglist_category' => $warninglists[$warninglistId]['category'],
                        ];
                        $eventWarnings[$warninglistId] = $warninglists[$warninglistId]['name'];

                        $store[$warninglistId] = [$match['value'], $match['match']];
                    }
                }

                $attributeKey = $keysToGet[$pos];
                $saveToCache[$attributeKey] = empty($store) ? '' : RedisTool::serialize($store);
            } elseif (!empty($result)) { // skip empty string that means no warning list match
                $matchedWarningList = RedisTool::deserialize($result);
                foreach ($matchedWarningList as $warninglistId => $matched) {
                    $attributes[$redisResultToAttributePos[$pos]]['warnings'][] = [
                        'value' => $matched[0],
                        'match' => $matched[1],
                        'warninglist_id' => $warninglistId,
                        'warninglist_name' => $warninglists[$warninglistId]['name'],
                        'warninglist_category' => $warninglists[$warninglistId]['category'],
                    ];
                    $eventWarnings[$warninglistId] = $warninglists[$warninglistId]['name'];
                }
            }
        }

        if (!empty($saveToCache)) {
            $pipe = $redis->pipeline();
            foreach ($saveToCache as $attributeKey => $json) {
                $redis->setex($attributeKey, 8 * 3600, $json); // cache for eight hour
            }
            $pipe->exec();
        }

        if (!empty($eventWarnings)) {
            $this->assignComments($attributes);
        }

        return $eventWarnings;
    }

    /**
     * Assign comments to warninglist hits.
     *
     * @param array $attributes the attributes to assign comments to
     * @return void
     */
    private function assignComments(array &$attributes)
    {
        $toFetch = [];
        foreach ($attributes as $attribute) {
            if (isset($attribute['warnings'])) {
                foreach ($attribute['warnings'] as $warning) {
                    $toFetch[$warning['warninglist_id']][] = $warning['match'];
                }
            }
        }

        $conditions = [];
        foreach ($toFetch as $warninglistId => $values) {
            $conditions[] = [
                'AND' => [
                    'warninglist_id' => $warninglistId,
                    'value' => array_unique($values),
                ]
            ];
        }

        $entries = $this->WarninglistEntry->find(
            'all',
            [
                'conditions' => [
                    'OR' => $conditions,
                    'comment !=' => '',
                ],
                'fields' => ['value', 'warninglist_id', 'comment'],
            ]
        );
        if (empty($entries)) {
            return;
        }

        $comments = [];
        foreach ($entries as $entry) {
            $entry = $entry['WarninglistEntry'];
            $comments[$entry['warninglist_id']][$entry['value']] = $entry['comment'];
        }

        foreach ($attributes as &$attribute) {
            if (isset($attribute['warnings'])) {
                foreach ($attribute['warnings'] as &$warning) {
                    if (isset($comments[$warning['warninglist_id']][$warning['match']])) {
                        $warning['comment'] = $comments[$warning['warninglist_id']][$warning['match']];
                    }
                }
            }
        }
    }

    /**
     * update the warninglists
     *
     * @return array the result of the update
     */
    public function update()
    {
        // Fetch existing default warninglists
        $existingWarninglist = $this->find(
            'all',
            [
                'fields' => ['id', 'name', 'version', 'enabled'],
                'recursive' => -1,
                'conditions' => ['default' => 1],
            ]
        )->toArray();
        $existingWarninglist = array_column(array_column($existingWarninglist, 'Warninglist'), null, 'name');

        $directories = glob(APP . '..' . DS . 'libraries' . DS . 'misp-warninglists' . DS . 'lists' . DS . '*', GLOB_ONLYDIR);
        $result = ['success' => [], 'fails' => []];
        foreach ($directories as $dir) {
            $list = FileAccessTool::readJsonFromFile($dir . DS . 'list.json');
            if (!isset($list['version'])) {
                $list['version'] = 1;
            }
            if (!isset($list['type'])) {
                $list['type'] = 'string';
            } elseif (is_array($list['type'])) {
                $list['type'] = $list['type'][0];
            }
            if (!isset($existingWarninglist[$list['name']]) || $list['version'] > $existingWarninglist[$list['name']]['version']) {
                $current = $existingWarninglist[$list['name']] ?? [];
                try {
                    $id = $this->__updateList($list, $current);
                    $result['success'][$id] = ['name' => $list['name'], 'new' => $list['version']];
                    if (!empty($current)) {
                        $result['success'][$id]['old'] = $current['version'];
                    }
                } catch (Exception $e) {
                    $result['fails'][] = ['name' => $list['name'], 'fail' => $e->getMessage()];
                }
            }
        }

        if (!empty($result['success']) || !empty($result['fails'])) {
            $this->regenerateWarninglistCaches();
        }

        return $result;
    }

    /**
     * quickDelete
     *
     * @param  mixed $id the id of the list to delete
     * @return array the result of the deletion
     */
    public function quickDelete($id)
    {
        $result = $this->WarninglistEntry->deleteAll(
            ['WarninglistEntry.warninglist_id' => $id],
            false
        );
        if ($result) {
            $result = $this->WarninglistType->deleteAll(
                ['WarninglistType.warninglist_id' => $id],
                false
            );
        }
        if ($result) {
            $result = $this->delete($id, false);
        }

        return $result;
    }

    /**
     * Import single warninglist
     *
     * @param array $list a list to import
     * @return int Warninglist ID
     * @throws \Exception
     */
    public function import(array $list)
    {
        $existingWarninglist = $this->find(
            'first',
            [
                'fields' => ['id', 'name', 'version', 'enabled', 'default'],
                'recursive' => -1,
                'conditions' => ['name' => $list['name']],
            ]
        );

        if ($existingWarninglist && $existingWarninglist['Warninglist']['default']) {
            throw new Exception('It is not possible to modify default warninglist.');
        }

        $id = $this->__updateList($list, $existingWarninglist ? $existingWarninglist['Warninglist'] : [], false);
        $this->regenerateWarninglistCaches($id);

        return $id;
    }

    /**
     * @param array $list List to update
     * @param array $existing Existing list
     * @param bool $default Whether the list is default
     * @return int Warninglist ID
     * @throws \Exception
     */
    private function __updateList(array $list, array $existing, $default = true)
    {
        $list['enabled'] = 0;
        $warninglist = [];
        if (!empty($existing)) {
            if ($existing['enabled']) {
                $list['enabled'] = 1;
            }
            $warninglist['Warninglist']['id'] = $existing['id']; // keep list ID
            // Delete all dependencies
            $this->WarninglistEntry->deleteAll(['WarninglistEntry.warninglist_id' => $existing['id']], false);
            $this->WarninglistType->deleteAll(['WarninglistType.warninglist_id' => $existing['id']], false);
        }
        $fieldsToSave = ['name', 'version', 'description', 'type', 'enabled'];
        foreach ($fieldsToSave as $fieldToSave) {
            $warninglist['Warninglist'][$fieldToSave] = $list[$fieldToSave];
        }
        if (!$default) {
            $warninglist['Warninglist']['default'] = 0;
        }
        $this->create();
        if (!$this->save($warninglist)) {
            throw new Exception('Could not save warninglist because of validation errors: ' . json_encode($this->validationErrors));
        }

        $db = $this->getDataSource();
        $warninglistId = (int)$this->id;
        $result = true;

        $keys = array_keys($list['list']);
        if ($keys === array_keys($keys)) {
            foreach (array_chunk($list['list'], 1000) as $chunk) {
                $valuesToInsert = [];
                foreach ($chunk as $value) {
                    if (!empty($value)) {
                        $valuesToInsert[] = [$value, $warninglistId];
                    }
                }
                $result = $db->insertMulti('warninglist_entries', ['value', 'warninglist_id'], $valuesToInsert);
            }
        } else { // import warninglist with comments
            foreach (array_chunk($list['list'], 1000, true) as $chunk) {
                $valuesToInsert = [];
                foreach ($chunk as $value => $comment) {
                    if (!empty($value)) {
                        $valuesToInsert[] = [$value, $comment, $warninglistId];
                    }
                }
                $result = $db->insertMulti('warninglist_entries', ['value', 'comment', 'warninglist_id'], $valuesToInsert);
            }
        }
        if (!$result) {
            throw new Exception('Could not insert values.');
        }

        if (empty($list['matching_attributes'])) {
            $list['matching_attributes'] = ['ALL'];
        }
        $values = [];
        foreach ($list['matching_attributes'] as $type) {
            $values[] = ['type' => $type, 'warninglist_id' => $warninglistId];
        }
        $this->WarninglistType->saveMany($values);

        return $warninglistId;
    }

    /**
     * Regenerate the warninglist caches, but if an ID is passed along, only regen the entries for the given ID.
     * This allows us to enable/disable a single warninglist without regenerating all caches.
     *
     * @param int|null $id the ID of the warninglist to regenerate
     * @return bool
     * @throws \RedisException
     */
    public function regenerateWarninglistCaches($id = null)
    {
        try {
            $redis = RedisTool::init();
        } catch (Exception $e) {
            return false;
        }

        $keysToDelete = ['misp:wlc:*'];
        if ($id === null) {
            // delete all cached entries when regenerating whole cache
            $keysToDelete[] = 'misp:warninglist_entries_cache:*';
        }
        RedisTool::deleteKeysByPattern($redis, $keysToDelete);

        $warninglists = $this->getEnabledAndCacheWarninglist();

        foreach ($warninglists as $warninglist) {
            if ($id && $warninglist['Warninglist']['id'] != $id) {
                continue;
            }
            $entries = $this->WarninglistEntry->find(
                'column',
                [
                    'conditions' => ['warninglist_id' => $warninglist['Warninglist']['id']],
                    'fields' => ['value'],
                ]
            );
            $this->cacheWarninglistEntries($entries, $warninglist['Warninglist']['id']);
        }

        return true;
    }

    /**
     * Get enable warninglists and cache them.
     *
     * @return array the warning lists
     */
    private function getEnabledAndCacheWarninglist()
    {
        $warninglists = $this->find(
            'all',
            [
                'contain' => ['WarninglistType'],
                'conditions' => ['enabled' => 1],
                'fields' => ['id', 'name', 'type', 'category'],
            ]
        );

        // Convert type to array
        foreach ($warninglists as &$warninglist) {
            $warninglist['types'] = [];
            foreach ($warninglist['WarninglistType'] as $wt) {
                $warninglist['types'][] = $wt['type'];
            }
            unset($warninglist['WarninglistType']);
        }

        try {
            RedisTool::init()->set('misp:warninglist_cache', RedisTool::serialize($warninglists));
        } catch (Exception $e) {
        }

        return $warninglists;
    }

    /**
     * cacheWarninglistEntries
     *
     * @param  mixed $warninglistEntries the entries
     * @param  mixed $id the id of the warninglist
     * @return bool true if the cache was successful
     */
    private function cacheWarninglistEntries(array $warninglistEntries, $id)
    {
        try {
            $redis = RedisTool::init();
        } catch (Exception $e) {
            return false;
        }

        $key = 'misp:warninglist_entries_cache:' . $id;
        RedisTool::unlink($redis, $key);
        if (method_exists($redis, 'saddArray')) {
            $redis->sAddArray($key, $warninglistEntries);
        } else {
            foreach ($warninglistEntries as $entry) {
                $redis->sAdd($key, $entry);
            }
        }

        return true;
    }

    /**
     * @return array
     * @throws \JsonException
     */
    public function getEnabled()
    {
        if (isset($this->enabledCache)) {
            return $this->enabledCache;
        }

        try {
            $warninglists = RedisTool::deserialize(RedisTool::init()->get('misp:warninglist_cache'));
        } catch (Exception $e) {
            $warninglists = false;
        }

        // $warninglists is false when nothing is cached
        if ($warninglists === false) {
            $warninglists = $this->getEnabledAndCacheWarninglist();
        }

        $this->enabledCache = $warninglists;

        return $warninglists;
    }

    /**
     * get warninglist entries (from cache if possible) and cache if needed
     *
     * @param int $id the ID of the warninglist
     * @return array
     */
    private function getWarninglistEntries($id)
    {
        try {
            $entries = RedisTool::init()->sMembers('misp:warninglist_entries_cache:' . $id);
            if (!empty($entries)) {
                return $entries;
            }
        } catch (Exception $e) {
        }

        $entries = $this->WarninglistEntry->find(
            'column',
            [
                'conditions' => ['warninglist_id' => $id],
                'fields' => ['WarninglistEntry.value'],
            ]
        );
        $this->cacheWarninglistEntries($entries, $id);

        return $entries;
    }

    /**
     * For 'hostname', 'string' and 'cidr' warninglist type, values are just in keys to save memory.
     *
     * @param array $warninglist the warninglist
     * @return array
     */
    public function getFilteredEntries(array $warninglist)
    {
        $id = $warninglist['Warninglist']['id'];
        if (isset($this->entriesCache[$id])) {
            return $this->entriesCache[$id];
        }

        $values = $this->getWarninglistEntries($id);
        if ($warninglist['Warninglist']['type'] === 'hostname') {
            $output = [];
            foreach ($values as $v) {
                $v = strtolower(trim($v, '.'));
                $output[$v] = true;
            }
            $values = $output;
        } elseif ($warninglist['Warninglist']['type'] === 'string') {
            $output = [];
            foreach ($values as $v) {
                $output[$v] = true;
            }
            $values = $output;
        } elseif ($warninglist['Warninglist']['type'] === 'cidr') {
            $values = new CidrTool($values);
        }

        $this->entriesCache[$id] = $values;

        return $values;
    }

    /**
     * @param array $object the object to check
     * @param array|null $warninglists If null, all enabled warninglists will be used
     * @return array
     */
    public function checkForWarning(array $object, $warninglists = null)
    {
        if ($warninglists === null) {
            $warninglists = $this->getEnabled();
        }

        if ($object['to_ids'] || $this->showForAll) {
            foreach ($warninglists as $list) {
                if (in_array('ALL', $list['types'], true) || in_array($object['type'], $list['types'], true)) {
                    $result = $this->checkValue($this->getFilteredEntries($list), $object['value'], $object['type'], $list['Warninglist']['type']);
                    if ($result !== false) {
                        $object['warnings'][] = [
                            'match' => $result[0],
                            'value' => $result[1],
                            'warninglist_id' => $list['Warninglist']['id'],
                            'warninglist_name' => $list['Warninglist']['name'],
                            'warninglist_category' => $list['Warninglist']['category'],
                        ];
                    }
                }
            }
        }

        return $object;
    }

    /**
     * @param array|\App\Lib\Tools\CidrTool $listValues the values of the list
     * @param string $value the value to check
     * @param string $type the type of the attribute
     * @param string $listType the type of the list
     * @return array|false [Matched value, attribute value that matched]
     */
    public function checkValue($listValues, $value, $type, $listType)
    {
        if ($type === 'malware-sample' || strpos($type, '|') !== false) {
            $value = explode('|', $value, 2);
        } else {
            $value = [$value];
        }
        foreach ($value as $v) {
            if ($listType === 'cidr') {
                $result = $listValues->contains($v);
            } elseif ($listType === 'string') {
                $result = $this->__evalString($listValues, $v);
            } elseif ($listType === 'substring') {
                $result = $this->__evalSubString($listValues, $v);
            } elseif ($listType === 'hostname') {
                $result = $this->__evalHostname($listValues, $v);
            } elseif ($listType === 'regex') {
                $result = $this->__evalRegex($listValues, $v);
            } else {
                $result = false;
            }
            if ($result !== false) {
                return [$result, $v];
            }
        }

        return false;
    }

    /**
     * Check for exact match.
     *
     * @param array $listValues the values of the list
     * @param string $value the value to check
     * @return false
     */
    private function __evalString($listValues, $value)
    {
        if (isset($listValues[$value])) {
            return $value;
        }

        return false;
    }

    /**
     * Check for substring match.
     *
     * @param array $listValues the values of the list
     * @param string $value the value to check
     * @return false
     */
    private function __evalSubString($listValues, $value)
    {
        foreach ($listValues as $listValue) {
            if (strpos($value, $listValue) !== false) {
                return $listValue;
            }
        }

        return false;
    }

    /**
     * Check for hostname match.
     *
     * @param array $listValues the values of the list
     * @param string $value the value to check
     * @return false
     */
    private function __evalHostname($listValues, $value)
    {
        // php's parse_url is dumb, so let's use some hacky workarounds
        if (strpos($value, '//') === false) {
            $value = explode('/', $value);
            $hostname = $value[0];
        } else {
            $value = explode('/', $value);
            $hostname = $value[2];
        }
        // If the hostname is not found, just return false
        if (!isset($hostname)) {
            return false;
        }
        $hostname = rtrim($hostname, '.');
        $hostname = explode('.', $hostname);
        $rebuilt = '';
        foreach (array_reverse($hostname) as $piece) {
            if (empty($rebuilt)) {
                $rebuilt = $piece;
            } else {
                $rebuilt = $piece . '.' . $rebuilt;
            }
            if (isset($listValues[$rebuilt])) {
                return $rebuilt;
            }
        }

        return false;
    }

    /**
     * Check for regex match.
     *
     * @param array $listValues the values of the list
     * @param string $value the value to check
     * @return false
     */
    private function __evalRegex($listValues, $value)
    {
        foreach ($listValues as $listValue) {
            if (preg_match($listValue, $value)) {
                return $listValue;
            }
        }

        return false;
    }

    /**
     * @return array
     */
    public function fetchTLDLists()
    {
        $tldLists = $this->find(
            'column',
            [
                'conditions' => ['name IN' => Warninglist::TLDS],
                'fields' => ['id'],
            ]
        );
        $tlds = [];
        foreach ($tldLists as $warninglistId) {
            $tlds = array_merge($tlds, $this->getWarninglistEntries($warninglistId));
        }
        $tlds = array_map('strtolower', $tlds);
        if (!in_array('onion', $tlds, true)) {
            $tlds[] = 'onion';
        }

        return $tlds;
    }

    /**
     * @return array
     */
    public function fetchSecurityVendorDomains()
    {
        $securityVendorList = $this->find(
            'column',
            [
                'conditions' => ['name' => 'List of known domains used by automated malware analysis services & security vendors'],
                'fields' => ['id'],
            ]
        );
        $domains = [];
        foreach ($securityVendorList as $warninglistId) {
            $domains = array_merge($domains, $this->getWarninglistEntries($warninglistId));
        }

        return $domains;
    }

    /**
     * @param array $attribute the attribute to filter
     * @param array|null $warninglists If null, all enabled warninglists will be used
     * @return bool
     */
    public function filterWarninglistAttribute(array $attribute, $warninglists = null)
    {
        if ($warninglists === null) {
            $warninglists = $this->getEnabled();
        }

        foreach ($warninglists as $warninglist) {
            if (in_array('ALL', $warninglist['types'], true) || in_array($attribute['type'], $warninglist['types'], true)) {
                $result = $this->checkValue($this->getFilteredEntries($warninglist), $attribute['value'], $attribute['type'], $warninglist['Warninglist']['type']);
                if ($result !== false) {
                    return false;
                }
            }
        }

        return true;
    }

    // public function missingTldLists()
    // {
    //     $missingTldLists = [];
    //     foreach (Warninglist::TLDS as $tldList) {
    //         $temp = $this->find('first', [
    //             'recursive' => -1,
    //             'conditions' => ['Warninglist.name' => $tldList],
    //             'fields' => ['Warninglist.id'],
    //         ]);
    //         if (empty($temp)) {
    //             $missingTldLists[] = $tldList;
    //         }
    //     }

    //     return $missingTldLists;
    // }

    /**
     * @param array|null $data the data to save
     * @param bool $validate whether to validate the data
     * @param array $fieldList  the fields to save
     * @return array|bool|mixed|null
     * @throws \Exception
     */
    public function save($data = null, $validate = true, $fieldList = [])
    {
        $db = $this->getDataSource();
        $transactionBegun = $db->begin();
        $entity = $this->newEntity($data);

        $success = parent::save($entity, $validate, $fieldList);

        if (empty($success)) {
            return false;
        }

        $db = $this->getDataSource();

        try {
            $id = (int)$this->id;
            if (isset($data['WarninglistEntry'])) {
                $this->WarninglistEntry->deleteAll(['warninglist_id' => $id], false);
                $entriesToInsert = [];
                foreach ($data['WarninglistEntry'] as $entry) {
                    $entriesToInsert[] = [$entry['value'], $entry['comment'] ?? null, $id];
                }
                $db->insertMulti(
                    $this->WarninglistEntry->table,
                    ['value', 'comment', 'warninglist_id'],
                    $entriesToInsert
                );
            }

            if (isset($data['WarninglistType'])) {
                $this->WarninglistType->deleteAll(['warninglist_id' => $id], false);
                foreach ($data['WarninglistType'] as &$entry) {
                    $entry['warninglist_id'] = $id;
                }
                $this->WarninglistType->saveMany($data['WarninglistType']);
            }

            if ($transactionBegun) {
                if ($success) {
                    $db->commit();
                } else {
                    $db->rollback();
                }
            }
        } catch (Exception $e) {
            if ($transactionBegun) {
                $db->rollback();
            }
            throw $e;
        }

        if ($success) {
            $this->afterFullSave(!isset($data['Warninglist']['id']), $success->toArray());
        }

        return $success;
    }

    /**
     * post full save actions
     *
     * @param bool $created True for a new creation, false for an edit
     * @param array $data the data that was saved
     * @return void
     */
    private function afterFullSave($created, array $data)
    {
        if (isset($data['Warninglist']['default']) && $data['Warninglist']['default'] == 0) {
            $this->regenerateWarninglistCaches($data['Warninglist']['id']);
        }

        if ($this->pubToZmq('warninglist')) {
            $warninglist = $this->find(
                'first',
                [
                    'conditions' => ['id' => $data['Warninglist']['id']],
                    'contains' => ['WarninglistEntry', 'WarninglistType'],
                ]
            );
            $pubSubTool = $this->getPubSubTool();
            $pubSubTool->warninglist_save($warninglist, $created ? 'add' : 'edit');
        }
    }

    /**
     * @param string $input the input to parse
     * @return array
     */
    public function parseFreetext($input)
    {
        $input = trim($input);
        if (empty($input)) {
            return [];
        }

        $entries = [];
        foreach (explode("\n", trim($input)) as $entry) {
            $valueAndComment = explode('#', $entry, 2);
            $entries[] = [
                'value' => trim($valueAndComment[0]),
                'comment' => count($valueAndComment) === 2 ? trim($valueAndComment[1]) : null,
            ];
        }

        return $entries;
    }

    /**
     * get the categories
     *
     * @return array
     */
    public function categories()
    {
        return [
            Warninglist::CATEGORY_FALSE_POSITIVE => __('False positive'),
            Warninglist::CATEGORY_KNOWN => __('Known identifier'),
        ];
    }
}
