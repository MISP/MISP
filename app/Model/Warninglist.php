<?php
App::uses('AppModel', 'Model');
App::uses('CidrTool', 'Tools');

/**
 * @property WarninglistType $WarninglistType
 * @property WarninglistEntry $WarninglistEntry
 */
class Warninglist extends AppModel
{
    public $useTable = 'warninglists';

    public $recursive = -1;

    public $actsAs = array(
        'AuditLog',
            'Containable',
    );

    public $validate = array(
        'name' => array(
            'rule' => array('valueNotEmpty'),
        ),
        'description' => array(
            'rule' => array('valueNotEmpty'),
        ),
        'version' => array(
            'rule' => array('numeric'),
        ),
    );

    public $hasMany = array(
        'WarninglistEntry' => array(
            'dependent' => true
        ),
        'WarninglistType' => array(
            'dependent' => true
        )
    );

    private $__tlds = array(
        'TLDs as known by IANA'
    );

    /** @var array */
    private $entriesCache = [];

    /** @var array|null */
    private $enabledCache = null;

    private $showForAll;

    public function __construct($id = false, $table = null, $ds = null)
    {
        parent::__construct($id, $table, $ds);
        $this->showForAll = Configure::read('MISP.warning_for_all');
    }

    /**
     * Attach warninglist matches to attributes or proposals with IDS mark.
     *
     * @param array $attributes
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
            $redis = $this->setupRedisWithException();
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
            return $eventWarnings;
        }

        $warninglistIdToName = [];
        $enabledTypes = [];
        foreach ($enabledWarninglists as $warninglist) {
            $warninglistIdToName[$warninglist['Warninglist']['id']] = $warninglist['Warninglist']['name'];
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
                            'warninglist_name' => $warninglistIdToName[$warninglistId],
                        ];
                        $eventWarnings[$warninglistId] = $warninglistIdToName[$warninglistId];

                        $store[$warninglistId] = [$match['value'], $match['match']];
                    }
                }

                $attributeKey = $keysToGet[$pos];
                $saveToCache[$attributeKey] = empty($store) ? '' : json_encode($store);

            } elseif (!empty($result)) { // skip empty string that means no warning list match
                $matchedWarningList = json_decode($result, true);
                foreach ($matchedWarningList as $warninglistId => $matched) {
                    $attributes[$redisResultToAttributePos[$pos]]['warnings'][] = [
                        'value' => $matched[0],
                        'match' => $matched[1],
                        'warninglist_id' => $warninglistId,
                        'warninglist_name' => $warninglistIdToName[$warninglistId],
                    ];
                    $eventWarnings[$warninglistId] = $warninglistIdToName[$warninglistId];
                }
            }
        }

        if (!empty($saveToCache)) {
            $pipe = $redis->multi(Redis::PIPELINE);
            foreach ($saveToCache as $attributeKey => $json) {
                $redis->setex($attributeKey, 8 * 3600, $json); // cache for eight hour
            }
            $pipe->exec();
        }

        return $eventWarnings;
    }

    public function update()
    {
        $existingWarninglist = $this->find('all', [
            'fields' => ['id', 'name', 'version', 'enabled'],
            'recursive' => -1,
        ]);
        $existingWarninglist = array_column(array_column($existingWarninglist, 'Warninglist'), null, 'name');

        $directories = glob(APP . 'files' . DS . 'warninglists' . DS . 'lists' . DS . '*', GLOB_ONLYDIR);
        $updated = array('success' => [], 'fails' => []);
        foreach ($directories as $dir) {
            $file = new File($dir . DS . 'list.json');
            $list = $this->jsonDecode($file->read());
            $file->close();

            if (!isset($list['version'])) {
                $list['version'] = 1;
            }
            if (!isset($list['type'])) {
                $list['type'] = 'string';
            } elseif (is_array($list['type'])) {
                $list['type'] = $list['type'][0];
            }
            if (!isset($existingWarninglist[$list['name']]) || $list['version'] > $existingWarninglist[$list['name']]['version']) {
                $current = isset($existingWarninglist[$list['name']]) ? $existingWarninglist[$list['name']] : [];
                $result = $this->__updateList($list, $current);
                if (is_numeric($result)) {
                    $updated['success'][$result] = array('name' => $list['name'], 'new' => $list['version']);
                    if (!empty($current)) {
                        $updated['success'][$result]['old'] = $current['version'];
                    }
                } else {
                    $updated['fails'][] = array('name' => $list['name'], 'fail' => json_encode($result));
                }
            }
        }
        $this->regenerateWarninglistCaches();
        return $updated;
    }

    public function quickDelete($id)
    {
        $result = $this->WarninglistEntry->deleteAll(
            array('WarninglistEntry.warninglist_id' => $id)
        );
        if ($result) {
            $result = $this->WarninglistType->deleteAll(
                array('WarninglistType.warninglist_id' => $id)
            );
        }
        if ($result) {
            $result = $this->delete($id, false);
        }
        return $result;
    }

    private function __updateList(array $list, array $current)
    {
        $list['enabled'] = 0;
        $warninglist = array();
        if (!empty($current)) {
            if ($current['enabled']) {
                $list['enabled'] = 1;
            }
            $this->quickDelete($current['id']);
        }
        $fieldsToSave = array('name', 'version', 'description', 'type', 'enabled');
        foreach ($fieldsToSave as $fieldToSave) {
            $warninglist['Warninglist'][$fieldToSave] = $list[$fieldToSave];
        }
        $this->create();
        if ($this->save($warninglist)) {
            $db = $this->getDataSource();
            $values = array();
            $warninglistId = (int)$this->id;
            foreach ($list['list'] as $value) {
                if (!empty($value)) {
                    $values[] = array('value' => $value, 'warninglist_id' => $warninglistId);
                }
            }
            unset($list['list']);
            $count = count($values);
            foreach (array_chunk($values, 500) as $chunk) {
                $result = $db->insertMulti('warninglist_entries', array('value', 'warninglist_id'), $chunk);
            }
            if ($result) {
                $this->saveField('warninglist_entry_count', $count);
            } else {
                return 'Could not insert values.';
            }
            if (!empty($list['matching_attributes'])) {
                $values = array();
                foreach ($list['matching_attributes'] as $type) {
                    $values[] = array('type' => $type, 'warninglist_id' => $warninglistId);
                }
                $this->WarninglistType->saveMany($values);
            } else {
                $this->WarninglistType->create();
                $this->WarninglistType->save(array('WarninglistType' => array('type' => 'ALL', 'warninglist_id' => $warninglistId)));
            }
            return $warninglistId;
        } else {
            return $this->validationErrors;
        }
    }

    /**
     * Regenerate the warninglist caches, but if an ID is passed along, only regen the entries for the given ID.
     * This allows us to enable/disable a single warninglist without regenerating all caches.
     * @param int|null $id
     * @return bool
     */
    public function regenerateWarninglistCaches($id = null)
    {
        $redis = $this->setupRedis();
        if ($redis === false) {
            return false;
        }

        // Unlink is non blocking way how to delete keys from Redis, but it must be supported by PHP extension and
        // Redis itself
        $unlinkSupported = method_exists($redis, 'unlink') && $redis->unlink(null) !== false;
        if ($unlinkSupported) {
            $redis->unlink($redis->keys('misp:wlc:*'));
        } else {
            $redis->del($redis->keys('misp:wlc:*'));
        }

        if ($id === null) {
            // delete all cached entries when regenerating whole cache
            $redis->del($redis->keys('misp:warninglist_entries_cache:*'));
        }

        $warninglists = $this->find('all', array(
            'contain' => array('WarninglistType'),
            'conditions' => array('enabled' => 1),
            'fields' => ['id', 'name', 'type'],
        ));
        $this->cacheWarninglists($warninglists);

        foreach ($warninglists as $warninglist) {
            if ($id && $warninglist['Warninglist']['id'] != $id) {
                continue;
            }
            $entries = $this->WarninglistEntry->find('column', array(
                'conditions' => array('warninglist_id' => $warninglist['Warninglist']['id']),
                'fields' => array('value')
            ));
            $this->cacheWarninglistEntries($entries, $warninglist['Warninglist']['id']);
        }
        return true;
    }

    private function cacheWarninglists(array $warninglists)
    {
        $redis = $this->setupRedis();
        if ($redis !== false) {
            $redis->del('misp:warninglist_cache');
            foreach ($warninglists as $warninglist) {
                $redis->sAdd('misp:warninglist_cache', json_encode($warninglist));
            }
            return true;
        }
        return false;
    }

    private function cacheWarninglistEntries(array $warninglistEntries, $id)
    {
        $redis = $this->setupRedis();
        if ($redis !== false) {
            $key = 'misp:warninglist_entries_cache:' . $id;
            $redis->del($key);
            if (method_exists($redis, 'saddArray')) {
                $redis->sAddArray($key, $warninglistEntries);
            } else {
                foreach ($warninglistEntries as $entry) {
                    $redis->sAdd($key, $entry);
                }
            }
            return true;
        }
        return false;
    }

    /**
     * @return array
     */
    public function getEnabled()
    {
        if (isset($this->enabledCache)) {
            return $this->enabledCache;
        }

        $redis = $this->setupRedis();
        if ($redis !== false && $redis->exists('misp:warninglist_cache')) {
            $warninglists = $redis->sMembers('misp:warninglist_cache');
            foreach ($warninglists as $k => $v) {
                $warninglists[$k] = json_decode($v, true);
            }
        } else {
            $warninglists = $this->find('all', array(
                'contain' => array('WarninglistType'),
                'conditions' => array('enabled' => 1),
                'fields' => ['id', 'name', 'type'],
            ));
            $this->cacheWarninglists($warninglists);
        }

        foreach ($warninglists as &$warninglist) {
            $warninglist['types'] = [];
            foreach ($warninglist['WarninglistType'] as $wt) {
                $warninglist['types'][] = $wt['type'];
            }
            unset($warninglist['WarninglistType']);
        }
        $this->enabledCache = $warninglists;
        return $warninglists;
    }

    /**
     * @param int $id
     * @return array
     */
    private function getWarninglistEntries($id)
    {
        $redis = $this->setupRedis();
        if ($redis !== false && $redis->exists('misp:warninglist_entries_cache:' . $id)) {
            return $redis->sMembers('misp:warninglist_entries_cache:' . $id);
        } else {
            $entries = $this->WarninglistEntry->find('column', array(
                'conditions' => array('warninglist_id' => $id),
                'fields' => array('WarninglistEntry.value')
            ));
            $this->cacheWarninglistEntries($entries, $id);
            return $entries;
        }
    }

    /**
     * For 'hostname', 'string' and 'cidr' warninglist type, values are just in keys to save memory.
     *
     * @param array $warninglist
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
        } else if ($warninglist['Warninglist']['type'] === 'string') {
            $output = [];
            foreach ($values as $v) {
                $output[$v] = true;
            }
            $values = $output;
        } else if ($warninglist['Warninglist']['type'] === 'cidr') {
            $values = new CidrTool($values);
        }

        $this->entriesCache[$id] = $values;

        return $values;
    }

    /**
     * @param array $object
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
                    $result = $this->__checkValue($this->getFilteredEntries($list), $object['value'], $object['type'], $list['Warninglist']['type']);
                    if ($result !== false) {
                        $object['warnings'][] = array(
                            'match' => $result[0],
                            'value' => $result[1],
                            'warninglist_name' => $list['Warninglist']['name'],
                            'warninglist_id' => $list['Warninglist']['id'],
                        );
                    }
                }
            }
        }
        return $object;
    }

    /**
     * @param array|CidrTool $listValues
     * @param string $value
     * @param string $type
     * @param string $listType
     * @return array|false [Matched value, attribute value that matched]
     */
    private function __checkValue($listValues, $value, $type, $listType)
    {
        if ($type === 'malware-sample' || strpos($type, '|') !== false) {
            $value = explode('|', $value, 2);
        } else {
            $value = array($value);
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

    public function quickCheckValue($listValues, $value, $type)
    {
        return $this->__checkValue($listValues, $value, '', $type) !== false;
    }

    /**
     * Check for exact match.
     *
     * @param array $listValues
     * @param string $value
     * @return false
     */
    private function __evalString($listValues, $value)
    {
        if (isset($listValues[$value])) {
            return $value;
        }
        return false;
    }

    private function __evalSubString($listValues, $value)
    {
        foreach ($listValues as $listValue) {
            if (strpos($value, $listValue) !== false) {
                return $listValue;
            }
        }
        return false;
    }

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
        $tldLists = $this->find('column', array(
            'conditions' => array('Warninglist.name' => $this->__tlds),
            'fields' => array('Warninglist.id')
        ));
        $tlds = array();
        if (!empty($tldLists)) {
            $tlds = $this->WarninglistEntry->find('column', array(
                'conditions' => array('WarninglistEntry.warninglist_id' => $tldLists),
                'fields' => array('WarninglistEntry.value')
            ));
            foreach ($tlds as $key => $value) {
                $tlds[$key] = strtolower($value);
            }
        }
        if (!in_array('onion', $tlds, true)) {
            $tlds[] = 'onion';
        }
        return $tlds;
    }

    /**
     * @param array $attribute
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
                $result = $this->__checkValue($this->getFilteredEntries($warninglist), $attribute['value'], $attribute['type'], $warninglist['Warninglist']['type']);
                if ($result !== false) {
                    return false;
                }
            }
        }
        return true;
    }

    public function missingTldLists()
    {
        $missingTldLists = array();
        foreach ($this->__tlds as $tldList) {
            $temp = $this->find('first', array(
                'recursive' => -1,
                'conditions' => array('Warninglist.name' => $tldList),
                'fields' => array('Warninglist.id')
            ));
            if (empty($temp)) {
                $missingTldLists[] = $tldList;
            }
        }
        return $missingTldLists;
    }
}
