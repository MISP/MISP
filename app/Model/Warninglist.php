<?php
App::uses('AppModel', 'Model');

class Warninglist extends AppModel
{
    public $useTable = 'warninglists';

    public $recursive = -1;

    public $actsAs = array(
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

    public function getTldLists()
    {
        return $this->__tlds;
    }

    /**
     * Attach warninglist matches to attributes with IDS mark. Results are also saved to
     *
     * @param array $attributes
     * @return array Warninglist ID => name
     */
    public function attachWarninglistToAttributes(array &$attributes)
    {
        if (empty($attributes)) {
            return [];
        }

        try {
            $redis = $this->setupRedisWithException();
        } catch (Exception $e) {
            // fallback to default implementation when redis is not available
            $eventWarnings = [];
            $warninglists = $this->getEnabled();
            if (empty($warninglists)) {
                return []; // no warninglist is enabled
            }
            foreach ($attributes as $pos => $attribute) {
                $attributes[$pos] = $this->simpleCheckForWarning($attribute, $warninglists);
                if (isset($event['Attribute'][$pos]['warnings'])) {
                    foreach ($attribute['warnings'] as $match) {
                        $eventWarnings[$match['warninglist_id']] = $match['warninglist_name'];
                    }
                }
            }
            return $eventWarnings;
        }

        $warninglistIdToName = [];
        $enabledTypes = [];
        foreach ($this->getEnabled() as $warninglist) {
            $warninglistIdToName[$warninglist['Warninglist']['id']] = $warninglist['Warninglist']['name'];
            foreach ($warninglist['types'] as $type) {
                $enabledTypes[$type] = true;
            }
        }

        if (empty($warninglistIdToName)) {
            return []; // no warninglist is enabled
        }

        $pipe = $redis->multi(Redis::PIPELINE);
        $redisResultToAttributePos = [];
        foreach ($attributes as $pos => $attribute) {
            if ($attribute['to_ids'] && (isset($enabledTypes[$attribute['type']]) || isset($enabledTypes['ALL']))) {
                $redisResultToAttributePos[] = $pos;
                $redis->get('misp:wl-cache:' . md5($attribute['type'] . ':' .  $attribute['value']));
            }
        }
        $results = $pipe->exec();

        $warninglists = null;
        $eventWarnings = [];
        $saveToCache = [];
        foreach ($results as $pos => $result) {
            if ($result === false) { // not in cache
                $attribute = $attributes[$redisResultToAttributePos[$pos]];
                $attribute = $this->simpleCheckForWarning($attribute, $warninglists);

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

                $redisKey = 'misp:wl-cache:' . md5($attribute['type'] . ':' .  $attribute['value']);
                $saveToCache[$redisKey] = empty($store) ? '' : json_encode($store);

            } elseif (!empty($result)) { // empty string means no warning list match
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
            foreach ($saveToCache as $redisKey => $json) {
                $redis->setex($redisKey, 3600 * 24, $json); // cache for one day
            }
            $pipe->exec();
        }

        return $eventWarnings;
    }

    public function update()
    {
        $directories = glob(APP . 'files' . DS . 'warninglists' . DS . 'lists' . DS . '*', GLOB_ONLYDIR);
        $updated = array('success' => [], 'fails' => []);
        foreach ($directories as $dir) {
            $file = new File($dir . DS . 'list.json');
            $list = json_decode($file->read(), true);
            $file->close();
            if (!isset($list['version'])) {
                $list['version'] = 1;
            }
            if (!isset($list['type'])) {
                $list['type'] = 'string';
            } elseif (is_array($list['type'])) {
                $list['type'] = $list['type'][0];
            }
            $current = $this->find('first', array(
                    'conditions' => array('name' => $list['name']),
                    'recursive' => -1,
                    'fields' => array('*')
            ));
            if (empty($current) || $list['version'] > $current['Warninglist']['version']) {
                $result = $this->__updateList($list, $current);
                if (is_numeric($result)) {
                    $updated['success'][$result] = array('name' => $list['name'], 'new' => $list['version']);
                    if (!empty($current)) {
                        $updated['success'][$result]['old'] = $current['Warninglist']['version'];
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

    private function __updateList($list, $current)
    {
        $list['enabled'] = 0;
        $warninglist = array();
        if (!empty($current)) {
            if ($current['Warninglist']['enabled']) {
                $list['enabled'] = 1;
            }
            $this->quickDelete($current['Warninglist']['id']);
        }
        $fieldsToSave = array('name', 'version', 'description', 'type', 'enabled');
        foreach ($fieldsToSave as $fieldToSave) {
            $warninglist['Warninglist'][$fieldToSave] = $list[$fieldToSave];
        }
        $this->create();
        if ($this->save($warninglist)) {
            $db = $this->getDataSource();
            $values = array();
            foreach ($list['list'] as $value) {
                if (!empty($value)) {
                    $values[] = array('value' => $value, 'warninglist_id' => $this->id);
                }
            }
            unset($list['list']);
            $count = count($values);
            $values = array_chunk($values, 100);
            foreach ($values as $chunk) {
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
                    $values[] = array('type' => $type, 'warninglist_id' => $this->id);
                }
                $this->WarninglistType->saveMany($values);
            } else {
                $this->WarninglistType->create();
                $this->WarninglistType->save(array('WarninglistType' => array('type' => 'ALL', 'warninglist_id' => $this->id)));
            }
            return $this->id;
        } else {
            return $this->validationErrors;
        }
    }

    // regenerate the warninglist caches, but if an ID is passed along, only regen the entries for the given ID.
    // This allows us to enable/disable a single warninglist without regenerating all caches
    public function regenerateWarninglistCaches($id = false)
    {
        $redis = $this->setupRedis();
        if ($redis === false) {
            return false;
        }
        // Delete cache
        $redis->del($redis->keys('misp:wl-cache:*'));

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
            $entries = $this->WarninglistEntry->find('list', array(
                'recursive' => -1,
                'conditions' => array('warninglist_id' => $warninglist['Warninglist']['id']),
                'fields' => array('value')
            ));
            $this->cacheWarninglistEntries($entries, $warninglist['Warninglist']['id']);
        }
        return true;
    }

    private function cacheWarninglists($warninglists)
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

    private function cacheWarninglistEntries($warninglistEntries, $id)
    {
        $redis = $this->setupRedis();
        if ($redis !== false) {
            $key = 'misp:warninglist_entries_cache:' . $id;
            $redis->del($key);
            if (method_exists($redis, 'saddArray')) {
                $redis->sAddArray($key, $warninglistEntries);
            } else {
                foreach ($warninglistEntries as $entry) {
                    $redis->sAdd('misp:warninglist_entries_cache:' . $id, $entry);
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
            $entries = array_values($this->WarninglistEntry->find('list', array(
                'recursive' => -1,
                'conditions' => array('warninglist_id' => $id),
                'fields' => array('value')
            )));
            $this->cacheWarninglistEntries($entries, $id);
            return $entries;
        }
    }

    /**
     * Filter out invalid IPv4 or IPv4 CIDR and append maximum netmaks if no netmask is given.
     * @param array $inputValues
     * @return array
     */
    private function filterCidrList($inputValues)
    {
        $outputValues = [];
        foreach ($inputValues as $v) {
            $parts = explode('/', $v, 2);
            if (filter_var($parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $maximumNetmask = 32;
            } else if (filter_var($parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                $maximumNetmask = 128;
            } else {
                // IP address part of CIDR is invalid
                continue;
            }

            if (!isset($parts[1])) {
                // If CIDR doesnt contains '/', we will consider CIDR as /32 for IPv4 or /128 for IPv6
                $v = "$v/$maximumNetmask";
            } else if ($parts[1] > $maximumNetmask || $parts[1] < 0) {
                // Netmask part of CIDR is invalid
                continue;
            }

            $outputValues[$v] = $v;
        }
        return $outputValues;
    }

    private function getFilteredEntries(array $warninglist)
    {
        if (isset($this->entriesCache[$warninglist['Warninglist']['id']])) {
            return $this->entriesCache[$warninglist['Warninglist']['id']];
        }

        $values = $this->getWarninglistEntries($warninglist['Warninglist']['id']);

        if ($warninglist['Warninglist']['type'] === 'hostname') {
            $output = [];
            foreach ($values as $v) {
                $v = trim($v, '.');
                $output[$v] = $v;
            }
            $values = $output;
        } else if ($warninglist['Warninglist']['type'] === 'string') {
            $values = array_combine($values, $values);
        } else if ($warninglist['Warninglist']['type'] === 'cidr') {
            $values = $this->filterCidrList($values);
        }

        $this->entriesCache[$warninglist['Warninglist']['id']] = $values;

        return $values;
    }

    public function fetchForEventView()
    {
        $warninglists = $this->getEnabled();
        foreach ($warninglists as $k => &$t) {
            $t['values'] = $this->getFilteredEntries($t);
        }
        return $warninglists;
    }

    public function simpleCheckForWarning($object, $warninglists = null)
    {
        if ($warninglists === null) {
            $warninglists = $this->getEnabled();
        }

        if ($object['to_ids']) {
            foreach ($warninglists as $list) {
                if (in_array('ALL', $list['types']) || in_array($object['type'], $list['types'])) {
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
     * @param array $listValues
     * @param string $value
     * @param string $type
     * @param string $listType
     * @return array|false [Matched value, attribute value that matched]
     */
    private function __checkValue($listValues, $value, $type, $listType)
    {
        if ($type === 'malware-sample' || strpos($type, '|') !== false) {
            $value = explode('|', $value);
        } else {
            $value = array($value);
        }
        $components = array(0, 1);
        foreach ($components as $component) {
            if (!isset($value[$component])) {
                continue;
            }
            if ($listType === 'cidr') {
                $result = $this->__evalCidrList($listValues, $value[$component]);
            } elseif ($listType === 'string') {
                $result = $this->__evalString($listValues, $value[$component]);
            } elseif ($listType === 'substring') {
                $result = $this->__evalSubString($listValues, $value[$component]);
            } elseif ($listType === 'hostname') {
                $result = $this->__evalHostname($listValues, $value[$component]);
            } elseif ($listType === 'regex') {
                $result = $this->__evalRegex($listValues, $value[$component]);
            } else {
                $result = false;
            }
            if ($result !== false) {
                return [$result, $value[$component]];
            }
        }
        return false;
    }

    public function quickCheckValue($listValues, $value, $type)
    {
        return $this->__checkValue($listValues, $value, '', $type) !== false;
    }

    private function __evalCidrList($listValues, $value)
    {
        $valueMask = null;
        if (strpos($value, '/') !== false) {
            list($value, $valueMask) = explode('/', $value);
        }

        $match = false;
        if (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            // This code converts IP address to all possible CIDRs that can contains given IP address
            // and then check if given hash table contains that CIDR.
            $ip = ip2long($value);
            for ($bits = 0; $bits <= 32; $bits++) {
                $mask = -1 << (32 - $bits);
                $needle = long2ip($ip & $mask) . "/$bits";
                if (isset($listValues[$needle])) {
                    $match = $listValues[$needle];
                    break;
                }
            }

        } elseif (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            foreach ($listValues as $lv) {
                if (strpos($lv, ':') !== false) { // IPv6 CIDR must contain dot
                    if ($this->__ipv6InCidr($value, $lv)) {
                        $match = $lv;
                        break;
                    }
                }
            }
        }

        if ($match && $valueMask) {
            $matchMask = explode('/', $match)[1];
            if ($valueMask < $matchMask) {
                return false;
            }
        }

        return $match;
    }

    // Using solution from https://github.com/symfony/symfony/blob/master/src/Symfony/Component/HttpFoundation/IpUtils.php
    private function __ipv6InCidr($ip, $cidr)
    {
        list($address, $netmask) = explode('/', $cidr);

        $bytesAddr = unpack('n*', inet_pton($address));
        $bytesTest = unpack('n*', inet_pton($ip));

        for ($i = 1, $ceil = ceil($netmask / 16); $i <= $ceil; ++$i) {
            $left = $netmask - 16 * ($i - 1);
            $left = ($left <= 16) ? $left : 16;
            $mask = ~(0xffff >> $left) & 0xffff;
            if (($bytesAddr[$i] & $mask) != ($bytesTest[$i] & $mask)) {
                return false;
            }
        }

        return true;
    }

    private function __evalString($listValues, $value)
    {
        if (isset($listValues[$value])) {
            return $listValues[$value];
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
        if (strpos($value, '//') == false) {
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
        foreach (array_reverse($hostname) as $k => $piece) {
            if (empty($rebuilt)) {
                $rebuilt = $piece;
            } else {
                $rebuilt = $piece . '.' . $rebuilt;
            }
            if (isset($listValues[$rebuilt])) {
                return $listValues[$rebuilt];
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

    public function fetchTLDLists()
    {
        $tldLists = $this->find('list', array(
            'conditions' => array('Warninglist.name' => $this->__tlds),
            'recursive' => -1,
            'fields' => array('Warninglist.id', 'Warninglist.id')
        ));
        $tlds = array();
        if (!empty($tldLists)) {
            $tldLists = array_keys($tldLists);
            $tlds = $this->WarninglistEntry->find('list', array(
                'conditions' => array('WarninglistEntry.warninglist_id' => $tldLists),
                'fields' => array('WarninglistEntry.value')
            ));
            foreach ($tlds as $key => $value) {
                $tlds[$key] = strtolower($value);
            }
        }
        if (!in_array('onion', $tlds)) {
            $tlds[] = 'onion';
        }
        return $tlds;
    }

    /**
     * @param array $attribute
     * @param array|null $warninglists If null, all enabled warninglists will be used
     * @return bool
     */
    public function filterWarninglistAttributes(array $attribute, $warninglists = null)
    {
        if ($warninglists === null) {
            $warninglists = $this->getEnabled();
        }

        foreach ($warninglists as $warninglist) {
            if (in_array('ALL', $warninglist['types']) || in_array($attribute['type'], $warninglist['types'])) {
                $result = $this->__checkValue($this->getFilteredEntries($warninglist), $attribute['value'], $attribute['type'], $warninglist['Warninglist']['type']);
                if ($result !== false) {
                    return false;
                }
            }
        }
        return true;
    }
}
