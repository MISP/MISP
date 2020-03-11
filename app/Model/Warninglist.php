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

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        return true;
    }

    public function getTldLists()
    {
        return $this->__tlds;
    }

    public function update()
    {
        $directories = glob(APP . 'files' . DS . 'warninglists' . DS . 'lists' . DS . '*', GLOB_ONLYDIR);
        $updated = array();
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
        $warninglists = $this->find('all', array('contain' => array('WarninglistType'), 'conditions' => array('enabled' => 1)));
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

    public function cacheWarninglists($warninglists)
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

    public function cacheWarninglistEntries($warninglistEntries, $id)
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

    public function getWarninglists($conditions)
    {
        $redis = $this->setupRedis();
        if ($redis !== false) {
            if ($redis->sCard('misp:warninglist_cache') === 0) {
                if (!empty($conditions)) {
                    $warninglists = $this->find('all', array('contain' => array('WarninglistType'), 'conditions' => $conditions));
                } else {
                    $warninglists = $this->find('all', array('contain' => array('WarninglistType'), 'conditions' => array('enabled' => 1)));
                }
                if (empty($conditions)) {
                    $this->cacheWarninglists($warninglists);
                }
                return $warninglists;
            } else {
                $warninglists = $redis->sMembers('misp:warninglist_cache');
                foreach ($warninglists as $k => $v) {
                    $warninglists[$k] = json_decode($v, true);
                }
                if (!empty($conditions)) {
                    foreach ($warninglists as $k => $v) {
                        foreach ($conditions as $k2 => $v2) {
                            if ($v['Warninglist'][$k2] != $v2) {
                                unset($warninglists[$k]);
                                continue 2;
                            }
                        }
                    }
                }
                return $warninglists;
            }
        }
    }

    public function getWarninglistEntries($id)
    {
        $redis = $this->setupRedis();
        if ($redis !== false) {
            if ($redis->sCard('misp:warninglist_entries_cache:' . $id) === 0) {
                $entries = $this->WarninglistEntry->find('list', array(
                        'recursive' => -1,
                        'conditions' => array('warninglist_id' => $id),
                        'fields' => array('value')
                ));
                $this->cacheWarninglistEntries($entries, $id);
            } else {
                $entries = $redis->sMembers('misp:warninglist_entries_cache:' . $id);
            }
        } else {
            $entries = $this->WarninglistEntry->find('list', array(
                    'recursive' => -1,
                    'conditions' => array('warninglist_id' => $id),
                    'fields' => array('value')
            ));
        }
        return $entries;
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

    public function fetchForEventView()
    {
        $warninglists = $this->getWarninglists(array('enabled' => 1));
        if (empty($warninglists)) {
            return array();
        }
        foreach ($warninglists as $k => &$t) {
            $t['values'] = $this->getWarninglistEntries($t['Warninglist']['id']);
            $t['values'] = array_values($t['values']);

            if ($t['Warninglist']['type'] === 'hostname') {
                $values = [];
                foreach ($t['values'] as $v) {
                    $v = rtrim($v, '.');
                    $values[$v] = $v;
                }
                $t['values'] = $values;
            } else if ($t['Warninglist']['type'] === 'string') {
                $t['values'] = array_combine($t['values'], $t['values']);
            } else if ($t['Warninglist']['type'] === 'cidr') {
                $t['values'] = $this->filterCidrList($t['values']);
            }

            foreach ($t['WarninglistType'] as $wt) {
                $t['types'][] = $wt['type'];
            }
            unset($warninglists[$k]['WarninglistType']);
        }
        return $warninglists;
    }

    public function simpleCheckForWarning($object, $warninglists, $returnVerboseValue = false)
    {
        if ($object['to_ids']) {
            foreach ($warninglists as $list) {
                if (in_array('ALL', $list['types']) || in_array($object['type'], $list['types'])) {
                    $result = $this->__checkValue($list['values'], $object['value'], $object['type'], $list['Warninglist']['type']);
                    if (!empty($result)) {
                        if ($returnVerboseValue) {
                            $object['warnings'][] = array(
                                'value' => $result,
                                'warninglist_name' => $list['Warninglist']['name'],
                                'warninglist_id' => $list['Warninglist']['id']
                            );
                        } else {
                            $object['warnings'][$result][] = $list['Warninglist']['name'];
                        }
                    }
                }
            }
        }
        return $object;
    }

    public function checkForWarning($object, &$eventWarnings, $warningLists, $returnVerboseValue = false)
    {
        if ($object['to_ids']) {
            foreach ($warningLists as $list) {
                if (in_array('ALL', $list['types']) || in_array($object['type'], $list['types'])) {
                    $result = $this->__checkValue($list['values'], $object['value'], $object['type'], $list['Warninglist']['type'], $returnVerboseValue);
                    if (!empty($result)) {
                        if ($returnVerboseValue) {
                            $object['warnings'][] = array(
                                'value' => $result,
                                'warninglist_name' => $list['Warninglist']['name'],
                                'warninglist_id' => $list['Warninglist']['id']
                            );
                        } else {
                            $object['warnings'][$result][] = $list['Warninglist']['name'];
                        }
                        if (empty($eventWarnings) || !in_array($list['Warninglist']['name'], $eventWarnings)) {
                            $eventWarnings[$list['Warninglist']['id']] = $list['Warninglist']['name'];
                        }
                    }
                }
            }
        }
        return $object;
    }

    public function setWarnings(&$event, &$warninglists)
    {
        if (empty($event['objects'])) {
            return $event;
        }
        $eventWarnings = array();
        foreach ($event['objects'] as &$object) {
            if ($object['to_ids']) {
                foreach ($warninglists as $list) {
                    if (in_array('ALL', $list['types']) || in_array($object['type'], $list['types'])) {
                        $result = $this->__checkValue($list['values'], $object['value'], $object['type'], $list['Warninglist']['type']);
                        if (!empty($result)) {
                            $object['warnings'][$result][] = $list['Warninglist']['name'];
                            if (!in_array($list['Warninglist']['name'], $eventWarnings)) {
                                $eventWarnings[$list['Warninglist']['id']] = $list['Warninglist']['name'];
                            }
                        }
                    }
                }
            }
        }
        $event['Event']['warnings'] = $eventWarnings;
        return $event;
    }

    private function __checkValue($listValues, $value, $type, $listType, $returnVerboseValue = false)
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
                $result = $this->__evalCIDRList($listValues, $value[$component]);
            } elseif ($listType === 'string') {
                $result = $this->__evalString($listValues, $value[$component]);
            } elseif ($listType === 'substring') {
                $result = $this->__evalSubString($listValues, $value[$component]);
            } elseif ($listType === 'hostname') {
                $result = $this->__evalHostname($listValues, $value[$component]);
            } elseif ($listType === 'regex') {
                $result = $this->__evalRegex($listValues, $value[$component]);
            }
            if (!empty($result)) {
                if ($returnVerboseValue) {
                    return $value[$component];
                }
                return ($component + 1);
            }
        }
        return false;
    }

    public function quickCheckValue($listValues, $value, $type)
    {
        $typeMapping = array(
            'cidr' => '__evalCIDRList',
            'string' => '__evalString',
            'substring' => '__evalSubString',
            'hostname' => '__evalHostname',
            'regex' => '__evalRegex'
        );
        $result = $this->{$typeMapping[$type]}($listValues, $value);
        return (!empty($result) ? 1 : false);
    }

    // This requires an IP type attribute in a non CIDR notation format
    // For the future we can expand this to look for CIDR overlaps?
    private function __evalCIDRList($listValues, $value)
    {
        if (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            // This code converts IP address to all possible CIDRs that can contains given IP address
            // and then check if given hash table contains that CIDR.
            $ip = ip2long($value);
            for ($bits = 0; $bits <= 32; $bits++) {
                $mask = -1 << (32 - $bits);
                $needle = long2ip($ip & $mask) . "/$bits";
                if (isset($listValues[$needle])) {
                    return true;
                }
            }

        } elseif (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            foreach ($listValues as $lv) {
                if (strpos($lv, ':') !== false) { // IPv6 CIDR must contain dot
                    if ($this->__ipv6InCidr($value, $lv)) {
                        return true;
                    }
                }
            }
        }

        return false;
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
            return true;
        }
        return false;
    }

    private function __evalSubString($listValues, $value)
    {
        foreach ($listValues as $listValue) {
            if (strpos($value, $listValue) !== false) {
                return true;
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
                return true;
            }
        }
        return false;
    }

    private function __evalRegex($listValues, $value)
    {
        foreach ($listValues as $listValue) {
            if (preg_match($listValue, $value)) {
                return true;
            }
        }
        return false;
    }

    public function fetchTLDLists()
    {
        $tldLists = $this->find('list', array('conditions' => array('Warninglist.name' => $this->__tlds), 'recursive' => -1, 'fields' => array('Warninglist.id', 'Warninglist.name')));
        $tlds = array();
        if (!empty($tldLists)) {
            $tldLists = array_keys($tldLists);
            $tlds = $this->WarninglistEntry->find('list', array('conditions' => array('WarninglistEntry.warninglist_id' => $tldLists), 'fields' => array('WarninglistEntry.value')));
            if (!empty($tlds)) {
                foreach ($tlds as $key => $value) {
                    $tlds[$key] = strtolower($value);
                }
            }
        }
        if (!in_array('onion', $tlds)) {
            $tlds[] = 'onion';
        }
        return $tlds;
    }

    public function filterWarninglistAttributes($warninglists, $attribute)
    {
        foreach ($warninglists as $warninglist) {
            if (in_array('ALL', $warninglist['types']) || in_array($attribute['type'], $warninglist['types'])) {
                $result = $this->__checkValue($warninglist['values'], $attribute['value'], $attribute['type'], $warninglist['Warninglist']['type']);
                if ($result !== false) {
                    return false;
                }
            }
        }
        return true;
    }
}
