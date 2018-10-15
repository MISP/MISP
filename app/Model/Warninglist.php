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
            $redis->del('misp:warninglist_entries_cache:');
            foreach ($warninglistEntries as $entry) {
                $redis->sAdd('misp:warninglist_entries_cache:' . $id, $entry);
            }
            return true;
        }
        return false;
    }

    public function getWarninglists($conditions)
    {
        $redis = $this->setupRedis();
        if ($redis !== false) {
            if (!$redis->exists('misp:warninglist_cache') || $redis->sCard('misp:warninglist_cache') == 0) {
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
            if (!$redis->exists('misp:warninglist_entries_cache:' . $id) || $redis->sCard('misp:warninglist_entries_cache:' . $id) == 0) {
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

    public function fetchForEventView()
    {
        $warninglists = $this->getWarninglists(array('enabled' => 1));
        if (empty($warninglists)) {
            return array();
        }
        foreach ($warninglists as $k => &$t) {
            $t['values'] = $this->getWarninglistEntries($t['Warninglist']['id']);
            $t['values'] = array_values($t['values']);
            if ($t['Warninglist']['type'] == 'hostname') {
                foreach ($t['values'] as $vk => $v) {
                    $t['values'][$vk] = rtrim($v, '.');
                }
            }
            if ($t['Warninglist']['type'] == 'string' || $t['Warninglist']['type'] == 'hostname') {
                $t['values'] = array_combine($t['values'], $t['values']);
            }
            foreach ($t['WarninglistType'] as &$wt) {
                $t['types'][] = $wt['type'];
            }
            unset($warninglists[$k]['WarninglistType']);
        }
        return $warninglists;
    }

    public function checkForWarning($object, &$eventWarnings, $warningLists)
    {
        if ($object['to_ids']) {
            foreach ($warningLists as $list) {
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

    private function __checkValue($listValues, $value, $type, $listType)
    {
        if (strpos($type, '|') || $type = 'malware-sample') {
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
                return ($component + 1);
            }
        }
        return false;
    }

    // This requires an IP type attribute in a non CIDR notation format
    // For the future we can expand this to look for CIDR overlaps?
    private function __evalCIDRList($listValues, $value)
    {
        $ipv4cidrlist = array();
        $ipv6cidrlist = array();
        // separate the CIDR list into IPv4 and IPv6
        foreach ($listValues as $lv) {
            $base = substr($lv, 0, strpos($lv, '/'));
            if (filter_var($base, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $ipv4cidrlist[] = $lv;
            } elseif (filter_var($base, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                $ipv6cidrlist[] = $lv;
            }
        }
        // evaluate the value separately for IPv4 and IPv6
        if (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return $this->__evalCIDR($value, $ipv4cidrlist, '__ipv4InCidr');
        } elseif (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return $this->__evalCIDR($value, $ipv6cidrlist, '__ipv6InCidr');
        }
        return false;
    }

    private function __evalCIDR($value, $listValues, $function)
    {
        $found = false;
        foreach ($listValues as $lv) {
            if ($this->$function($value, $lv)) {
                $found = true;
            }
        }
        if ($found) {
            return true;
        }
        return false;
    }

    // using Alnitak's solution from http://stackoverflow.com/questions/594112/matching-an-ip-to-a-cidr-mask-in-php5
    private function __ipv4InCidr($ip, $cidr)
    {
        list($subnet, $bits) = explode('/', $cidr);
        $ip = ip2long($ip);
        $subnet = ip2long($subnet);
        $mask = -1 << (32 - $bits);
        $subnet &= $mask; # nb: in case the supplied subnet wasn't correctly aligned
        return ($ip & $mask) == $subnet;
    }

    // using Snifff's solution from http://stackoverflow.com/questions/7951061/matching-ipv6-address-to-a-cidr-subnet
    private function __ipv6InCidr($ip, $cidr)
    {
        $ip = inet_pton($ip);
        $binaryip = $this->__inet_to_bits($ip);
        list($net, $maskbits) = explode('/', $cidr);
        $net = inet_pton($net);
        $binarynet = $this->__inet_to_bits($net);
        $ip_net_bits = substr($binaryip, 0, $maskbits);
        $net_bits = substr($binarynet, 0, $maskbits);
        return ($ip_net_bits === $net_bits);
    }

    // converts inet_pton output to string with bits
    private function __inet_to_bits($inet)
    {
        $unpacked = unpack('A16', $inet);
        $unpacked = str_split($unpacked[1]);
        $binaryip = '';
        foreach ($unpacked as $char) {
            $binaryip .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
        }
        return $binaryip;
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
