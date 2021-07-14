<?php
App::uses('AppModel', 'Model');
App::uses('ConnectionManager', 'Model');
App::uses('Sanitize', 'Utility');

class Sightingdb extends AppModel
{

    public $errors = array(
        1 => 'Invalid SightingDB.',
        2 => 'No response from SightingDB.',
        3 => 'Invalid or unexpected response from SightingDB.',
        4 => 'DNS error - name resolution error.',
        5 => 'Could not connect to the SightingDB. Error unspecified.'
    );

    public $actsAs = array(
        'AuditLog',
        'SysLogLogable.SysLogLogable' => array(
            'userModel' => 'User',
            'userKey' => 'user_id',
            'change' => 'full'),
        'Trim',
        'Containable',
    );

    public $validate = array(
        'name' => array(
            'notBlank' => array(
                'rule' => array('notBlank'),
                'required' => array('create'),
                'message' => 'Name not set.'
            )
        ),
        'host' => array(
            'notBlank' => array(
                'rule' => array('notBlank'),
                'required' => array('create'),
                'message' => 'Host not set.'
            )
        ),
        'port' => array(
            'numeric' => array(
                'rule' => array('numeric'),
                'message' => 'Port needs to be numeric.'
            )
        ),
        'owner' => array(
            'notBlank' => array(
                'rule' => array('notBlank'),
                'required' => array('create'),
                'message' => 'Owner not set.'
            )
        )
    );

    public $hasMany = array(
        'SightingdbOrg' => array(
            'className' => 'SightingdbOrg',
            'foreignKey' => 'sightingdb_id',
            'dependent' => true
        )
    );

    private $__sightingdbs = false;

    private $__connectionStatus = array();

    /*
     * Load all sightingDBs into a persistent array
     * Helps with repeated lookups
     */
    private function __loadSightingdbs($user)
    {
        $this->__sightingdbs = $this->find('all', array(
            'recursive' => -1,
            'contain' => array('SightingdbOrg'),
            'conditions' => array('Sightingdb.enabled' => 1)
        ));
        $this->__sightingdbs = $this->extractOrgIdsFromList($this->__sightingdbs);
        foreach ($this->__sightingdbs as $k => $sightingdb) {
            if (
                empty($user['Role']['perm_site_admin']) &&
                !empty($sightingdb['Sightingdb']['org_id']) &&
                !in_array($user['org_id'], $sightingdb['Sightingdb']['org_id'])
            ) {
                unset($this->__sightingdbs[$k]);
            }
            if (empty($this->__connectionStatus[$sightingdb['Sightingdb']['id']])) {
                $this->__connectionStatus[$sightingdb['Sightingdb']['id']] = $this->requestStatus($sightingdb);
            }
            if (!is_array($this->__connectionStatus[$sightingdb['Sightingdb']['id']])) {
                unset($this->__sightingdbs[$k]);
            }
        }
        $this->__sightingdbs = array_values($this->__sightingdbs);
    }

    /*
     * Loop through a list of attributes, and pass each value to SightingDB.
     * If there's a hit, append the data directly to the attributes
     */
    public function attachToAttributes($attributes, $user)
    {
        if (!empty(Configure::read('Plugin.Sightings_sighting_db_enable'))) {
            if ($this->__sightingdbs === false) {
                $this->__loadSightingdbs($user);
            }
            if (!empty($this->__sightingdbs)) {
                $values = array();
                foreach ($attributes as $attribute) {
                    $values[$attribute['Attribute']['value']] = array();
                }
                foreach ($this->__sightingdbs as $sightingdb) {
                    $values = $this->queryValues($values, $sightingdb);
                }
                foreach ($attributes as &$attribute) {
                    if (!empty($values[$attribute['Attribute']['value']])) {
                        $attribute['Attribute']['Sightingdb'] = array_values($values[$attribute['Attribute']['value']]);
                    }
                }
            }
        }
        return $attributes;
    }

    /*
     * Loop through all attributes of an event, including those in objects
     * and pass each value to SightingDB. If there's a hit, append the data
     * directly to the attributes
     */
    public function attachToEvent($event, $user)
    {
        if (!empty(Configure::read('Plugin.Sightings_sighting_db_enable'))) {
            if ($this->__sightingdbs === false) {
                $this->__loadSightingdbs($user);
            }
            if (!empty($this->__sightingdbs)) {
                $values = $this->__collectValues($event);
                foreach ($this->__sightingdbs as $sightingdb) {
                    $values = $this->queryValues($values, $sightingdb);
                }
                $event = $this->__attachValuesToEvent($event, $values);
            }
        }
        return $event;
    }

    /*
     * Extract all attribute values from an event.
     * Also accepts the meta format from after pagination
     */
    private function __collectValues($event)
    {
        $values = array();
        if (!empty($event['Attribute'])) {
            foreach ($event['Attribute'] as $attribute) {
                $values[$attribute['value']] = array();
            }
        }
        if (!empty($event['Object'])) {
            foreach ($event['Object'] as $object) {
                if (!empty($object['Attribute'])) {
                    foreach ($object['Attribute'] as $attribute) {
                        $values[$attribute['value']] = array();
                    }
                }
            }
        }
        if (!empty($event['objects'])) {
            foreach ($event['objects'] as $object) {
                if ($object['objectType'] === 'attribute') {
                    $values[$object['value']] = array();
                } else if ($object['objectType'] === 'object') {
                    foreach ($object['Attribute'] as $attribute) {
                        $values[$attribute['value']] = array();
                    }
                }
            }
        }
        return $values;
    }

    /*
     * Reattach the sightingDB results where applicable to all attriutes in an event
     */
    private function __attachValuesToEvent($event, $values)
    {
        if (!empty($event['Attribute'])) {
            foreach ($event['Attribute'] as &$attribute) {
                if (!empty($values[$attribute['value']])) {
                    $attribute['Sightingdb'] = array_values($values[$attribute['value']]);
                }
            }
        }
        if (!empty($event['Object'])) {
            foreach ($event['Object'] as &$object) {
                if (!empty($object['Attribute'])) {
                    foreach ($object['Attribute'] as &$attribute) {
                        if (!empty($values[$attribute['value']])) {
                            $attribute['Sightingdb'] = array_values($values[$attribute['value']]);
                        }
                    }
                }
            }
        }
        if (!empty($event['objects'])) {
            foreach ($event['objects'] as &$object) {
                if ($object['objectType'] === 'attribute') {
                    if (!empty($values[$object['value']])) {
                        $object['Sightingdb'] = array_values($values[$object['value']]);
                    }
                } else if ($object['objectType'] === 'object') {
                    foreach ($object['Attribute'] as &$attribute) {
                        if (!empty($values[$attribute['value']])) {
                            $attribute['Sightingdb'] = array_values($values[$attribute['value']]);
                        }
                    }
                }
            }
        }
        return $event;
    }

    /*
     * Query the sightingDB for each value extracted
     */
    public function queryValues($values, $sightingdb)
    {
        $host = $sightingdb['Sightingdb']['host'];
        $port = $sightingdb['Sightingdb']['port'];
        App::uses('SyncTool', 'Tools');
        $syncTool = new SyncTool();
        $params = array(
            'ssl_verify_peer' => empty($sightingdb['Sightingdb']['ssl_skip_verification']),
            'ssl_verify_peer_name' => empty($sightingdb['Sightingdb']['ssl_skip_verification']),
            'ssl_verify_host' => empty($sightingdb['Sightingdb']['ssl_skip_verification']),
            'skip_proxy' => !empty($sightingdb['Sightingdb']['skip_proxy'])
        );
        $HttpSocket = $syncTool->createHttpSocket($params);
        $payload = array('items' => array());
        $namespace = empty($sightingdb['Sightingdb']['namespace']) ? 'all' : $sightingdb['Sightingdb']['namespace'];
        $valueLookup = array();
        foreach ($values as $k => $value) {
            $hashedValue = hash('sha256', $k);
            $payload['items'][] = array(
                'namespace' => $namespace,
                'value' => $hashedValue
            );
            $valueLookup[$hashedValue] = $k;
        }
        $request = array(
            'header' => array(
                'Accept' => 'application/json',
                'Content-Type' => 'application/json'
            )
        );
        try {
            $response = $HttpSocket->post(
                sprintf(
                    '%s:%s/rb',
                    $host,
                    $port
                ),
                json_encode($payload),
                $request
            );
        } catch (Exception $e) {
            return $values;
        }
        if ($response->code == 200) {
            $responseData = json_decode($response->body, true);
            if ($responseData !== false && empty($responseData['error'])) {
                foreach ($responseData['items'] as $k => $item) {
                    if (empty($item['error'])) {
                        $values[$valueLookup[$item['value']]][$sightingdb['Sightingdb']['id']] = array(
                            'first_seen' => $item['first_seen'],
                            'last_seen' => $item['last_seen'],
                            'count' => $item['count'],
                            'sightingdb_id' => $sightingdb['Sightingdb']['id']
                        );
                    }
                }
            }
        }
        return $values;
    }

    /*
     * Extract the org IDs from the sightingdbOrg objects and attach them to a simple list
     */
    public function extractOrgIdsFromList($data)
    {
        foreach ($data as &$element) {
            $element = $this->extractOrgIds($element);
        }
        return $data;
    }

    public function extractOrgIds($element)
    {
        if (isset($element['SightingdbOrg'])) {
            $element['Sightingdb']['org_id'] = Hash::extract($element['SightingdbOrg'], '{n}.org_id');
            unset($element['SightingdbOrg']);
        }
        return $element;
    }

    /*
     * Query the SightingDB, returning:
     * - implementation
     * - version
     * - vendor
     * - author
     * - measured response time
     */
    public function requestStatus($sightingdb)
    {
        if (!is_array($sightingdb)) {
            $sightingdb = $this->find('first', array(
                'conditions' => array('Sightingdb.id' => $sightingdb),
                'recursive' => -1
            ));
        }
        if (empty($sightingdb)) {
            return __('Invalid SightingDB entry.');
        }
        App::uses('SyncTool', 'Tools');
        $syncTool = new SyncTool();
        $params = array(
            'ssl_allow_self_signed' => true,
            'ssl_verify_peer' => false,
            'ssl_verify_peer_name' => false
        );
        $HttpSocket = $syncTool->createHttpSocket($params);
        $start = microtime(true);
        try {
            $response = $HttpSocket->get(
                sprintf(
                    '%s:%s/i',
                    $sightingdb['Sightingdb']['host'],
                    $sightingdb['Sightingdb']['port']
                )
            );
        } catch (Exception $e) {
            if (strpos($e->getMessage(), 'php_network_getaddresses') !== false) {
                return __('Could not resolve Sightingdb address.');
            } else {
                return __('Something went wrong. Could not contact the SightingDB server.');
            }
        }
        $response_time = round(1000*(microtime(true) - $start));
        if ($response->code == 200) {
            $responseData = json_decode($response->body, true);
            if (!empty($responseData['implementation'])) {
                $result = array();
                $fields = array('implementation', 'version', 'vendor', 'author');
                foreach ($fields as $field) {
                    $result[$field] = $responseData[$field];
                }
                $result['response_time'] = $response_time . 'ms';
                return $result;
            } else {
                return __('The SightingDB returned an invalid response.');
            }
        } else {
            return __('No response from the SightingDB server.');
        }
    }

    /*
     * Get a list of all valid sightingDBs for the user
     */
    public function getSightingdbList($user)
    {
        $sightingdbs = $this->find('all', array(
            'recursive' => -1,
            'contain' => 'SightingdbOrg',
            'conditions' => array('Sightingdb.enabled' => 1)
        ));
        if (empty($sightingdbs)) {
            return array();
        }
        $sightingdbs = $this->extractOrgIdsFromList($sightingdbs);
        $toReturn = array();
        foreach ($sightingdbs as $sightingdb) {
            if (
                !empty($user['Role']['perm_site_admin']) ||
                empty($sightingdb['Sightingdb']['org_id']) ||
                in_array($user['org_id'], $sightingdb['Sightingdb']['org_id']
            )) {
                $toReturn[$sightingdb['Sightingdb']['id']] = $sightingdb;
            }
        }
        return $toReturn;
    }
}
