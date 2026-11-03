<?php
App::uses('AppModel', 'Model');
App::uses('ConnectionManager', 'Model');
App::uses('Sanitize', 'Utility');

class Sightingdb extends AppModel
{
    // Below the namespaces MISP reads from, where it writes the sightings recorded in it
    const PUSH_NAMESPACE = 'misp';

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
     * Loop through a list of objects, and pass each of their attribute values to
     * SightingDB. If there's a hit, append the data directly to the attributes
     */
    public function attachToObjects($objects, $user)
    {
        if (!empty(Configure::read('Plugin.Sightings_sighting_db_enable'))) {
            if ($this->__sightingdbs === false) {
                $this->__loadSightingdbs($user);
            }
            if (!empty($this->__sightingdbs)) {
                $values = array();
                foreach ($objects as $object) {
                    foreach ($object['Attribute'] ?? [] as $attribute) {
                        $values[$attribute['value']] = array();
                    }
                }
                foreach ($this->__sightingdbs as $sightingdb) {
                    $values = $this->queryValues($values, $sightingdb);
                }
                foreach ($objects as &$object) {
                    if (empty($object['Attribute'])) {
                        continue;
                    }
                    foreach ($object['Attribute'] as &$attribute) {
                        if (!empty($values[$attribute['value']])) {
                            $attribute['Sightingdb'] = array_values($values[$attribute['value']]);
                        }
                    }
                    unset($attribute);
                }
                unset($object);
            }
        }
        return $objects;
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
     * Reattach the sightingDB results where applicable to all attributes in an event
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
     * Query the sightingDB for each value extracted: how often it was sighted,
     * and, when the connection has a false-positive namespace, how often it was
     * reported as a false-positive. A hit is attached under the connection's id
     * with `count`, `first_seen` and `last_seen` for sightings, and the same
     * under `false_positive`. A sighted value SightingDB will expire - it has a
     * TTL - also carries `expiration`, the Unix time it stops being valid: its
     * last sighting plus the TTL.
     */
    public function queryValues($values, $sightingdb)
    {
        $namespaces = array('sighting' => $this->__namespace($sightingdb));
        $falsePositiveNamespace = $this->__falsePositiveNamespace($sightingdb);
        if ($falsePositiveNamespace !== null) {
            $namespaces['false_positive'] = $falsePositiveNamespace;
        }
        $payload = array('items' => array());
        $lookup = array();
        foreach ($values as $k => $value) {
            $hashedValue = self::hashValue($k);
            foreach ($namespaces as $type => $namespace) {
                $payload['items'][] = array(
                    'namespace' => $namespace,
                    'value' => $hashedValue
                );
                $lookup[] = array($k, $type);
            }
        }
        $responseData = $this->__post($sightingdb, '/rb', $payload, 3);
        if (empty($responseData['items'])) {
            return $values;
        }
        $id = $sightingdb['Sightingdb']['id'];
        // Results are positional: item n answers item n of the request
        foreach ($responseData['items'] as $n => $item) {
            if (!empty($item['error']) || !isset($lookup[$n])) {
                continue;
            }
            list($k, $type) = $lookup[$n];
            if (!isset($values[$k][$id])) {
                $values[$k][$id] = array('sightingdb_id' => $id, 'count' => 0);
            }
            $hit = array(
                'count' => $item['count'],
                'first_seen' => $item['first_seen'],
                'last_seen' => $item['last_seen']
            );
            if ($type === 'sighting') {
                $values[$k][$id] = array_merge($values[$k][$id], $hit);
                if (!empty($item['ttl'])) {
                    $values[$k][$id]['expiration'] = (int)$item['last_seen'] + (int)$item['ttl'];
                }
            } else {
                $values[$k][$id]['false_positive'] = $hit;
            }
        }
        return $values;
    }

    /*
     * Daily counts for the given values from the hourly statistics SightingDB
     * keeps, for the sightings graph: per SightingDB the user may query, keyed by
     * its name, then by type ('sighting', and 'false-positive' when the
     * connection has a false-positive namespace), then by Y-m-d.
     */
    public function queryDailyCounts(array $values, array $user)
    {
        $result = array();
        if (empty(Configure::read('Plugin.Sightings_sighting_db_enable')) || empty($values)) {
            return $result;
        }
        foreach ($this->getSightingdbList($user) as $sightingdb) {
            $namespaces = array('sighting' => $this->__namespace($sightingdb));
            $falsePositiveNamespace = $this->__falsePositiveNamespace($sightingdb);
            if ($falsePositiveNamespace !== null) {
                $namespaces['false-positive'] = $falsePositiveNamespace;
            }
            $payload = array('items' => array());
            $types = array();
            foreach (array_unique($values) as $value) {
                foreach ($namespaces as $type => $namespace) {
                    $payload['items'][] = array(
                        'namespace' => $namespace,
                        'value' => self::hashValue($value),
                        // A graph is not an analyst looking a value up
                        'noshadow' => true
                    );
                    $types[] = $type;
                }
            }
            $responseData = $this->__post($sightingdb, '/rbs', $payload, 3);
            if (empty($responseData['items'])) {
                continue;
            }
            // Every line the connection can draw, flat at zero where nothing was counted
            $counts = array_fill_keys(array_keys($namespaces), array());
            foreach ($responseData['items'] as $n => $item) {
                if (!empty($item['error']) || empty($item['stats']) || !isset($types[$n])) {
                    continue;
                }
                foreach ($item['stats'] as $hour => $count) {
                    $day = date('Y-m-d', (int)$hour);
                    $counts[$types[$n]][$day] = ($counts[$types[$n]][$day] ?? 0) + (int)$count;
                }
            }
            $result[$sightingdb['Sightingdb']['name']] = $counts;
        }
        return $result;
    }

    /*
     * Write sightings recorded in MISP to every enabled SightingDB that asks for
     * them, as the SHA-256 of each value. They go to a `misp` namespace below the
     * ones MISP reads from: lookups are exact, so MISP never counts its own
     * sightings a second time, while the rest of SightingDB's users see them.
     * Best effort: a SightingDB that is down never stops a sighting being saved
     * in MISP, so failures are logged and otherwise ignored.
     *
     * @param array $sightings Each with `value`, `timestamp` (Unix time) and `type`
     *                         (0 sighting, 1 false-positive)
     */
    public function pushSightings(array $sightings, array $user)
    {
        if (empty(Configure::read('Plugin.Sightings_sighting_db_enable')) || empty($sightings)) {
            return;
        }
        foreach ($this->getSightingdbList($user) as $sightingdb) {
            if (empty($sightingdb['Sightingdb']['push_sightings'])) {
                continue;
            }
            $falsePositiveNamespace = $this->__falsePositiveNamespace($sightingdb);
            $namespaces = array(
                0 => $this->__namespace($sightingdb) . '/' . self::PUSH_NAMESPACE,
                1 => $falsePositiveNamespace === null ? null : $falsePositiveNamespace . '/' . self::PUSH_NAMESPACE,
            );
            $payload = array('items' => array());
            foreach ($sightings as $sighting) {
                $namespace = $namespaces[(int)$sighting['type']] ?? null;
                if ($namespace === null) {
                    continue;
                }
                $payload['items'][] = array(
                    'namespace' => $namespace,
                    'value' => self::hashValue($sighting['value']),
                    'timestamp' => (int)$sighting['timestamp']
                );
            }
            if (empty($payload['items'])) {
                continue;
            }
            $responseData = $this->__post($sightingdb, '/wb', $payload, 5);
            if ($responseData === false || ($responseData['message'] ?? null) !== 'ok') {
                $this->log(sprintf(
                    'Could not push %s sighting(s) to SightingDB "%s": %s',
                    count($payload['items']),
                    $sightingdb['Sightingdb']['name'],
                    $responseData === false ? 'no valid response' : json_encode($responseData['errors'] ?? $responseData)
                ), LOG_WARNING);
            }
        }
    }

    /*
     * What MISP stores in and looks up from SightingDB in place of a value
     */
    public static function hashValue($value)
    {
        return hash('sha256', (string)$value);
    }

    private function __namespace(array $sightingdb)
    {
        return empty($sightingdb['Sightingdb']['namespace']) ? 'all' : $sightingdb['Sightingdb']['namespace'];
    }

    private function __falsePositiveNamespace(array $sightingdb)
    {
        return empty($sightingdb['Sightingdb']['false_positive_namespace']) ? null : $sightingdb['Sightingdb']['false_positive_namespace'];
    }

    /*
     * POST a JSON payload to a SightingDB, authenticated with the connection's
     * API key if it has one. Returns the decoded response, or false when the
     * server could not be reached or did not answer with JSON.
     */
    private function __post(array $sightingdb, $path, array $payload, $timeout = null)
    {
        App::uses('SyncTool', 'Tools');
        $syncTool = new SyncTool();
        $params = array(
            'ssl_verify_peer' => empty($sightingdb['Sightingdb']['ssl_skip_verification']),
            'ssl_verify_peer_name' => empty($sightingdb['Sightingdb']['ssl_skip_verification']),
            'ssl_verify_host' => empty($sightingdb['Sightingdb']['ssl_skip_verification']),
            'skip_proxy' => !empty($sightingdb['Sightingdb']['skip_proxy'])
        );
        if ($timeout !== null) {
            $params['timeout'] = $timeout;
        }
        $request = array(
            'header' => array(
                'Accept' => 'application/json',
                'Content-Type' => 'application/json'
            )
        );
        if (!empty($sightingdb['Sightingdb']['api_key'])) {
            $request['header']['Authorization'] = $sightingdb['Sightingdb']['api_key'];
        }
        try {
            $HttpSocket = $syncTool->createHttpSocket($params);
            $response = $HttpSocket->post(
                sprintf('%s:%s%s', $sightingdb['Sightingdb']['host'], $sightingdb['Sightingdb']['port'], $path),
                json_encode($payload),
                $request
            );
        } catch (Exception $e) {
            return false;
        }
        $responseData = json_decode($response->body, true);
        if (!is_array($responseData)) {
            return false;
        }
        // /rb answers 200; /wb answers 403 or 400 when nothing at all was written
        if ($response->code != 200 && !isset($responseData['items'])) {
            return false;
        }
        return $responseData;
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
