<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;
use Cake\ORM\Table;
use Cake\Validation\Validator;
use Cake\Core\Configure;
use Cake\Core\Exception\Exception;
use Cake\Utility\Hash;
require_once(ROOT . '/src/Lib/Tools/HttpTool.php');

class SightingdbsTable extends AppTable
{
    private $__sightingdbs = false;

    private $__connectionStatus = array();

    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('AuditLog');
        $this->setDisplayField('name');
        $this->hasMany(
            'SightingdbOrg',
            [
                'dependent' => false,
                'cascadeCallbacks' => false
            ]
        );
    }

    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->notEmptyString('name')
            ->notEmptyString('host')
            ->notEmptyString('owner')
            ->add('port', 'integer', [
                'rule' => 'isInteger',
                'message' => __('Port has to be an integer.')
            ])
            ->add('port', 'positive', [
                'rule' => ['range', 0, 65535],
                'message' => __('Port has to be in the 0-65535 range.')
            ])
            ->requirePresence(['name', 'host', 'owner', 'port'], 'create');
        return $validator;
    }


    /*
     * Load all sightingDBs into a persistent array
     * Helps with repeated lookups
     */
    private function __loadSightingdbs(Object $user): void
    {
        $this->__sightingdbs = $this->find('all', array(
            'recursive' => -1,
            'contain' => array('SightingdbOrg'),
            'conditions' => array('Sightingdb.enabled' => 1)
        ));
        $this->__sightingdbs = $this->find('all')
            ->where(['enabled' => 1])
            ->contain(['SightingdbOrg'])
            ->disableHydration();
        $this->__sightingdbs = $this->extractOrgIdsFromList($this->__sightingdbs);
        foreach ($this->__sightingdbs as $k => $sightingdb) {
            if (
                empty($user['Role']['perm_site_admin']) &&
                !empty($sightingdb['org_id']) &&
                !in_array($user['org_id'], $sightingdb['org_id'])
            ) {
                unset($this->__sightingdbs[$k]);
            }
            if (empty($this->__connectionStatus[$sightingdb['id']])) {
                $this->__connectionStatus[$sightingdb['id']] = $this->requestStatus($sightingdb);
            }
            if (!is_array($this->__connectionStatus[$sightingdb['id']])) {
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
                $values = [];
                foreach ($attributes as $attribute) {
                    $values[$attribute['Attribute']['value']] = [];
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
    public function queryValues(array $values, array $sightingdb): array
    {
        $host = $sightingdb['host'];
        $port = $sightingdb['port'];
        $params = [
            'ssl_verify_peer' => empty($sightingdb['ssl_skip_verification']),
            'ssl_verify_peer_name' => empty($sightingdb['ssl_skip_verification']),
            'ssl_verify_host' => empty($sightingdb['ssl_skip_verification']),
            'skip_proxy' => !empty($sightingdb['skip_proxy']),
            'headers' => [
                'Accept' => 'application/json',
                'Content-Type' => 'application/json'
            ]
        ];
        $payload = ['items' => []];
        $namespace = empty($sightingdb['namespace']) ? 'all' : $sightingdb['namespace'];
        $valueLookup = [];
        foreach ($values as $k => $value) {
            $hashedValue = hash('sha256', $k);
            $payload['items'][] = [
                'namespace' => $namespace,
                'value' => $hashedValue
            ];
            $valueLookup[$hashedValue] = $k;
        }
        $http = new \App\Lib\Tools\HttpTool($params);
        try {
            $response = $http->post(
                sprintf(
                    '%s:%s/rb',
                    $host,
                    $port
                ),
                json_encode($payload)
            );
        } catch (Exception $e) {
            return $values;
        }
        if ($response->getStatusCode() == 200) {
            $responseData = json_decode($response->getStringBody(), true);
            if ($responseData !== false && empty($responseData['error'])) {
                foreach ($responseData['items'] as $k => $item) {
                    if (empty($item['error'])) {
                        $values[$valueLookup[$item['value']]][$sightingdb['id']] = [
                            'first_seen' => $item['first_seen'],
                            'last_seen' => $item['last_seen'],
                            'count' => $item['count'],
                            'sightingdb_id' => $sightingdb['id']
                        ];
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
        $result = [];
        foreach ($data as $k => $element) {
            $result[$k] = $this->extractOrgIds($element);
        }
        return $result;
    }

    public function extractOrgIds($element)
    {
        if (isset($element['SightingdbOrg'])) {
            $element['org_id'] = Hash::extract($element['SightingdbOrg'], '{n}.org_id');
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
    public function requestStatus(mixed $sightingdb): mixed
    {
        if (!is_array($sightingdb)) {
            $sightingdb = $this->find('all', [
                'conditions' => array('Sightingdb.id' => $sightingdb),
                'recursive' => -1
            ])->first();
        }
        if (empty($sightingdb)) {
            return __('Invalid SightingDB entry.');
        }
        $params = [
            'ssl_allow_self_signed' => true,
            'ssl_verify_peer' => false,
            'ssl_verify_peer_name' => false
        ];
        $http = new \App\Lib\Tools\HttpTool($params);
        $start = microtime(true);
        try {
            $response = $http->get(
                sprintf(
                    '%s:%s/i',
                    $sightingdb['host'],
                    $sightingdb['port']
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
        if ($response->getStatusCode() == 200) {
            $responseData = json_decode($response->getStringBody(), true);
            if (!empty($responseData['implementation'])) {
                $result = [];
                $fields = ['implementation', 'version', 'vendor', 'author'];
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
    public function getSightingdbList($user): array
    {
        $sightingdbs = $this->find()->where(['enabled' => 1])->contain(['SightingdbOrg'])->all()->toList();
        if (empty($sightingdbs)) {
            return [];
        }
        $sightingdbs = $this->extractOrgIdsFromList($sightingdbs);
        $toReturn = [];
        foreach ($sightingdbs as $sightingdb) {
            if (
                !empty($user['Role']['perm_site_admin']) ||
                empty($sightingdb['org_id']) ||
                in_array($user['org_id'], $sightingdb['org_id']
            )) {
                $toReturn[$sightingdb['id']] = $sightingdb;
            }
        }
        return $toReturn;
    }

}
