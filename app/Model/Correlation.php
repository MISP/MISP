<?php
App::uses('AppModel', 'Model');
App::uses('RandomTool', 'Tools');

/**
 * @property Attribute $Attribute
 */
class Correlation extends AppModel
{
    const CACHE_NAME = 'misp:top_correlations',
        CACHE_AGE = 'misp:top_correlations_age';

    public $belongsTo = array(
        'Attribute' => [
            'className' => 'Attribute',
            'foreignKey' => 'attribute_id'
        ],
        'Event' => array(
            'className' => 'Event',
            'foreignKey' => 'event_id'
        )
    );

    /** @var array */
    private $exclusions;

    /**
     * Use old schema with `date` and `info` fields.
     * @var bool
     */
    private $oldSchema;

    /** @var bool */
    private $deadlockAvoidance;

    public function __construct($id = false, $table = null, $ds = null)
    {
        parent::__construct($id, $table, $ds);
        $this->oldSchema = $this->schema('date') !== null;
        $this->deadlockAvoidance = Configure::read('MISP.deadlock_avoidance');
    }

    public function correlateValueRouter($value)
    {
        if (Configure::read('MISP.background_jobs')) {

            /** @var Job $job */
            $job = ClassRegistry::init('Job');
            $jobId = $job->createJob(
                'SYSTEM',
                Job::WORKER_DEFAULT,
                'correlateValue',
                $value,
                'Recorrelating'
            );

            $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::DEFAULT_QUEUE,
                BackgroundJobsTool::CMD_EVENT,
                [
                    'correlateValue',
                    $value,
                    $jobId
                ],
                true,
                $jobId
            );

            return true;
        } else {
            return $this->correlateValue($value);
        }
    }

    private function __buildAdvancedCorrelationConditions($a)
    {
        if (isset($a['Attribute'])) {
            $a = $a['Attribute'];
        }
        $extraConditions = null;
        if (in_array($a['type'], ['ip-src', 'ip-dst', 'ip-src|port', 'ip-dst|port'], true)) {
            $extraConditions = $this->cidrCorrelation($a);
        } else if ($a['type'] === 'ssdeep' && function_exists('ssdeep_fuzzy_compare')) {
            $extraConditions = $this->ssdeepCorrelation($a);
        }
        return $extraConditions;
    }

    private function __addAdvancedCorrelations($correlatingAttribute)
    {
        if (empty(Configure::read('MISP.enable_advanced_correlations'))) {
            return [];
        }
        $extraConditions = $this->__buildAdvancedCorrelationConditions($correlatingAttribute);
        if (empty($extraConditions)) {
            return [];
        }
        return $this->Attribute->find('all', [
            'conditions' => [
                'AND' => $extraConditions,
                'NOT' => [
                    'Attribute.type' => Attribute::NON_CORRELATING_TYPES,
                ],
                'Attribute.disable_correlation' => 0,
                'Event.disable_correlation' => 0,
                'Attribute.deleted' => 0
            ],
            'recursive' => -1,
            'fields' => [
                'Attribute.event_id',
                'Attribute.id',
                'Attribute.distribution',
                'Attribute.sharing_group_id',
                'Attribute.value1',
                'Attribute.value2',
            ],
            'contain' => [
                'Event' => [
                    'fields' => ['Event.id', 'Event.org_id', 'Event.distribution', 'Event.sharing_group_id']
                ]
            ],
            'order' => [],
        ]);
    }

    private function __getMatchingAttributes($value)
    {
        $conditions = [
            'OR' => [
                'Attribute.value1' => $value,
                'AND' => [
                    'Attribute.value2' => $value,
                    'NOT' => ['Attribute.type' => Attribute::PRIMARY_ONLY_CORRELATING_TYPES]
                ]
            ],
            'NOT' => [
                'Attribute.type' => Attribute::NON_CORRELATING_TYPES,
            ],
            'Attribute.disable_correlation' => 0,
            'Event.disable_correlation' => 0,
            'Attribute.deleted' => 0
        ];
        $correlatingAttributes = $this->Attribute->find('all', [
            'conditions' => $conditions,
            'recursive' => -1,
            'fields' => [
                'Attribute.event_id',
                'Attribute.id',
                'Attribute.type',
                'Attribute.distribution',
                'Attribute.sharing_group_id',
                'Attribute.value1',
                'Attribute.value2',
            ],
            'contain' => [
                'Event' => [
                    'fields' => ['Event.id', 'Event.org_id', 'Event.distribution', 'Event.sharing_group_id']
                ]
            ],
            'order' => [],
        ]);
        return $correlatingAttributes;
    }

    private function __addCorrelationEntry($value, $a, $b, $correlations)
    {
        if (
            $a['Attribute']['event_id'] !== $b['Attribute']['event_id']
        ) {
            if ($this->deadlockAvoidance) {
                $correlations[] = [
                    'value' => $value,
                    '1_event_id' => $a['Event']['id'],
                    '1_attribute_id' => $a['Attribute']['id'],
                    'event_id' => $b['Attribute']['event_id'],
                    'attribute_id' => $b['Attribute']['id'],
                    'org_id' => $b['Event']['org_id'],
                    'distribution' => $b['Event']['distribution'],
                    'a_distribution' => $b['Attribute']['distribution'],
                    'sharing_group_id' => $b['Event']['sharing_group_id'],
                    'a_sharing_group_id' => $b['Attribute']['sharing_group_id'],
                ];
            } else {
                $correlations[] = [
                    $value,
                    $a['Event']['id'],
                    $a['Attribute']['id'],
                    $b['Attribute']['event_id'],
                    $b['Attribute']['id'],
                    $b['Event']['org_id'],
                    $b['Event']['distribution'],
                    $b['Attribute']['distribution'],
                    $b['Event']['sharing_group_id'],
                    $b['Attribute']['sharing_group_id'],
                ];
            }
        }
        return $correlations;
    }

    public function correlateValue($value, $jobId = false)
    {
        $correlatingAttributes = $this->__getMatchingAttributes($value);
        $count = count($correlatingAttributes);
        $correlations = [];
        if ($jobId) {
            if (empty($this->Job)) {
                $this->Job = ClassRegistry::init('Job');
            }
            $job = $this->Job->find('first', [
                'recursive' => -1,
                'conditions' => ['id' => $jobId]
            ]);
            if (empty($job)) {
                $jobId = false;
            }
        }
        foreach ($correlatingAttributes as $k => $correlatingAttribute) {
            foreach ($correlatingAttributes as $correlatingAttribute2) {
                $correlations = $this->__addCorrelationEntry($value, $correlatingAttribute, $correlatingAttribute2, $correlations);
            }
            $extraCorrelations = $this->__addAdvancedCorrelations($correlatingAttribute);
            if (!empty($extraCorrelations)) {
                foreach ($extraCorrelations as $extraCorrelation) {
                    $correlations = $this->__addCorrelationEntry($value, $correlatingAttribute, $extraCorrelation, $correlations);
                    //$correlations = $this->__addCorrelationEntry($value, $extraCorrelation, $correlatingAttribute, $correlations);
                }
            }
            if ($jobId && $k % 100 === 0) {
                $this->Job->saveProgress($jobId, __('Correlating Attributes based on value. %s attributes correlated out of %s.', $k, $count), floor(100 * $k / $count));
            }
        }
        return $this->__saveCorrelations($correlations);
    }

    private function __saveCorrelations($correlations)
    {
        if (empty($correlations)) {
            return true;
        }
        $fields = [
            'value', '1_event_id', '1_attribute_id', 'event_id', 'attribute_id', 'org_id',
            'distribution', 'a_distribution', 'sharing_group_id', 'a_sharing_group_id',
        ];

        // In older MISP instances, correlations table contains also date and info columns, that stores information
        // about correlated event title and date. But because this information can be fetched directly from Event table,
        // it is not necessary to keep them there. The problem is that these columns are marked as not null, so they must
        // be filled with value and removing these columns can take long time for big instances. So for new installation
        // these columns doesn't exists anymore and we don't need to save dummy value into them. Also feel free to remove
        // them from your instance.
        if ($this->oldSchema) {
            $fields[] = 'date';
            $fields[] = 'info';
        }

        if ($this->deadlockAvoidance) {
            if ($this->oldSchema) {
                foreach ($correlations as &$correlation) {
                    $correlation['date'] = '1000-01-01'; // Dummy value
                    $correlation['info'] = ''; // Dummy value
                }
            }
            return $this->saveMany($correlations, array(
                'atomic' => false,
                'callbacks' => false,
                'deep' => false,
                'validate' => false,
                'fieldList' => $fields
            ));
        } else {
            if ($this->oldSchema) {
                foreach ($correlations as &$correlation) {
                    $correlation[] = '1000-01-01'; // Dummy value
                    $correlation[] = ''; // Dummy value
                }
            }
            $db = $this->getDataSource();
            return $db->insertMulti('correlations', $fields, $correlations);
        }
    }

    public function beforeSaveCorrelation($attribute)
    {
        // (update-only) clean up the relation of the old value: remove the existing relations related to that attribute, we DO have a reference, the id
        // ==> DELETE FROM correlations WHERE 1_attribute_id = $a_id OR attribute_id = $a_id; */
        // first check if it's an update
        if (isset($attribute['id'])) {
            $this->deleteAll([
                'OR' => [
                    'Correlation.1_attribute_id' => $attribute['id'],
                    'Correlation.attribute_id' => $attribute['id']
                ],
            ], false);
        }
        if ($attribute['type'] === 'ssdeep') {
            $this->FuzzyCorrelateSsdeep = ClassRegistry::init('FuzzyCorrelateSsdeep');
            $this->FuzzyCorrelateSsdeep->purge(null, $attribute['id']);
        }
    }

    public function afterSaveCorrelation($a, $full = false, $event = false)
    {
        if (!empty($a['disable_correlation']) || Configure::read('MISP.completely_disable_correlation')) {
            return true;
        }
        // Don't do any correlation if the type is a non correlating type
        if (in_array($a['type'], Attribute::NON_CORRELATING_TYPES, true)) {
            return true;
        }
        if ($this->__preventExcludedCorrelations($a)) {
            return true;
        }
        if (!$event) {
            $event = $this->Attribute->Event->find('first', array(
                'recursive' => -1,
                'fields' => array('Event.distribution', 'Event.id', 'Event.org_id', 'Event.sharing_group_id', 'Event.disable_correlation'),
                'conditions' => array('id' => $a['event_id']),
                'order' => array(),
            ));
        }

        if (!empty($event['Event']['disable_correlation']) && $event['Event']['disable_correlation']) {
            return true;
        }
        // generate additional correlating attribute list based on the advanced correlations
        $extraConditions = $this->__buildAdvancedCorrelationConditions($a);
        $correlatingValues = array($a['value1']);
        if (!empty($a['value2']) && !in_array($a['type'], Attribute::PRIMARY_ONLY_CORRELATING_TYPES, true)) {
            $correlatingValues[] = $a['value2'];
        }

        $correlatingAttributes = [];
        foreach ($correlatingValues as $k => $cV) {
            $conditions = [
                'OR' => [
                    'Attribute.value1' => $cV,
                    'AND' => [
                        'Attribute.value2' => $cV,
                        'NOT' => ['Attribute.type' => Attribute::PRIMARY_ONLY_CORRELATING_TYPES]
                    ]
                ],
                'NOT' => [
                    'Attribute.event_id' => $a['event_id'],
                    'Attribute.type' => Attribute::NON_CORRELATING_TYPES,
                ],
                'Attribute.disable_correlation' => 0,
                'Event.disable_correlation' => 0,
                'Attribute.deleted' => 0
            ];
            if (!empty($extraConditions)) {
                $conditions['OR'][] = $extraConditions;
            }
            if ($full) {
                $conditions['Attribute.id > '] = $a['id'];
            }
            $correlatingAttributes[$k] = $this->Attribute->find('all', array(
                'conditions' => $conditions,
                'recursive' => -1,
                'fields' => [
                    'Attribute.event_id', 'Attribute.id', 'Attribute.distribution', 'Attribute.sharing_group_id',
                    'Attribute.value1', 'Attribute.value2'
                ],
                'contain' => ['Event.id', 'Event.org_id', 'Event.distribution', 'Event.sharing_group_id'],
                'order' => []
            ));
        }
        $correlations = array();
        foreach ($correlatingAttributes as $k => $cA) {
            foreach ($cA as $corr) {
                $correlations = $this->__addCorrelationEntry(
                    $k === 0 ? $corr['Attribute']['value1'] : $corr['Attribute']['value2'],
                    ['Attribute' => $a, 'Event' => $event['Event']],
                    $corr,
                    $correlations
                );
                $correlations = $this->__addCorrelationEntry(
                    $correlatingValues[$k],
                    $corr,
                    ['Attribute' => $a, 'Event' => $event['Event']],
                    $correlations
                );
            }
        }
        return $this->__saveCorrelations($correlations);
    }

    /**
     * @param array $a
     * @return bool True if attribute value is excluded
     */
    private function __preventExcludedCorrelations($a)
    {
        if ($this->exclusions === null) {
            try {
                $redis = $this->setupRedisWithException();
                $this->exclusions = $redis->sMembers('misp:correlation_exclusions');
            } catch (Exception $e) {
                return false;
            }
        } else if (empty($this->exclusions)) {
            return false;
        }

        $value = $a['value1'];
        if (!empty($a['value2'])) {
            $value .= '|' . $a['value2'];
        }
        foreach ($this->exclusions as $exclusion) {
            if (!empty($exclusion)) {
                $firstChar = $exclusion[0];
                $lastChar = substr($exclusion, -1);
                if ($firstChar === '%' && $lastChar === '%') {
                    $exclusion = substr($exclusion, 1, -1);
                    if (strpos($value, $exclusion) !== false) {
                        return true;
                    }
                } else if ($firstChar === '%') {
                    $exclusion = substr($exclusion, 1);
                    if (substr($value, -strlen($exclusion)) === $exclusion) {
                        return true;
                    }
                } else if ($lastChar === '%') {
                    $exclusion = substr($exclusion, 0, -1);
                    if (substr($value, 0, strlen($exclusion)) === $exclusion) {
                        return true;
                    }
                } else {
                    if ($value === $exclusion) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private function ssdeepCorrelation($a)
    {
        if (!isset($this->FuzzyCorrelateSsdeep)) {
            $this->FuzzyCorrelateSsdeep = ClassRegistry::init('FuzzyCorrelateSsdeep');
        }
        $fuzzyIds = $this->FuzzyCorrelateSsdeep->query_ssdeep_chunks($a['value1'], $a['id']);
        if (!empty($fuzzyIds)) {
            $ssdeepIds = $this->Attribute->find('list', array(
                'recursive' => -1,
                'conditions' => array(
                    'Attribute.type' => 'ssdeep',
                    'Attribute.id' => $fuzzyIds
                ),
                'fields' => array('Attribute.id', 'Attribute.value1')
            ));
            $threshold = Configure::read('MISP.ssdeep_correlation_threshold') ?: 40;
            $attributeIds = array();
            foreach ($ssdeepIds as $attributeId => $v) {
                $ssdeep_value = ssdeep_fuzzy_compare($a['value1'], $v);
                if ($ssdeep_value >= $threshold) {
                    $attributeIds[] = $attributeId;
                }
            }
            return ['Attribute.id' => $attributeIds];
        }
        return false;
    }

    private function cidrCorrelation($a)
    {
        $ipValues = array();
        $ip = $a['value1'];
        if (strpos($ip, '/') !== false) { // IP is CIDR
            list($networkIp, $mask) = explode('/', $ip);
            $ip_version = filter_var($networkIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? 4 : 6;

            $conditions = array(
                'type' => array('ip-src', 'ip-dst', 'ip-src|port', 'ip-dst|port'),
                'value1 NOT LIKE' => '%/%', // do not return CIDR, just plain IPs
                'disable_correlation' => 0,
                'deleted' => 0,
            );

            if (in_array($this->getDataSource()->config['datasource'], ['Database/Mysql', 'Database/MysqlObserver'])) {
                // Massive speed up for CIDR correlation. Instead of testing all in PHP, database can do that work much
                // faster. But these methods are just supported by MySQL.
                if ($ip_version === 4) {
                    $startIp = ip2long($networkIp) & ((-1 << (32 - $mask)));
                    $endIp = $startIp + pow(2, (32 - $mask)) - 1;
                    // Just fetch IP address that fit in CIDR range.
                    $conditions['INET_ATON(value1) BETWEEN ? AND ?'] = array($startIp, $endIp);

                    // Just fetch IPv4 address that starts with given prefix. This is fast, because value1 is indexed.
                    // This optimisation is possible just to mask bigger than 8 bites.
                    if ($mask >= 8) {
                        $ipv4Parts = explode('.', $networkIp);
                        $ipv4Parts = array_slice($ipv4Parts, 0, intval($mask / 8));
                        $prefix = implode('.', $ipv4Parts);
                        $conditions['value1 LIKE'] = $prefix . '%';
                    }
                } else {
                    $conditions[] = 'IS_IPV6(value1)';
                    // Just fetch IPv6 address that starts with given prefix. This is fast, because value1 is indexed.
                    if ($mask >= 16) {
                        $ipv6Parts = explode(':', rtrim($networkIp, ':'));
                        $ipv6Parts = array_slice($ipv6Parts, 0, intval($mask / 16));
                        $prefix = implode(':', $ipv6Parts);
                        $conditions['value1 LIKE'] = $prefix . '%';
                    }
                }
            }

            $ipList = $this->Attribute->find('column', array(
                'conditions' => $conditions,
                'fields' => ['Attribute.value1'],
                'unique' => true,
                'order' => false,
            ));
            foreach ($ipList as $ipToCheck) {
                $ipToCheckVersion = filter_var($ipToCheck, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? 4 : 6;
                if ($ipToCheckVersion === $ip_version) {
                    if ($ip_version === 4) {
                        if ($this->__ipv4InCidr($ipToCheck, $ip)) {
                            $ipValues[] = $ipToCheck;
                        }
                    } else {
                        if ($this->__ipv6InCidr($ipToCheck, $ip)) {
                            $ipValues[] = $ipToCheck;
                        }
                    }
                }
            }
        } else {
            $ip_version = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? 4 : 6;
            $cidrList = $this->Attribute->getSetCIDRList();
            foreach ($cidrList as $cidr) {
                if (strpos($cidr, '.') !== false) {
                    if ($ip_version === 4 && $this->__ipv4InCidr($ip, $cidr)) {
                        $ipValues[] = $cidr;
                    }
                } else {
                    if ($ip_version === 6 && $this->__ipv6InCidr($ip, $cidr)) {
                        $ipValues[] = $cidr;
                    }
                }
            }
        }
        $extraConditions = array();
        if (!empty($ipValues)) {
            $extraConditions = array('OR' => array(
                'Attribute.value1' => $ipValues,
                'Attribute.value2' => $ipValues
            ));
        }
        return $extraConditions;
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

    /**
     * @return int|bool
     * @throws Exception
     */
    public function generateTopCorrelationsRouter()
    {
        if (Configure::read('MISP.background_jobs')) {
            /** @var Job $job */
            $job = ClassRegistry::init('Job');
            $jobId = $job->createJob(
                'SYSTEM',
                Job::WORKER_DEFAULT,
                'generateTopCorrelations',
                '',
                'Starting generation of top correlations.'
            );

            $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::DEFAULT_QUEUE,
                BackgroundJobsTool::CMD_EVENT,
                [
                    'generateTopCorrelations',
                    $jobId
                ],
                true,
                $jobId
            );

            return $jobId;
        } else {
            return $this->generateTopCorrelations();
        }
    }

    public function generateTopCorrelations($jobId = false)
    {
        try {
            $redis = $this->setupRedisWithException();
        } catch (Exception $e) {
            throw new NotFoundException(__('No redis connection found.'));
        }
        $max_id = $this->find('first', [
            'fields' => ['MAX(id) AS max_id'],
            'recursive' => -1
        ]);
        if (empty($max_id)) {
            return false;
        }
        if ($jobId) {
            if (empty($this->Job)) {
                $this->Job = ClassRegistry::init('Job');
            }
            $job = $this->Job->find('first', [
                'recursive' => -1,
                'conditions' => ['id' => $jobId]
            ]);
            if (empty($job)) {
                $jobId = false;
            }
        }
        $max_id = $max_id[0]['max_id'];

        $redis->del(self::CACHE_NAME);
        $redis->set(self::CACHE_AGE, time());
        $chunk_size = 1000000;
        $max = ceil($max_id / $chunk_size);
        for ($i = 0; $i < $max; $i++) {
            $correlations = $this->find('column', [
                'fields' => ['value'],
                'conditions' => [
                    'id >' => $i * $chunk_size,
                    'id <=' => (($i + 1) * $chunk_size)
                ]
            ]);
            $newElements = count($correlations);
            $correlations = array_count_values($correlations);
            $pipeline = $redis->pipeline();
            foreach ($correlations as $correlation => $count) {
                $pipeline->zadd(self::CACHE_NAME, ['INCR'], $count, $correlation);
            }
            $pipeline->exec();
            if ($jobId) {
                $this->Job->saveProgress($jobId, __('Generating top correlations. Processed %s IDs.', ($i * $chunk_size) + $newElements), floor(100 * $i / $max));
                return $jobId;
            }
        }
        return true;
    }

    public function findTop(array $query)
    {
        try {
            $redis = $this->setupRedisWithException();
        } catch (Exception $e) {
            return false;
        }
        $start = $query['limit'] * ($query['page'] -1);
        $end = $query['limit'] * $query['page'];
        $list = $redis->zRevRange(self::CACHE_NAME, $start, $end, true);
        $results = [];
        foreach ($list as $value => $count) {
            $results[] = [
                'Correlation' => [
                    'value' => $value,
                    'count' => $count,
                    'excluded' => $this->__preventExcludedCorrelations(['value1' => $value]),
                ]
            ];
        }
        return $results;
    }

    public function getTopTime()
    {
        try {
            $redis = $this->setupRedisWithException();
        } catch (Exception $e) {
            return false;
        }
        return $redis->get(self::CACHE_AGE);
    }
}
