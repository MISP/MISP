<?php
App::uses('AppModel', 'Model');
App::uses('ValueFacetTool', 'Tools');

/**
 * @property MispAttribute $Attribute
 * @property Event $Event
 * @method saveCorrelations(array $correlations)
 * @method createCorrelationEntry(string $value, array $a, array $b)
 * @method runBeforeSaveCorrelation(array $attribute)
 * @method fetchRelatedEventIds(array $user, int $eventId, array $sgids, bool $excludeNonCorrelating = false)
 * @method fetchRelatedEventCount(array $user, int $eventId, array $sgids, int $limit)
 * @method fetchRelatedEventCounts(array $user, array $eventIds, array $sgids, int $limit)
 * @method getFieldRules
 * @method getContainRules($filter = null)
 * @method updateContainedCorrelations(array $data, string $type, array $options = [])
 * @method purgeCorrelations(int $evenId = null)
 * @method getTableName()
 */
class Correlation extends AppModel
{
    const CACHE_NAME = 'misp:top_correlations',
        CACHE_AGE = 'misp:top_correlations_age';

    const IP_TYPES = ['ip-src', 'ip-dst', 'ip-src|port', 'ip-dst|port'];

    // The types whose CIDR correlates with the addresses it holds
    const CIDR_TYPES = ['ip-src', 'ip-dst'];

    // Every correlation table's id is a signed BIGINT once 3.0's schema upgrade has run
    const ID_LIMIT = 9223372036854775807;

    public $belongsTo = array(
        'Attribute' => [
            'className' => 'MispAttribute',
            'foreignKey' => 'attribute_id'
        ],
        'Event' => array(
            'className' => 'Event',
            'foreignKey' => 'event_id'
        )
    );

    public $validEngines = [
        'Default' => 'default_correlations',
        'NoAcl' => 'no_acl_correlations',
        'OnDemand' => false,
        'Legacy' => 'correlations'
    ];

    public $actsAs = array(
        'Containable'
    );

    /** @var bool */
    private $advancedCorrelationEnabled;

    /** @var array|null value1 => [value id => bool], the IP lookups of the chunk being recorrelated */
    private $cidrHits = null;

    private $containCache = [];

    /** @var ValueConditionRewriter|null Holds the value ids of the chunk being recorrelated */
    private $valueRewriter = null;

    /** @var array|null The exclusions as the checks read them, built once */
    private $exclusionMatcher = null;

    /** @var OverCorrelatingValue */
    public $OverCorrelatingValue;

    /** @var CorrelationRule */
    public $CorrelationRule;

    private $engine = null;

    public $virtualTable = false;

    public function __construct($id = false, $table = null, $ds = null)
    {
        parent::__construct($id, $table, $ds);
        $correlationEngine = $this->getCorrelationModelName();
        if ($correlationEngine !== 'NoAcl' && $correlationEngine !== 'OnDemand') {
            $this->bindModel(
                [
                    'belongsTo' => [
                        'Object' => [
                            'className' => 'Object',
                            'foreignKey' => 'object_id'
                        ]
                    ]
                ]
            );
        }
        $deadlockAvoidance = Configure::read('MISP.deadlock_avoidance') ?: false;
        // load the currently used correlation engine
        $this->Behaviors->load($correlationEngine . 'Correlation', ['deadlockAvoidance' => $deadlockAvoidance]);
        // getTableName() needs to be implemented by the engine - this points us to the table to be used
        $this->useTable = $this->getTableName();
        $this->advancedCorrelationEnabled = (bool)Configure::read('MISP.enable_advanced_correlations');
        // load the overcorrelatingvalue model for chaining
        $this->OverCorrelatingValue = ClassRegistry::init('OverCorrelatingValue');
        // load the correlationRule model
        $this->CorrelationRule = ClassRegistry::init('CorrelationRule');
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

        /**
     * @return int|bool
     * @throws Exception
     */
    public function generateCorrelationRouter($eventId = null)
    {
        if (Configure::read('MISP.background_jobs')) {
            /** @var Job $job */
            $job = ClassRegistry::init('Job');
            $jobId = $job->createJob(
                'SYSTEM',
                Job::WORKER_DEFAULT,
                'generateCorrelation',
                '',
                $eventId ? __('Starting the recorrelation of event #%d.', $eventId) : 'Starting full recorrelation.'
            );

            $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::DEFAULT_QUEUE,
                BackgroundJobsTool::CMD_ADMIN,
                [
                    'jobGenerateCorrelation',
                    $jobId,
                    $eventId
                ],
                true,
                $jobId
            );

            return $jobId;
        } else {
            $this->generateCorrelation(false, $eventId);
            return true;
        }
    }

    /**
     * Generate correlation for given attributes or events.
     *
     * @param int|false $jobId
     * @param int|false $eventId
     * @param int|false $attributeId
     * @return int Number of processed attributes
     * @throws Exception
     */
    public function generateCorrelation($jobId = false, $eventId = false, $attributeId = false)
    {
        if ($this->onDemandEngine()) {
            return true;
        }
        $this->purgeCorrelations($eventId);

        $this->FuzzyCorrelateSsdeep = ClassRegistry::init('FuzzyCorrelateSsdeep');
        $this->FuzzyCorrelateSsdeep->purge($eventId, $attributeId);

        if (empty($eventId) && empty($attributeId)) {
            $this->OverCorrelatingValue->truncateTable();
        }

        if (!$eventId) {
            $eventIds = $this->Event->find('column', [
                'fields' => ['Event.id'],
                'conditions' => ['Event.disable_correlation' => 0],
            ]);
            $full = true;
            $this->virtualTable = $this->CorrelationRule->generateVirtualTable();
        } else {
            $eventIds = [$eventId];
            $full = false;
        }
        $attributeCount = 0;
        if (Configure::read('MISP.background_jobs') && $jobId) {
            $this->Job = ClassRegistry::init('Job');
            $this->Job->id = $jobId;
            if (!$this->Job->exists()) {
                $jobId = false;
            }
        } else {
            $jobId = false;
        }

        if (!empty($eventIds)) {
            $eventCount = count($eventIds);
            foreach ($eventIds as $j => $currentEventId) {
                $attributeCount += $this->iteratedCorrelation(
                    $jobId,
                    $full,
                    $attributeId,
                    $eventCount,
                    $currentEventId,
                    $j
                );
            }
        }
        if ($jobId) {
            $this->Job->saveStatus($jobId, true);
        }
        return $attributeCount;
    }

    /**
     * @param int|false $jobId
     * @param bool $full
     * @param int $attributeId
     * @param int $eventCount
     * @param int $eventId
     * @param int $j
     * @return int
     * @throws Exception
     */
    private function iteratedCorrelation(
        $jobId = false,
        $full = false,
        $attributeId = null,
        $eventCount = null,
        $eventId = null,
        $j = 0
    )
    {
        if ($jobId) {
            $message = $attributeId ? __('Correlating Attribute %s', $attributeId) : __('Correlating Event %s (%s MB used)', $eventId, intval(memory_get_usage() / 1024 / 1024));
            $this->Job->saveProgress($jobId, $message, !empty($eventCount) ? ($j / $eventCount) * 100 : 0);
        }
        $attributeConditions = [
            'Attribute.deleted' => 0,
            'Attribute.disable_correlation' => 0,
            'Attribute.type NOT IN' => MispAttribute::NON_CORRELATING_TYPES,
        ];
        if ($eventId) {
            $attributeConditions['Attribute.event_id'] = $eventId;
            $event = $this->Event->find('first', [
                'conditions' => ['Event.id' => $eventId],
                'recursive' => -1,
                'fields' => $this->getContainRules('Event')['fields'],
            ]);
            if (empty($event)) {
                return 0; // event not found, skip
            }
        } else {
            $event = false;
        }
        if ($attributeId) {
            $attributeConditions['Attribute.id'] = $attributeId;
        }

        $chunk_size = Configure::check('MISP.correlation_chunk_size') ? Configure::read('MISP.correlation_chunk_size') : 5000;
        $continue = true;
        $last_id = 0;
        $attributeCount = 0;
        while ($continue) {
            $attributes = $this->Attribute->fetchAttributesInChunksSingle($attributeConditions, $this->getFieldRules(), false, $chunk_size, $last_id, $continue);
            $attributeCount += count($attributes);
            $this->attributeValue()->attachValues($attributes, 'Attribute');
            $this->valueRewriter = $this->chunkRewriter($attributes);
            $this->cidrHits = $this->cidrProbe($attributes);
            try {
                foreach ($attributes as $attribute) {
                    $this->afterSaveCorrelation($attribute['Attribute'], $full, $event);
                }
            } finally {
                $this->valueRewriter = null;
                $this->cidrHits = null;
            }
        }
        // Generating correlations can take long time, so clear caches after each event to refresh them
        $this->OverCorrelatingValue->cleanCache();
        $this->containCache = [];

        return $attributeCount;
    }

    /**
     * A field and the joins that show a correlation's value as the other
     * attribute holds it: its value1 or value2 in the correlation's value
     * group, or the group's own text when neither is (an advanced match).
     *
     * @param string $otherAttributeField The column holding the other attribute's id
     * @return array ['field' => expression, 'joins' => array]
     */
    public function displayValueQuery($otherAttributeField)
    {
        $db = $this->getDataSource();
        $group = $db->name('GroupValue.value');
        $first = $db->name('OtherValue1.value');
        $second = $db->name('OtherValue2.value');
        $join = function ($table, $alias, $left, $right) use ($db) {
            return [
                'table' => $table,
                'alias' => $alias,
                'type' => 'LEFT',
                'conditions' => [$db->name($left) . ' = ' . $db->name($right)],
            ];
        };
        return [
            'field' => $db->expression(sprintf(
                'CASE WHEN %s THEN %s WHEN %s THEN %s ELSE %s END AS %s',
                $this->attributeValue()->ciEqualColumns($first, $group),
                $first,
                $this->attributeValue()->ciEqualColumns($second, $group),
                $second,
                $group,
                $db->name('display_value')
            )),
            'joins' => [
                $join('attribute_values', 'GroupValue', 'GroupValue.id', 'Correlation.value_id'),
                $join('attributes', 'OtherAttribute', 'OtherAttribute.id', $otherAttributeField),
                $join('attribute_values', 'OtherValue1', 'OtherValue1.id', 'OtherAttribute.value1_id'),
                $join('attribute_values', 'OtherValue2', 'OtherValue2.id', 'OtherAttribute.value2_id'),
            ],
        ];
    }

    /**
     * Conditions leaving out the correlations whose value group an exclusion
     * names exactly, or that over-correlates.
     *
     * @return array
     */
    public function excludedValueConditions()
    {
        $groups = $this->exclusionMatcher()['groups'];
        $conditions = [];
        if (!empty($groups)) {
            $conditions[] = ['Correlation.value_id NOT IN' => array_keys($groups)];
        }
        $conditions[] = $this->OverCorrelatingValue->blockedGroupsCondition('Correlation.value_id');
        return $conditions;
    }

    /**
     * Whether an exclusion matches the value: an exact one by the value's
     * group or any stored spelling of it, a wildcard one ignoring case.
     *
     * @param string|null $value
     * @param int|null $groupId The value's group, when the caller has it; a
     *   spelling stored after the exclusions were read is known only by it.
     * @return bool
     */
    public function isExcludedValue($value, $groupId = null)
    {
        $matcher = $this->exclusionMatcher();
        $value = (string)$value;
        if (isset($matcher['spellings'][$value]) || ($groupId !== null && isset($matcher['groups'][$groupId]))) {
            return true;
        }
        if (empty($matcher['contains']) && empty($matcher['endsWith']) && empty($matcher['startsWith'])) {
            return false;
        }
        $value = mb_strtolower($value);
        foreach ($matcher['contains'] as $pattern) {
            if (str_contains($value, $pattern)) {
                return true;
            }
        }
        foreach ($matcher['endsWith'] as $pattern) {
            if (str_ends_with($value, $pattern)) {
                return true;
            }
        }
        foreach ($matcher['startsWith'] as $pattern) {
            if (str_starts_with($value, $pattern)) {
                return true;
            }
        }
        return false;
    }

    /**
     * The exclusions, read once: %x% contains, %x ends with, x% starts with
     * (lower-cased), anything else exact, with its value group and every
     * stored spelling.
     *
     * @return array
     */
    private function exclusionMatcher()
    {
        if ($this->exclusionMatcher !== null) {
            return $this->exclusionMatcher;
        }
        $matcher = ['groups' => [], 'spellings' => [], 'contains' => [], 'endsWith' => [], 'startsWith' => []];
        $this->CorrelationExclusion = ClassRegistry::init('CorrelationExclusion');
        $exact = [];
        foreach ($this->CorrelationExclusion->find('column', ['fields' => ['value']]) as $exclusion) {
            $exclusion = (string)$exclusion;
            if ($exclusion === '') {
                continue;
            }
            $firstChar = $exclusion[0];
            $lastChar = substr($exclusion, -1);
            if ($firstChar === '%' && $lastChar === '%') {
                $matcher['contains'][] = mb_strtolower(substr($exclusion, 1, -1));
            } else if ($firstChar === '%') {
                $matcher['endsWith'][] = mb_strtolower(substr($exclusion, 1));
            } else if ($lastChar === '%') {
                $matcher['startsWith'][] = mb_strtolower(substr($exclusion, 0, -1));
            } else {
                $exact[] = $exclusion;
                $matcher['spellings'][$exclusion] = true;
            }
        }
        if (!empty($exact)) {
            $ids = [];
            foreach ($this->attributeValue()->resolveCi($exact) as $variants) {
                if (!empty($variants)) {
                    $matcher['groups'][min($variants)] = true;
                    array_push($ids, ...$variants);
                }
            }
            foreach ($this->attributeValue()->fetchValues($ids) as $spelling) {
                $matcher['spellings'][$spelling] = true;
            }
        }
        return $this->exclusionMatcher = $matcher;
    }

    /**
     * A condition on the correlations whose value an exclusion matches, as
     * the save-time check reads it: %x% contains, %x ends with, x% starts
     * with, anything else is the value and its case variants.
     *
     * @param string $exclusion
     * @return array|null Null when it matches nothing.
     */
    public function exclusionMatchCondition($exclusion)
    {
        $exclusion = (string)$exclusion;
        $leading = $exclusion !== '' && $exclusion[0] === '%';
        $trailing = strlen($exclusion) > 1 && substr($exclusion, -1) === '%';
        if (!$leading && !$trailing) {
            $ids = $this->attributeValue()->resolveCi([$exclusion]);
            $ids = isset($ids[$exclusion]) ? $ids[$exclusion] : [];
            return empty($ids) ? null : ['Correlation.value_id' => $ids];
        }
        $inner = substr($exclusion, $leading ? 1 : 0, strlen($exclusion) - ($leading ? 1 : 0) - ($trailing ? 1 : 0));
        if ($inner === '') {
            return null;
        }
        $pattern = ($leading ? '%' : '') . addcslashes($inner, '\\%_') . ($trailing ? '%' : '');
        return [$this->attributeValue()->likeCondition('Correlation.value_id', $pattern)];
    }

    /**
     * @return AttributeValue
     */
    private function attributeValue()
    {
        return ClassRegistry::init('AttributeValue');
    }

    /**
     * Every value of a chunk resolved in one go, for its lookups.
     *
     * @param array $attributes
     * @return ValueConditionRewriter|null
     */
    private function chunkRewriter(array $attributes)
    {
        if (empty($attributes)) {
            return null;
        }
        $values = [];
        foreach ($attributes as $attribute) {
            $values[$attribute['Attribute']['value1']] = true;
            if ($attribute['Attribute']['value2'] !== '') {
                $values[$attribute['Attribute']['value2']] = true;
            }
        }
        return $this->attributeValue()->batchRewriter('Attribute', array_map('strval', array_keys($values)));
    }

    /**
     * The facet rows holding each single address of a chunk, in one go.
     *
     * @param array $attributes
     * @return array|null value1 => [value id => bool]
     */
    private function cidrProbe(array $attributes)
    {
        if (!$this->advancedCorrelationEnabled) {
            return null;
        }
        $addresses = [];
        foreach ($attributes as $attribute) {
            if (in_array($attribute['Attribute']['type'], self::IP_TYPES, true)) {
                $range = ValueFacetTool::ipRange($attribute['Attribute']['value1']);
                if ($range !== null && $range[2] === 128) {
                    $addresses[(string)$attribute['Attribute']['value1']] = $range[0];
                }
            }
        }
        return $this->attributeValue()->facets()->containing($addresses);
    }

    /**
     * @param array $attribute Simple attribute array
     * @param int[] $ownIds The ids of value1's case variants
     * @return array|null
     */
    private function __buildAdvancedCorrelationConditions($attribute, array $ownIds = [])
    {
        if (!$this->advancedCorrelationEnabled) {
            return null;
        }

        if (in_array($attribute['Attribute']['type'], self::IP_TYPES, true)) {
            return $this->cidrCorrelation($attribute, $ownIds);
        } else if ($attribute['Attribute']['type'] === 'ssdeep' && function_exists('ssdeep_fuzzy_compare')) {
            return $this->ssdeepCorrelation($attribute);
        }
        return null;
    }

    /**
     * @param array $correlatingAttribute
     * @param int[] $ownIds The ids of value1's case variants
     * @return array
     */
    private function __addAdvancedCorrelations($correlatingAttribute, array $ownIds = [])
    {
        if (!$this->advancedCorrelationEnabled) {
            return [];
        }
        $extraConditions = $this->__buildAdvancedCorrelationConditions($correlatingAttribute, $ownIds);
        if (empty($extraConditions)) {
            return [];
        }
        return $this->Attribute->find('all', [
            'conditions' => [
                'AND' => $extraConditions,
                'NOT' => [
                    'Attribute.type' => MispAttribute::NON_CORRELATING_TYPES,
                ],
                'Attribute.disable_correlation' => 0,
                'Event.disable_correlation' => 0,
                'Attribute.deleted' => 0
            ],
            'recursive' => -1,
            'fields' => $this->getFieldRules(),
            'contain' => $this->getContainRules(),
            'order' => [],
        ]);
    }

    private function __getMatchingAttributes($value)
    {
        // stupid hack to allow statically retrieving the constants
        ClassRegistry::init('MispAttribute');
        $conditions = [
            'OR' => [
                'Attribute.value1' => $value,
                'AND' => [
                    'Attribute.value2' => $value,
                    'NOT' => ['Attribute.type' => MispAttribute::PRIMARY_ONLY_CORRELATING_TYPES]
                ]
            ],
            'NOT' => [
                'Attribute.type' => MispAttribute::NON_CORRELATING_TYPES,
            ],
            'Attribute.disable_correlation' => 0,
            'Event.disable_correlation' => 0,
            'Attribute.deleted' => 0
        ];
        $correlatingAttributes = $this->Attribute->find('all', [
            'conditions' => $conditions,
            'recursive' => -1,
            'fields' => $this->getFieldRules(),
            'contain' => $this->getContainRules(),
            'order' => [],
        ]);
        return $correlatingAttributes;
    }

    public function correlateValue($value, $jobId = false)
    {
        if ($this->onDemandEngine()) {
            return true;
        }
        $correlatingAttributes = $this->__getMatchingAttributes($value);
        $count = count($correlatingAttributes);
        $correlations = [];
        $variants = $this->attributeValue()->resolveCi([$value]);
        $variants = isset($variants[(string)$value]) ? $variants[(string)$value] : [];
        if (empty($variants)) {
            return true;
        }
        $groupId = min($variants);
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
                if ($correlatingAttribute['Attribute']['event_id'] === $correlatingAttribute2['Attribute']['event_id']) {
                    continue;
                }
                $correlations[] = $this->createCorrelationEntry($groupId, $correlatingAttribute, $correlatingAttribute2);
            }
            $extraCorrelations = $this->__addAdvancedCorrelations($correlatingAttribute, $variants);
            if (!empty($extraCorrelations)) {
                foreach ($extraCorrelations as $extraCorrelation) {
                    if ($correlatingAttribute['Attribute']['event_id'] === $extraCorrelation['Attribute']['event_id']) {
                        continue;
                    }
                    $correlations[] = $this->createCorrelationEntry($groupId, $correlatingAttribute, $extraCorrelation);
                    //$correlations = $this->createCorrelationEntry($value, $extraCorrelation, $correlatingAttribute, $correlations);
                }
            }
            if ($jobId && $k % 100 === 0) {
                $this->Job->saveProgress($jobId, __('Correlating Attributes based on value. %s attributes correlated out of %s.', $k, $count), floor(100 * $k / $count));
            }
        }
        if (empty($correlations)) {
            return true;
        }
        return $this->__saveCorrelations($correlations);
    }

    /**
     * @param array $correlations
     * @return array|bool|bool[]|mixed
     */
    private function __saveCorrelations(array $correlations)
    {
        try {
            return $this->saveCorrelations($correlations);
        } catch (Exception $e) {
            // Correlations may fail for different reasons, such as the correlation already existing. We don't care and don't want to break the process
            return true;
        }
    }

    public function beforeSaveCorrelation(array $attribute)
    {
        $this->runBeforeSaveCorrelation($attribute);
    }

    /**
     * @param string $scope
     * @param int $id
     * @return bool|array Returns array if object is found, false if object doesn't exists or true if object is not required
     */
    private function __cachedGetContainData($scope, $id)
    {
        $rules = $this->getContainRules($scope);
        if (!empty($rules)) {
            if (!isset($this->containCache[$scope][$id])) {
                $temp = $this->Attribute->$scope->find('first', array(
                    'recursive' => -1,
                    'fields' => $rules['fields'],
                    'conditions' => ['id' => $id],
                    'order' => array(),
                ));
                if (empty($temp)) {
                    return false;
                }
                return $this->containCache[$scope][$id] = $temp[$scope];
            }
            return $this->containCache[$scope][$id];
        }

        return true;
    }

    /**
     * @param array $a
     * @param bool $full
     * @param array|false $event
     * @return array|bool|bool[]|mixed
     * @throws Exception
     */
    public function afterSaveCorrelation($a, $full = false, $event = false)
    {
        if ($this->onDemandEngine()) {
            return true;
        }
        $a = ['Attribute' => $a];
        if (!empty($a['Attribute']['disable_correlation']) || Configure::read('MISP.completely_disable_correlation')) {
            return true;
        }
        // Don't do any correlation if the type is a non correlating type
        if (in_array($a['Attribute']['type'], MispAttribute::NON_CORRELATING_TYPES, true)) {
            return true;
        }
        if (!$event) {
            $a['Event'] = $this->__cachedGetContainData('Event', $a['Attribute']['event_id']);
            if (!$a['Event']) {
                // orphaned attribute, do not correlate
                return true;
            }
        } else {
            $a['Event'] = $event['Event'];
        }
        if (!empty($a['Event']['disable_correlation'])) {
            return true;
        }
        /* 
         *Removed this check for now, it assumed that correlation rules COMPLETELY blocked correlation, which is not the case.
        if (!$this->CorrelationRule->canCorrelate($a)) {
            return true;
        }
        */
        $value1 = $a['Attribute']['value1'];
        $value2 = null;
        if (!empty($a['Attribute']['value2']) && !in_array($a['Attribute']['type'], MispAttribute::PRIMARY_ONLY_CORRELATING_TYPES, true)) {
            $value2 = $a['Attribute']['value2'];
        }
        $rewriter = $this->valueRewriter ?: $this->attributeValue()->batchRewriter('Attribute', $value2 === null ? [$value1] : [$value1, $value2]);
        // generate additional correlating attribute list based on the advanced correlations
        $advanced = !$this->isExcludedValue($value1, $rewriter->groupId($value1));
        $correlatingValues = $advanced ? [$value1] : [];
        if ($value2 !== null && !$this->isExcludedValue($value2, $rewriter->groupId($value2))) {
            $correlatingValues[] = $value2;
        }
        if (empty($correlatingValues)) {
            return true;
        }
        if (!empty($a['Attribute']['object_id'])) {
            $a['Object'] = $this->__cachedGetContainData('Object', $a['Attribute']['object_id']);
            if (!$a['Object']) {
                // orphaned attribute, do not correlate
                return true;
            }
        }
        $correlations = [];
        $extraConditions = $advanced ? $this->__buildAdvancedCorrelationConditions($a, $rewriter->variantIds($a['Attribute']['value1'])) : null;
        foreach ($correlatingValues as $cV) {
            if ($cV === null) {
                continue;
            }
            if ($full && $this->OverCorrelatingValue->isBlocked($cV)) {
                continue; // skip already blocked values when doing full correlation
            }
            $conditions = [
                'Attribute.type NOT IN' => MispAttribute::NON_CORRELATING_TYPES,
                'Attribute.event_id !=' => $a['Attribute']['event_id'],
                'Attribute.disable_correlation' => 0,
                'Event.disable_correlation' => 0,
                'Attribute.deleted' => 0,
            ];
            if ($full) {
                // On a full correlation, only correlate with attributes that have a higher ID to avoid duplicate correlations
                $conditions['Attribute.id >'] = $a['Attribute']['id'];
            }
            $correlationLimit = $this->OverCorrelatingValue->getLimit();

            $conditions = $this->CorrelationRule->attachCustomCorrelationRules($a, $conditions);
            $conditions1 = $conditions2 = $conditions;

            $conditions1['Attribute.value1'] = $cV;
            $conditions2[] = [
                'AND' => [
                    'Attribute.value2' => $cV,
                    'NOT' => ['Attribute.type' => MispAttribute::PRIMARY_ONLY_CORRELATING_TYPES]
                ]
            ];
            $conditions1 = $rewriter->rewrite($conditions1);
            $conditions2 = $rewriter->rewrite($conditions2);
            $correlatingAttributes1 = $this->Attribute->find('all', [
                'conditions' => $conditions1,
                'recursive' => -1,
                'fields' => $this->getFieldRules(),
                'contain' => $this->getContainRules(),
                'order' => [],
                'callbacks' => 'before', // memory leak fix
                // let's fetch the limit +1 - still allows us to detect overcorrelations, but we'll also never need more
                'limit' => empty($correlationLimit) ? null : ($correlationLimit+1)
            ]);

            $correlatingAttributes2 = $this->Attribute->find('all', [
                'conditions' => $conditions2,
                'recursive' => -1,
                'fields' => $this->getFieldRules(),
                'contain' => $this->getContainRules(),
                'order' => [],
                'callbacks' => 'before', // memory leak fix
                // let's fetch the limit +1 - still allows us to detect overcorrelations, but we'll also never need more
                'limit' => empty($correlationLimit) ? null : ($correlationLimit+1)
            ]);
            if (!empty($extraConditions)) {
                $correlatingAttributes3 = $this->Attribute->find('all', [
                    'conditions' => [$conditions, $extraConditions],
                    'recursive' => -1,
                    'fields' => $this->getFieldRules(),
                    'contain' => $this->getContainRules(),
                    'order' => [],
                    'callbacks' => 'before', // memory leak fix
                    // let's fetch the limit +1 - still allows us to detect overcorrelations, but we'll also never need more
                    'limit' => empty($correlationLimit) ? null : ($correlationLimit+1)
                ]);
            } else {
                $correlatingAttributes3 = [];
            }

            // Let's check if we don't have a case of an over-correlating attribute
            $count = count($correlatingAttributes1) + count($correlatingAttributes2) + count($correlatingAttributes3);
            if ($count > $correlationLimit) {
                // If we have more correlations for the value than the limit, set the block entry and stop the correlation process
                $this->OverCorrelatingValue->block($cV);
                return true;
            } else if ($count !== 0 && !$full && !isset($a['Attribute']['skip_overcorrelation_unblock'])) {
                // If we have fewer hits than the limit, proceed with the correlation, but first make sure we remove any existing blockers
                // Added the skip_correlation flag as a reason to skip over this, we're receiving an event that in itself contains more than the limit in correlations. Let's not unblock any values in this case.
                $this->OverCorrelatingValue->unblock($cV);
            }
            // A correlation is keyed by its value's group; an advanced match by the target's own value
            $groupId = $rewriter->groupId($cV);
            $advancedGroupIds = empty($correlatingAttributes3) ? [] : $this->attributeValue()->groupIds(
                array_column(array_column($correlatingAttributes3, 'Attribute'), 'value1_id')
            );
            foreach ([$correlatingAttributes1, $correlatingAttributes2, $correlatingAttributes3] as $set => $correlatingAttributes) {
                foreach ($correlatingAttributes as $b) {
                    $valueId = $set === 2 ? ($advancedGroupIds[(int)$b['Attribute']['value1_id']] ?? null) : $groupId;
                    if ($valueId === null) {
                        continue;
                    }
                    if ($a['Attribute']['id'] > $b['Attribute']['id']) {
                        $correlations[] = $this->createCorrelationEntry($valueId, $a, $b);
                    } else {
                        $correlations[] = $this->createCorrelationEntry($valueId, $b, $a);
                    }
                }
            }
            unset($correlatingAttributes1, $correlatingAttributes2, $correlatingAttributes3, $correlatingAttributes);
        }
        if (empty($correlations)) {
            return true;
        }
        return $this->__saveCorrelations($correlations);
    }

    /**
     * @param array $attribute Simple attribute array
     * @return array[]|false
     */
    private function ssdeepCorrelation($attribute)
    {
        if (!isset($this->FuzzyCorrelateSsdeep)) {
            $this->FuzzyCorrelateSsdeep = ClassRegistry::init('FuzzyCorrelateSsdeep');
        }
        $value = $attribute['Attribute']['value1'];
        $fuzzyIds = $this->FuzzyCorrelateSsdeep->query_ssdeep_chunks($value, $attribute['Attribute']['id']);
        if (!empty($fuzzyIds)) {
            $ssdeepIds = $this->Attribute->find('list', array(
                'recursive' => -1,
                'conditions' => array(
                    'Attribute.type' => 'ssdeep',
                    'Attribute.id' => $fuzzyIds
                ),
                'fields' => array('Attribute.id', 'Attribute.value')
            ));
            $threshold = Configure::read('MISP.ssdeep_correlation_threshold') ?: 40;
            $attributeIds = [];
            foreach ($ssdeepIds as $attributeId => $v) {
                $ssdeepValue = ssdeep_fuzzy_compare($value, $v);
                if ($ssdeepValue >= $threshold) {
                    $attributeIds[] = $attributeId;
                }
            }
            return ['Attribute.id' => $attributeIds];
        }
        return false;
    }

    /**
     * Conditions on the attributes an IP attribute correlates with by
     * address: an address with the CIDRs holding it and with its other
     * spellings (/32, v4-mapped, ...), a CIDR with the addresses it holds.
     * Two CIDRs never correlate.
     *
     * @param array $attribute Simple attribute array
     * @param int[] $ownIds The ids of value1's case variants, which correlate exactly
     * @return array|null
     */
    private function cidrCorrelation(array $attribute, array $ownIds)
    {
        $value = (string)$attribute['Attribute']['value1'];
        $range = ValueFacetTool::ipRange($value);
        if ($range === null) {
            return null;
        }
        $facets = $this->attributeValue()->facets();
        if ($range[2] < 128) {
            if (!in_array($attribute['Attribute']['type'], self::CIDR_TYPES, true)) {
                return null;
            }
            return [
                'Attribute.type' => self::IP_TYPES,
                sprintf('%s IN (%s)', $this->getDataSource()->name('Attribute.value1_id'), $facets->membersQuery($range)),
            ];
        }
        $hits = isset($this->cidrHits[$value]) ? $this->cidrHits[$value] : $facets->containing([$value => $range[0]])[$value];
        $own = array_flip($ownIds);
        $cidrs = $addresses = [];
        foreach ($hits as $id => $isCidr) {
            if (isset($own[$id])) {
                continue;
            }
            if ($isCidr) {
                $cidrs[] = $id;
            } else {
                $addresses[] = $id;
            }
        }
        $matches = [];
        if (!empty($cidrs)) {
            $matches[] = ['Attribute.value1_id' => $cidrs, 'Attribute.type' => self::CIDR_TYPES];
        }
        if (!empty($addresses)) {
            $matches[] = ['Attribute.value1_id' => $addresses, 'Attribute.type' => self::IP_TYPES];
        }
        return empty($matches) ? null : ['OR' => $matches];
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
        if ($this->onDemandEngine()) {
            $this->generateTopOnDemand();
            return true;
        }
        try {
            $redis = RedisTool::init();
        } catch (Exception $e) {
            throw new NotFoundException(__('No redis connection found.'));
        }
        $maxId = $this->find('first', [
            'fields' => ['MAX(id) AS max_id'],
            'recursive' => -1,
        ]);
        if (empty($maxId)) {
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
        $maxId = $maxId[0]['max_id'];

        RedisTool::unlink($redis, self::CACHE_NAME);
        $redis->set(self::CACHE_AGE, time());
        $chunkSize = 1000000;
        $maxPage = ceil($maxId / $chunkSize);
        for ($page = 0; $page < $maxPage; $page++) {
            $correlations = $this->find('column', [
                'fields' => ['value_id'],
                'conditions' => [
                    'id >' => $page * $chunkSize,
                    'id <=' => ($page + 1) * $chunkSize
                ],
                'callbacks' => false, // when callbacks are enabled, memory is leaked
            ]);
            $newElements = count($correlations);
            $correlations = array_count_values($correlations);
            $pipeline = $redis->pipeline();
            foreach ($correlations as $correlation => $count) {
                $pipeline->zIncrBy(self::CACHE_NAME, $count, $correlation);
            }
            $pipeline->exec();
            if ($jobId) {
                $this->Job->saveProgress($jobId, __('Generating top correlations. Processed %s IDs.', ($page * $chunkSize) + $newElements), floor(100 * $page / $maxPage));
            }
        }
        return true;
    }

    /**
     * Count how often each value occurs, value1 and value2 apart, into
     * attr_value_counts: one row per value, its case variants counted together
     * under the lowest of their ids.
     */
    public function generateTopOnDemand()
    {
        $this->query('TRUNCATE TABLE attr_value_counts');
        $this->query(
            "INSERT INTO attr_value_counts (value_id, cnt_v1, cnt_v2)
            SELECT MIN(v.id), SUM(x.cnt_v1), SUM(x.cnt_v2)
            FROM (
                SELECT a.value1_id AS value_id, COUNT(*) AS cnt_v1, 0 AS cnt_v2
                FROM attributes a
                WHERE a.deleted = 0 AND a.disable_correlation = 0
                GROUP BY a.value1_id
                UNION ALL
                SELECT a.value2_id AS value_id, 0 AS cnt_v1, COUNT(*) AS cnt_v2
                FROM attributes a
                WHERE a.deleted = 0 AND a.disable_correlation = 0 AND a.value2_id IS NOT NULL
                GROUP BY a.value2_id
            ) AS x
            JOIN attribute_values AS v ON v.id = x.value_id
            WHERE v.value <> ''
            GROUP BY v.value"
        );
    }

    private function findTopOnDemand(array $query)
    {
        $limit  = (int)($query['limit'] ?? 100);
        $page   = max(1, (int)($query['page'] ?? 1));
        $offset = $limit * ($page - 1);

        $sql = "
            SELECT value_id, (cnt_v1 + cnt_v2) AS cnt
            FROM attr_value_counts
            WHERE (cnt_v1 + cnt_v2) > 0
            ORDER BY cnt DESC
            LIMIT " . intval($limit) . " OFFSET " . intval($offset);

        $rows = [];
        foreach ($this->query($sql) as $row) {
            // The columns land under the table name, or under 0
            $rows[] = array_merge(...array_values($row));
        }
        $values = ClassRegistry::init('AttributeValue')->fetchValues(array_column($rows, 'value_id'));

        $results = [];
        foreach ($rows as $row) {
            $v   = $values[(int)$row['value_id']] ?? '';
            $cnt = (int)$row['cnt'];

            $results[] = [
                'Correlation' => [
                    'value'    => (string)$v,
                    'count'    => $cnt,
                    'excluded' => $this->isExcludedValue((string)$v, (int)$row['value_id']),
                ]
            ];
        }
        return $results;
    }
    
    /**
     * @param array $query
     * @return array|false
     * @throws RedisException
     */
    public function findTop(array $query)
    {
        if ($this->onDemandEngine()) {
            return $this->findTopOnDemand($query);
        }
        try {
            $redis = RedisTool::init();
        } catch (Exception $e) {
            return false;
        }

        $start = $query['limit'] * ($query['page'] -1);
        $end = $query['limit'] * $query['page'] - 1;
        $list = $redis->zRevRange(self::CACHE_NAME, $start, $end, true);
        $results = [];

        $realValues = $this->attributeValue()->fetchValues(array_keys($list));

        foreach ($list as $valueId => $count) {
            $value = $realValues[$valueId] ?? null;
            $results[] = [
                'Correlation' => [
                    'value' => $value,
                    'count' => $count,
                    'excluded' => $this->isExcludedValue($value, (int)$valueId),
                ]
            ];
        }
        return $results;
    }

    public function getTopTime()
    {
        if ($this->onDemandEngine()) {
            return true;
        }
        try {
            $redis = RedisTool::init();
        } catch (Exception $e) {
            return false;
        }
        return $redis->get(self::CACHE_AGE);
    }

    /**
     * @param array $user User array
     * @param int $eventIds List of event IDs
     * @param array $sgids List of sharing group IDs
     * @return array
     */
    public function getAttributesRelatedToEvent(array $user, $eventIds, array $sgids)
    {
        return $this->runGetAttributesRelatedToEvent($user, $eventIds, $sgids);
    }


    /**
     * @param array $user User array
     * @param array $attribute Attribute Array
     * @param array $fields List of fields to include
     * @param bool $includeEventData Flag to include the event data in the response
     * @param bool $valueText False to leave the value ids in the related
     *   attributes, for the caller to fill in (AttributeValue::attachNested)
     * @return array
     */
    public function getRelatedAttributes($user, $sgids, $attribute, $fields=[], $includeEventData = false, $valueText = true)
    {
        if (in_array($attribute['type'], MispAttribute::NON_CORRELATING_TYPES, true)) {
            return [];
        }
        return $this->runGetRelatedAttributes($user, $sgids, $attribute, $fields, $includeEventData, $valueText);
    }

    /**
     * @param array $user User array
     * @param int $eventId Event ID
     * @param array $sgids List of sharing group IDs
     * @param bool $excludeNonCorrelating Drop the correlations that are never
     *      rendered anywhere - those whose value sits in correlation_exclusions
     *      or in over_correlating_values. getAttributesRelatedToEvent() always
     *      drops them, so a caller that shows both a list of related events and
     *      their correlations has to ask for the same set here, or it announces
     *      a relation it then has nothing to show for.
     * @return array
     */
    public function getRelatedEventIds(array $user, int $eventId, array $sgids, bool $excludeNonCorrelating = false)
    {
        $relatedEventIds = $this->fetchRelatedEventIds($user, $eventId, $sgids, $excludeNonCorrelating);
        if (empty($relatedEventIds)) {
            return [];
        }
        return $relatedEventIds;
    }

    /**
     * Count the events getRelatedEventIds($user, $eventId, $sgids, true)
     * returns, reading at most $limit correlations each way.
     *
     * @param array $user
     * @param int $eventId
     * @param array $sgids
     * @param int $limit
     * @return array [int $count, bool $more] $more when correlations were left unread
     */
    public function countRelatedEvents(array $user, int $eventId, array $sgids, int $limit)
    {
        return $this->fetchRelatedEventCount($user, $eventId, $sgids, $limit);
    }

    /**
     * countRelatedEvents() for several events, batched where the engine
     * supports it.
     *
     * @param array $user
     * @param int[] $eventIds
     * @param array $sgids
     * @param int $limit
     * @return array event id => [int $count, bool $more]
     */
    public function countRelatedEventsFor(array $user, array $eventIds, array $sgids, int $limit)
    {
        if ($this->Behaviors->hasMethod('fetchRelatedEventCounts')) {
            return $this->fetchRelatedEventCounts($user, $eventIds, $sgids, $limit);
        }
        $counts = [];
        foreach ($eventIds as $eventId) {
            $counts[(int)$eventId] = $this->fetchRelatedEventCount($user, (int)$eventId, $sgids, $limit);
        }
        return $counts;
    }

    /**
     * Fetch correlations scoped to a specific set of
     * attribute IDs. Returns correlated attributes from
     * other events, grouped by the source attribute ID.
     *
     * @param array $user
     * @param int $eventId
     * @param array $sgids Authorised sharing group IDs
     * @param array $attributeIds Attribute IDs to scope
     * @return array Keyed by source attribute ID
     */
    public function getAttributeCorrelations(
        array $user,
        $eventId,
        array $sgids,
        array $attributeIds
    ) {
        return $this->runGetAttributeCorrelations(
            $user, $eventId, $sgids, $attributeIds
        );
    }

    /**
     * Whether this value matches an entry in `correlation_exclusions`, by the
     * rule isExcludedValue() owns.
     *
     * @param string $value
     * @return bool
     */
    public function isValueExcluded($value)
    {
        return $this->isExcludedValue((string)$value);
    }

    public function attachExclusionsToOverCorrelations($data)
    {
        foreach ($data as $k => $v) {
            $data[$k]['OverCorrelatingValue']['excluded'] = $this->isExcludedValue($data[$k]['OverCorrelatingValue']['value']);
        }
        return $data;
    }

    /**
     * @param array $attributes
     * @return array
     */
    public function attachCorrelationExclusion(array $attributes)
    {
        $compositeTypes = $this->Attribute->getCompositeTypes();
        foreach ($attributes as &$attribute) {
            if ($attribute['disable_correlation'] || in_array($attribute['type'],MispAttribute::NON_CORRELATING_TYPES, true)) {
                continue;
            }
            $primaryOnly = in_array($attribute['type'], MispAttribute::PRIMARY_ONLY_CORRELATING_TYPES, true);
            if (in_array($attribute['type'], $compositeTypes, true)) {
                $values = explode('|', $attribute['value']);
            } else {
                $values = [$attribute['value']];
            }

            if ($this->isExcludedValue($values[0])) {
                $attribute['correlation_exclusion'] = true;
            } elseif (!empty($values[1]) && !$primaryOnly && $this->isExcludedValue($values[1])) {
                $attribute['correlation_exclusion'] = true;
            }

            if ($this->OverCorrelatingValue->isBlocked($values[0])) {
                $attribute['over_correlation'] = true;
            } elseif (!empty($values[1]) && !$primaryOnly && $this->OverCorrelatingValue->isBlocked($values[1])) {
                $attribute['over_correlation'] = true;
            }
        }

        return $attributes;
    }

    public function collectMetrics()
    {
        $results = [
            'engine' => $this->getCorrelationModelName(),
            'db' => [
                'Default' => [
                    'name' => __('Default correlation engine'),
                    'tables' => [
                        'default_correlations' => [
                            'id_limit' => self::ID_LIMIT
                        ]
                    ]
                ],
                'NoAcl' => [
                    'name' => __('No ACL correlation engine'),
                    'tables' => [
                        'no_acl_correlations' => [
                            'id_limit' => self::ID_LIMIT
                        ]
                    ]
                ],
                'OnDemand' => [
                    'name' => __('On Demand correlation engine'),
                    'tables' => [
                    ]
                ],
                'Legacy' => [
                    'name' => __('Legacy correlation engine (< 2.4.160)'),
                    'tables' => [
                        'correlations' => [
                            'id_limit' => self::ID_LIMIT
                        ]
                    ]
                ]
            ],
            'over_correlations' => $this->OverCorrelatingValue->find('count'),
        ];
        $this->CorrelationExclusion = ClassRegistry::init('CorrelationExclusion');
        $results['excluded_correlations'] = $this->CorrelationExclusion->find('count');
        // One catalog read for every table; a table that is not there (the
        // legacy one, on most instances) simply has no entry and gets no
        // metrics, which is what the SHOW TABLE STATUS guard used to do.
        $sizes = $this->getSchemaInspector()->tableSizes();
        foreach ($results['db'] as &$result) {
            foreach ($result['tables'] as $table_name => &$table_data) {
                if (!isset($sizes[$table_name])) {
                    continue;
                }
                $last_id = $this->query(sprintf('select max(id) as max_id from %s;', $table_name));
                $table_data['size_on_disk'] = $sizes[$table_name]['total_in_bytes'];
                $table_data['row_count'] = $sizes[$table_name]['row_estimate'];
                $table_data['last_id'] = $last_id[0][0]['max_id'];
                $table_data['id_saturation'] = round(100 * $table_data['last_id'] / $table_data['id_limit'], 2);
            }
        }
        return $results;
    }

    public function truncate(array $user, string $engine)
    {
        if ($this->onDemandEngine()) {
            return true;
        }
        $table = $this->validEngines[$engine];
        $result = $this->query('truncate table ' . $table);
        if ($result !== true) {
            $this->loadLog()->createLogEntry(
                $user,
                'truncate',
                'Correlation',
                0,
                'Could not truncate table ' . $table,
                'Errors: ' . json_encode($result)
            );
        }
        return $result === true;
    }

    /**
     * @return string
     */
    public function getCorrelationModelName()
    {
        if (!isset($this->engine)) {
            $this->engine = Configure::read('MISP.correlation_engine') ?: 'Default';
        }
        return $this->engine;
    }

    public function getRuleImpact($id)
    {
        $rule = $this->CorrelationRule->find('first', [
            'recursive' => -1,
            'conditions' => ['CorrelationRule.id' => $id]
        ]);
        if (empty($rule)) {
            throw new NotFoundException(__('Invalid Correlation Rule'));
        }
        $eventIds = $this->CorrelationRule->getEventIdsForRule($rule);
        return count($eventIds);
    }

    public function executeRule($id)
    {
        if ($this->onDemandEngine()) {
            throw new MethodNotAllowedException(__('You\'re using an on demand correlation engine, no need to execute rules on existing data, it will be adhered to live when fetching data.'));
        }
        $rule = $this->CorrelationRule->find('first', [
            'conditions' => ['CorrelationRule.id' => $id],
            'recursive' => -1
        ]);
        if (empty($rule)) {
            throw new NotFoundException(__('Invalid Correlation Rule'));
        }
        $eventIds = $this->CorrelationRule->getEventIdsForRule($rule);
        if (!empty($eventIds) && is_array($eventIds)) {
            // A correlation rule only suppresses correlations where BOTH ends are in
            // the rule's event set (see CorrelationRule::checkEventIds), so delete only
            // those. (Was previously an OR of two identical, order-swapped AND clauses.)
            if (!$this->deleteAll([
                'AND' => [
                    'Correlation.event_id IN' => $eventIds,
                    'Correlation.1_event_id IN' => $eventIds,
                ]
                ], false, false)) {
                throw new InternalErrorException(__('Could not delete correlations for rule %s', $id));
            }
        }
        return true;
    }
}
