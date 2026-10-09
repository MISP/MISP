<?php
App::uses('AppModel', 'Model');

class OverCorrelatingValue extends AppModel
{
    public $recursive = -1;

    /** @var array|null Every spelling of every blocked value => true, loaded on first use */
    private $blockedValues = null;

    /**
     * The text key 2.x matched on, still written until the engines compare
     * value ids.
     *
     * @param string|null $value
     * @return string
     */
    public static function truncate(?string $value): string
    {
        if ($value === null) {
            return '';
        }
        $value = mb_strtolower($value);
        return mb_substr($value, 0, 191);
    }

    /**
     * Whether the value, or a variant the dictionary collation holds equal
     * to it, is blocked.
     *
     * @param string $value
     * @return bool
     */
    public function isBlocked($value)
    {
        if ($this->blockedValues === null) {
            $this->blockedValues = [];
            $rows = $this->find('all', [
                'fields' => ['Spelling.value'],
                'joins' => [
                    $this->blockedValueJoin('INNER'),
                    [
                        'table' => 'attribute_values',
                        'alias' => 'Spelling',
                        'type' => 'INNER',
                        'conditions' => ['Spelling.value = BlockedValue.value'],
                    ],
                ],
            ]);
            foreach ($rows as $row) {
                $this->blockedValues[$row['Spelling']['value']] = true;
            }
        }
        return isset($this->blockedValues[(string)$value]);
    }

    /**
     * @param string $type
     * @return array
     */
    private function blockedValueJoin($type)
    {
        return [
            'table' => 'attribute_values',
            'alias' => 'BlockedValue',
            'type' => $type,
            'conditions' => ['BlockedValue.id = OverCorrelatingValue.value_id'],
        ];
    }

    /**
     * @param string $value
     * @return void
     * @throws Exception
     */
    public function block($value)
    {
        if ($this->isBlocked($value)) {
            return;
        }
        $valueId = ClassRegistry::init('AttributeValue')->intern((string)$value);
        $this->create();
        try {
            $this->save([
                'value' => self::truncate($value),
                'value_id' => $valueId,
                'occurrence' => 0
            ]);
        } catch (Exception $e) {
            //most likely the text key already holds a variant of it, there's no reason to break the process for this
        }
        // Its variants are blocked with it
        $this->blockedValues = null;
    }

    /**
     * @param string $value
     * @return void
     */
    public function unblock($value)
    {
        $ids = $this->find('column', [
            'fields' => ['OverCorrelatingValue.id'],
            'joins' => [$this->blockedValueJoin('INNER')],
            'conditions' => ['BlockedValue.value' => (string)$value],
        ]);
        if (!empty($ids)) {
            $this->deleteAll(['OverCorrelatingValue.id' => $ids], false);
            $this->blockedValues = null;
        }
    }

    public function cleanCache()
    {
        $this->blockedValues = null;
    }

    /**
     * @return int
     */
    public function getLimit()
    {
        return Configure::read('MISP.correlation_limit') ?: 20;
    }

    /**
     * The blocked values as stored. A row the dictionary does not hold yet
     * shows its text key.
     *
     * @param array $query
     * @return array
     */
    public function getOverCorrelations($query)
    {
        $query['fields'] = [
            'OverCorrelatingValue.id',
            'OverCorrelatingValue.value',
            'OverCorrelatingValue.occurrence',
            'BlockedValue.value',
        ];
        $query['joins'][] = $this->blockedValueJoin('LEFT');
        $data = $this->find('all', $query);
        $limit = $this->getLimit();
        foreach ($data as $k => $v) {
            if (isset($v['BlockedValue']['value'])) {
                $data[$k]['OverCorrelatingValue']['value'] = $v['BlockedValue']['value'];
            }
            unset($data[$k]['BlockedValue']);
            if ($v['OverCorrelatingValue']['occurrence'] >= $limit) {
                $data[$k]['OverCorrelatingValue']['over_correlation'] = true;
            } else {
                $data[$k]['OverCorrelatingValue']['over_correlation'] = false;
            }
        }
        return $data;
    }

    /**
     * Points the rows without a value id at the dictionary entry of their
     * text key: the lowest id among the values the dictionary collation holds
     * equal to it. A key whose entry another row already holds keeps no id.
     *
     * @return int The rows remapped.
     */
    public function remapValueIds()
    {
        $rows = $this->find('list', [
            'fields' => ['OverCorrelatingValue.id', 'OverCorrelatingValue.value'],
            'conditions' => ['OverCorrelatingValue.value_id' => null],
            'order' => ['OverCorrelatingValue.id' => 'ASC'],
        ]);
        if (empty($rows)) {
            return 0;
        }
        $resolved = ClassRegistry::init('AttributeValue')->resolveCi(array_values($rows));
        $taken = array_flip($this->find('column', [
            'fields' => ['OverCorrelatingValue.value_id'],
            'conditions' => ['OverCorrelatingValue.value_id !=' => null],
        ]));
        $remapped = 0;
        foreach ($rows as $id => $value) {
            $ids = isset($resolved[(string)$value]) ? $resolved[(string)$value] : [];
            if (empty($ids) || isset($taken[min($ids)])) {
                continue;
            }
            $this->updateAll(
                ['OverCorrelatingValue.value_id' => min($ids)],
                ['OverCorrelatingValue.id' => $id]
            );
            $taken[min($ids)] = true;
            $remapped++;
        }
        $this->blockedValues = null;
        return $remapped;
    }

    public function generateOccurrencesRouter()
    {
        if (Configure::read('MISP.background_jobs')) {
            /** @var Job $job */
            $job = ClassRegistry::init('Job');
            $jobId = $job->createJob(
                'SYSTEM',
                Job::WORKER_DEFAULT,
                'generateOccurrences',
                '',
                'Starting populating the occurrences field for the over correlating values.'
            );

            $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::DEFAULT_QUEUE,
                BackgroundJobsTool::CMD_ADMIN,
                [
                    'jobGenerateOccurrences',
                    $jobId
                ],
                true,
                $jobId
            );
        } else {
            $this->generateOccurrences();
        }
    }

    /**
     * Counts the attributes that correlate on each blocked value, its case
     * variants included, as the correlation limit counts them.
     *
     * @return void
     */
    public function generateOccurrences()
    {
        $overCorrelations = $this->find('all', [
            'fields' => ['OverCorrelatingValue.id', 'OverCorrelatingValue.value_id'],
            'conditions' => ['OverCorrelatingValue.value_id !=' => null],
        ]);
        if (empty($overCorrelations)) {
            return;
        }
        $AttributeValue = ClassRegistry::init('AttributeValue');
        $values = $AttributeValue->fetchValues(array_column(array_column($overCorrelations, 'OverCorrelatingValue'), 'value_id'));
        $rewriter = $AttributeValue->batchRewriter('Attribute', array_values($values));
        $this->Attribute = ClassRegistry::init('MispAttribute');
        $counts = [];
        foreach ($overCorrelations as $overCorrelation) {
            $valueId = (int)$overCorrelation['OverCorrelatingValue']['value_id'];
            if (!isset($values[$valueId])) {
                continue;
            }
            $count = $this->Attribute->find('count', [
                'recursive' => -1,
                'conditions' => $rewriter->rewrite([
                    'OR' => [
                        'Attribute.value1' => $values[$valueId],
                        'AND' => [
                            'Attribute.value2' => $values[$valueId],
                            'NOT' => ['Attribute.type' => MispAttribute::PRIMARY_ONLY_CORRELATING_TYPES]
                        ],
                    ],
                    'NOT' => ['Attribute.type' => MispAttribute::NON_CORRELATING_TYPES],
                    'Attribute.disable_correlation' => 0,
                    'Event.disable_correlation' => 0,
                    'Attribute.deleted' => 0,
                ]),
                'contain' => ['Event'],
            ]);
            $counts[] = ['OverCorrelatingValue' => [
                'id' => $overCorrelation['OverCorrelatingValue']['id'],
                'occurrence' => $count,
            ]];
        }
        $this->saveMany($counts);
    }

    public function truncateTable()
    {
        $this->query('TRUNCATE TABLE over_correlating_values');
        $this->cleanCache();
    }
}
