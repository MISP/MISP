<?php
App::uses('AppModel', 'Model');

class OverCorrelatingValue extends AppModel
{
    public $recursive = -1;

    /** @var array */
    private $blockedValues = [];

    public static function truncate(?string $value): string
    {
        if ($value === null) {
            return '';
        }
        $value = mb_strtolower($value);
        return mb_substr($value, 0, 191);
    }
    public static function truncateValues(array $values): array
    {
        return array_map(function(string $value) {
            return self::truncate($value);
        }, $values);
    }

    /**
     * @param string $value
     * @return bool
     */
    public function isBlocked($value)
    {
        $value = self::truncate($value);
        if (isset($this->blockedValues[$value])) {
            return $this->blockedValues[$value];
        }

        $isBlocked = $this->hasAny(['value' => $value]);
        return $this->blockedValues[$value] = $isBlocked;
    }

    /**
     * @param string $value
     * @return void
     * @throws Exception
     */
    public function block($value)
    {
        if (!$this->isBlocked($value)) {
            $value = self::truncate($value);
            $this->create();
            try {
                $this->save([
                    'value' => mb_strtolower($value),
                    'occurrence' => 0
                ]);
                $this->blockedValues[$value] = true;
            } catch (Exception $e) {
                //most likely we ran into an issue with capitalisation, there's no reason to break the process for this
            }
        }
    }

    /**
     * @param string $value
     * @return void
     */
    public function unblock($value)
    {
        $value = self::truncate($value);
        $this->deleteAll([
            'OverCorrelatingValue.value' => $value,
        ], false);
        $this->blockedValues[$value] = false;
    }

    public function cleanCache()
    {
        $this->blockedValues = [];
    }

    /**
     * @return int
     */
    public function getLimit()
    {
        return Configure::read('MISP.correlation_limit') ?: 20;
    }

    public function getOverCorrelations($query)
    {
        $data = $this->find('all', $query);
        $limit = $this->getLimit();
        foreach ($data as $k => $v) {
            if ($v['OverCorrelatingValue']['occurrence'] >= $limit) {
                $data[$k]['OverCorrelatingValue']['over_correlation'] = true;
            } else {
                $data[$k]['OverCorrelatingValue']['over_correlation'] = false;
            }
        }
        return $data;
    }

    public function findOverCorrelatingValues(array $valuesToCheck): array
    {
        $valuesToCheck = array_unique(self::truncateValues($valuesToCheck), SORT_REGULAR);
        return $this->find('column', [
            'conditions' => ['value' => $valuesToCheck],
            'fields' => ['value'],
        ]);
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

    public function generateOccurrences()
    {
        $overCorrelations = $this->find('all', [
            'recursive' => -1
        ]);
        $this->Attribute = ClassRegistry::init('MispAttribute');
        foreach (array_chunk($overCorrelations, 100, true) as $chunk) {
            foreach ($this->__countOccurrences($chunk) as $k => $occurrence) {
                $overCorrelations[$k]['OverCorrelatingValue']['occurrence'] = $occurrence;
            }
        }
        $this->saveMany($overCorrelations);
    }

    /**
     * Count the attributes matching each of the given over correlating values in a single query.
     *
     * Values are stored truncated, so they are matched as a prefix of the attribute values and the
     * conditions of two values can overlap, which rules out collapsing them into a GROUP BY. Summing
     * one match expression per value over a single pass however counts exactly what one count query
     * per value counted.
     *
     * @param array $overCorrelations
     * @return array Occurrence count, keyed like the given over correlating values
     */
    private function __countOccurrences(array $overCorrelations)
    {
        $db = $this->Attribute->getDataSource();
        $primaryOnlyTypes = [];
        foreach (MispAttribute::PRIMARY_ONLY_CORRELATING_TYPES as $type) {
            $primaryOnlyTypes[] = $db->value($type, 'string');
        }
        $nonCorrelatingTypes = [];
        foreach (MispAttribute::NON_CORRELATING_TYPES as $type) {
            $nonCorrelatingTypes[] = $db->value($type, 'string');
        }
        $matches = $fields = [];
        foreach ($overCorrelations as $k => $overCorrelation) {
            $value = $db->value($overCorrelation['OverCorrelatingValue']['value'] . '%', 'string');
            $match = sprintf(
                'Attribute.value1 LIKE %s OR (Attribute.value2 LIKE %s AND Attribute.type NOT IN (%s))',
                $value,
                $value,
                implode(', ', $primaryOnlyTypes)
            );
            $matches[] = '(' . $match . ')';
            $fields[] = sprintf('SUM(%s) AS occurrence_%d', $match, $k);
        }
        $sql = sprintf(
            'SELECT %s FROM %s AS Attribute' .
            ' INNER JOIN %s AS Event ON Event.id = Attribute.event_id' .
            ' WHERE (%s)' .
            ' AND Attribute.type NOT IN (%s)' .
            ' AND Attribute.disable_correlation = 0' .
            ' AND Event.disable_correlation = 0' .
            ' AND Attribute.deleted = 0',
            implode(', ', $fields),
            $db->fullTableName($this->Attribute),
            $db->fullTableName($this->Attribute->Event),
            implode(' OR ', $matches),
            implode(', ', $nonCorrelatingTypes)
        );
        // the second parameter keeps these statements out of the query cache, they are large and never repeated
        $result = $this->Attribute->query($sql, false);
        $occurrences = [];
        foreach ($overCorrelations as $k => $overCorrelation) {
            $occurrences[$k] = (int)($result[0][0]['occurrence_' . $k] ?? 0);
        }
        return $occurrences;
    }

    public function truncateTable()
    {
        $this->query('TRUNCATE TABLE over_correlating_values');
        $this->cleanCache();
    }
}
