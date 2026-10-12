<?php
/**
 * An AttributeValue that records the dictionary work of the pre-pass tests:
 * every prime() and every save that had to query, at what transaction depth,
 * and how many statements each sent.
 *
 * Depth counts the transactions opened since the recorder was made, so a
 * test's own rollback transaction is depth 0, where production code runs
 * outside any transaction. Require it once the application is booted.
 */
class PrePassRecordingAttributeValue extends AttributeValue
{
    /** @var array[] ['phase' => 'prime'|'save', 'depth' => int, 'values' => int, 'statements' => int] */
    public $calls = [];

    /** @var int */
    public $statements = 0;

    /** @var array[] [column, the text the save split off, the id it was given] */
    public $assigned = [];

    private $baseDepth;

    public function __construct()
    {
        parent::__construct();
        $this->baseDepth = $this->rawDepth();
    }

    public function prime(array $values)
    {
        $before = $this->statements;
        $previous = parent::prime($values);
        $this->calls[] = [
            'phase' => 'prime',
            'depth' => $this->depth(),
            'values' => count($values),
            'statements' => $this->statements - $before,
        ];
        return $previous;
    }

    public function assignIds(array &$row, array $fields = [])
    {
        $before = $this->statements;
        parent::assignIds($row, $fields);
        foreach (['value1', 'value2'] as $column) {
            if (array_key_exists($column . '_id', $row)) {
                $this->assigned[] = [$column, (string)$row[$column], $row[$column . '_id']];
            }
        }
        if ($this->statements > $before) {
            $this->calls[] = [
                'phase' => 'save',
                'depth' => $this->depth(),
                'values' => count(array_filter([$row['value1'] ?? null, $row['value2'] ?? null], 'strlen')),
                'statements' => $this->statements - $before,
            ];
        }
    }

    public function getDataSource()
    {
        $caller = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 2)[1]['function'] ?? '';
        if ($caller === 'fetchRows' || $caller === 'insertChunk') {
            $this->statements++;
        }
        return parent::getDataSource();
    }

    /**
     * @return int Values the map holds right now
     */
    public function primedCount()
    {
        $property = new ReflectionProperty(AttributeValue::class, 'primed');
        $property->setAccessible(true);
        return count($property->getValue($this));
    }

    /**
     * @param string $phase
     * @return array[]
     */
    public function callsOf($phase)
    {
        return array_values(array_filter($this->calls, function ($call) use ($phase) {
            return $call['phase'] === $phase;
        }));
    }

    public function depth()
    {
        return $this->rawDepth() - $this->baseDepth;
    }

    protected function inTransaction()
    {
        return $this->depth() > 0;
    }

    private function rawDepth()
    {
        $db = parent::getDataSource();
        $started = new ReflectionProperty($db, '_transactionStarted');
        $started->setAccessible(true);
        if (!$started->getValue($db)) {
            return 0;
        }
        $nesting = new ReflectionProperty($db, '_transactionNesting');
        $nesting->setAccessible(true);
        return $nesting->getValue($db) + 1;
    }
}
