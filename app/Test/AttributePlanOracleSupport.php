<?php
/**
 * Records the SQL that MISP issues on its value paths, with the plan the
 * database chose for each statement shape (see QueryPlanSummary). Used by
 * AttributePlanOracleTest for the plans suite of tests/value_oracle. Every
 * operation runs in a transaction that is rolled back.
 */

require_once __DIR__ . '/AttributePayloadOracleSupport.php';
require_once __DIR__ . '/QueryPlanSummary.php';

App::uses('ConnectionManager', 'Model');

/**
 * Mixed into a subclass of the configured datasource. A statement is
 * explained as it is logged, while the temporary tables it reads still exist.
 */
trait PlanCapturingLog
{
    public function logQuery($sql, $params = array())
    {
        PlanCapture::observe($this, $sql, (array)$params, (int)$this->took);
    }

    public function explainJson($verb, $sql, array $params)
    {
        $statement = $this->_connection->prepare(
            $verb . ' FORMAT=JSON ' . $sql
        );
        try {
            $statement->execute($params);
            return json_decode($statement->fetchColumn(), true);
        } finally {
            $statement->closeCursor();
        }
    }
}

class PlanCapture
{
    const KINDS = ['select', 'insert', 'update', 'delete', 'replace'];

    private static $database = '';
    private static $active = false;
    private static $statements = [];
    private static $other = 0;
    private static $otherMs = 0;
    private static $explainMs = 0.0;

    /**
     * Replaces the default connection with one whose class logs into the
     * capture.
     */
    public static function install()
    {
        $db = ConnectionManager::getDataSource('default');
        $parent = get_class($db);
        if (!preg_match('/^Mysql\w*$/', $parent)) {
            throw new RuntimeException(
                "Plan capture needs a MySQL datasource, not $parent."
            );
        }
        if (!class_exists('PlanCapturingDatasource', false)) {
            // The parent class is the configured one, known only here.
            eval(
                'class PlanCapturingDatasource extends ' . $parent .
                ' { use PlanCapturingLog; }'
            );
        }
        // ConnectionManager only accepts classes registered as datasources.
        App::uses('PlanCapturingDatasource', 'Model/Datasource/Database');
        $config = $db->config;
        $config['datasource'] = 'PlanCapturingDatasource';
        self::$database = $config['database'];
        unset($db);
        ConnectionManager::drop('default');
        ConnectionManager::create('default', $config)->fullDebug = true;
        ClassRegistry::flush();
    }

    public static function start()
    {
        self::$statements = [];
        self::$other = 0;
        self::$otherMs = 0;
        self::$explainMs = 0.0;
        self::$active = true;
    }

    /**
     * @return array 'value': the statements on value tables in the order
     *  they first ran, each with its plan and execution count, and the large
     *  reads among them. Kept out of the comparison: 'timings', and
     *  'indexes', the index names per statement (see
     *  QueryPlanSummary::indexes()).
     */
    public static function stop()
    {
        self::$active = false;
        $statements = [];
        $statementMs = [];
        $indexes = [];
        foreach (self::$statements as $statement) {
            $statements[] = $statement['entry'] +
                ['executions' => $statement['executions']];
            $statementMs[] = $statement['ms'];
            $indexes[] = $statement['indexes'];
        }
        return [
            'value' => [
                'statements' => $statements,
                'large_reads' => QueryPlanSummary::largeReads($statements),
            ],
            'timings' => [
                'statement_ms' => $statementMs,
                'value_sql_ms' => array_sum($statementMs),
                'other_statements' => self::$other,
                'other_sql_ms' => self::$otherMs,
                'explain_ms' => (int)round(self::$explainMs),
            ],
            'indexes' => $indexes,
        ];
    }

    public static function observe($db, $sql, array $params, $took)
    {
        if (!self::$active) {
            return;
        }
        $shape = QueryPlanSummary::shape($sql, self::$database);
        $kind = QueryPlanSummary::kind($shape);
        if (
            !in_array($kind, self::KINDS, true) ||
            !QueryPlanSummary::touchesValueTables($shape)
        ) {
            self::$other++;
            self::$otherMs += $took;
            return;
        }
        if (!isset(self::$statements[$shape])) {
            list($entry, $indexes) = self::explain($db, $shape, $sql, $params);
            self::$statements[$shape] = [
                'entry' => $entry,
                'indexes' => $indexes,
                'executions' => 0,
                'ms' => 0,
            ];
        }
        self::$statements[$shape]['executions']++;
        self::$statements[$shape]['ms'] += $took;
    }

    private static function explain($db, $shape, $sql, array $params)
    {
        $entry = ['sql' => $shape, 'kind' => QueryPlanSummary::kind($shape)];
        $indexes = [];
        $verb = QueryPlanSummary::explainVerb($shape);
        if ($verb === null) {
            return [$entry, $indexes];
        }
        $started = microtime(true);
        try {
            $plan = (array)$db->explainJson(
                $verb,
                QueryPlanSummary::stripComment($sql),
                $params
            );
            $entry += QueryPlanSummary::summarise($plan);
            $indexes = QueryPlanSummary::indexes($plan);
        } catch (PDOException $e) {
            $entry['explain_error'] = str_replace(
                self::$database . '.',
                '',
                $e->getMessage()
            );
        } finally {
            self::$explainMs += (microtime(true) - $started) * 1000;
        }
        return [$entry, $indexes];
    }
}

class AttributePlanOracle
{
    const OPERATIONS = [
        'fetchEvent', 'attributeRestSearch', 'eventRestSearch',
        'recorrelateEvent', 'relatedToEvent', 'attributeIndex',
        'saveAttribute', 'paginatedAttributes',
    ];

    /**
     * @param array $request ['operations' => [name => ['op' => one of
     *  OPERATIONS, 'user' => user id, 'args' => [...], 'engine' => optional
     *  correlation engine]]]
     * @return array Per name: 'value' (compared), 'timings', 'indexes',
     *  'error'
     */
    public static function capture(array $request)
    {
        // Nothing a rolled-back operation does may leave the process.
        Configure::write('Plugin.ZeroMQ_enable', false);
        Configure::write('Plugin.Kafka_enable', false);
        Configure::write('Security.syslog', false);
        PlanCapture::install();
        $out = [];
        foreach ($request['operations'] ?? [] as $name => $operation) {
            $out[$name] = self::run($operation);
        }
        return $out;
    }

    private static function run(array $operation)
    {
        $engine = Configure::read('MISP.correlation_engine');
        if (!empty($operation['engine'])) {
            Configure::write('MISP.correlation_engine', $operation['engine']);
        }
        // Fresh models: no lookup cached by an earlier operation.
        ClassRegistry::flush();
        ClassRegistry::init([
            'class' => 'PayloadRecordingAttribute', 'alias' => 'Attribute',
        ]);
        ClassRegistry::init([
            'class' => 'PayloadRecordingShadowAttribute',
            'alias' => 'ShadowAttribute',
        ]);
        $user = ClassRegistry::init('User')->getAuthUser($operation['user']);
        // What AppController records for the request's user.
        Configure::write('CurrentUserId', $user['id'] ?? null);
        Configure::write('CurrentRequestIsRest', true);
        $db = ConnectionManager::getDataSource('default');
        $error = null;
        $started = microtime(true);
        $db->begin();
        PlanCapture::start();
        try {
            $op = $operation['op'];
            if (!in_array($op, self::OPERATIONS, true)) {
                throw new InvalidArgumentException("Unknown operation $op");
            }
            if (empty($user)) {
                throw new InvalidArgumentException(
                    'Unknown user ' . $operation['user']
                );
            }
            self::$op($user, $operation['args'] ?? []);
        } catch (Throwable $e) {
            $error = get_class($e) . ': ' . $e->getMessage();
        } finally {
            $captured = PlanCapture::stop();
            // A DROP TABLE commits implicitly, even of a temporary table.
            $committed = !$db->getConnection()->inTransaction();
            try {
                $db->rollback();
            } catch (PDOException $e) {
                if (!$committed) {
                    throw $e;
                }
            }
            Configure::write('MISP.correlation_engine', $engine);
        }
        if ($committed) {
            $captured['value']['implicit_commit'] = true;
        }
        $captured['timings']['elapsed_ms'] =
            (int)round((microtime(true) - $started) * 1000);
        $captured['error'] = $error;
        return $captured;
    }

    private static function fetchEvent(array $user, array $args)
    {
        ClassRegistry::init('Event')->fetchEvent($user, $args['options']);
    }

    private static function attributeRestSearch(array $user, array $args)
    {
        ClassRegistry::getObject('Attribute')
            ->restSearch($user, $args['format'], $args['filters'])
            ->close();
    }

    private static function eventRestSearch(array $user, array $args)
    {
        ClassRegistry::init('Event')
            ->restSearch($user, $args['format'], $args['filters'])
            ->close();
    }

    private static function recorrelateEvent(array $user, array $args)
    {
        ClassRegistry::init('Correlation')
            ->generateCorrelation(false, $args['event_id']);
    }

    /**
     * What fetchEvent() asks the correlation engine for an event.
     */
    private static function relatedToEvent(array $user, array $args)
    {
        $Correlation = ClassRegistry::init('Correlation');
        $sgids = ClassRegistry::init('SharingGroup')->authorizedIds($user);
        $sgids = empty($sgids) ? [-1] : $sgids;
        $eventId = (int)$args['event_id'];
        $Correlation->getRelatedEventIds($user, $eventId, $sgids);
        $Correlation->getAttributesRelatedToEvent($user, $eventId, $sgids);
    }

    /**
     * The REST branch of AttributesController::index().
     */
    private static function attributeIndex(array $user, array $args)
    {
        $Attribute = ClassRegistry::getObject('Attribute');
        $filters = $args['filters'];
        $conditions = $Attribute->buildFilterConditions(
            $user,
            $filters,
            false
        );
        $params = $args['params'] + [
            'conditions' => $conditions,
            'flatten' => 1,
            'includeWarninglistHits' => 1,
        ];
        $Attribute->fetchAttributes($user, $params);
    }

    private static function saveAttribute(array $user, array $args)
    {
        $Attribute = ClassRegistry::getObject('Attribute');
        $Attribute->create();
        if (!$Attribute->save(['Attribute' => $args['attribute']])) {
            throw new RuntimeException(
                'Save failed: ' . json_encode($Attribute->validationErrors)
            );
        }
    }

    private static function paginatedAttributes(array $user, array $args)
    {
        ClassRegistry::init('Event')->fetchPaginatedAttributes(
            $user,
            $args['event_id'],
            $args['options']
        );
    }
}
