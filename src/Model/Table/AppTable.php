<?php

namespace App\Model\Table;

use App\Lib\Tools\BackgroundJobsTool;
use App\Lib\Tools\EncryptedValue;
use App\Lib\Tools\FileAccessTool;
use App\Lib\Tools\GitTool;
use Cake\Collection\CollectionInterface;
use Cake\Core\Configure;
use Cake\Database\Expression\QueryExpression;
use Cake\Http\Exception\MethodNotAllowedException;
use Cake\I18n\FrozenTime;
use Cake\ORM\Locator\LocatorAwareTrait;
use Cake\ORM\Query;
use Cake\ORM\Table;
use Cake\ORM\TableRegistry;
use Cake\Utility\Hash;
use Exception;
use InvalidArgumentException;

class AppTable extends Table
{
    use LocatorAwareTrait;

    /** @var LogsTable */
    public $Log = null;

    /** @var WorkflowsTable $Workflow  */
    private $Workflow;

    /** @var BackgroundJobsTool */
    private static $loadedBackgroundJobsTool;

    public function initialize(array $config): void
    {
    }

    public function getStatisticsUsageForModel(object $table, array $scopes, array $options = []): array
    {
        $defaultOptions = [
            'limit' => 5,
            'includeOthers' => true,
            'ignoreNull' => true,
        ];
        $options = $this->getOptions($defaultOptions, $options);
        $stats = [];
        foreach ($scopes as $scope) {
            $queryTopUsage = $table->find();
            $queryTopUsage
                ->select(
                    [
                        $scope,
                        'count' => $queryTopUsage->func()->count('id'),
                    ]
                );
            if ($queryTopUsage->getDefaultTypes()[$scope] != 'boolean') {
                $queryTopUsage->where(
                    function (QueryExpression $exp) use ($scope) {
                        return $exp
                            ->isNotNull($scope)
                            ->notEq($scope, '');
                    }
                );
            }
            $queryTopUsage
                ->group($scope)
                ->order(['count' => 'DESC'])
                ->limit($options['limit'])
                ->page(1)
                ->enableHydration(false);
            $topUsage = $queryTopUsage->all()->toList();
            $stats[$scope] = $topUsage;
            if (
                !empty($options['includeOthers']) && !empty($topUsage) &&
                $queryTopUsage->getDefaultTypes()[$scope] != 'boolean'  // No need to get others as we only have 2 possibilities already considered
            ) {
                $queryOthersUsage = $table->find();
                $queryOthersUsage
                    ->select(
                        [
                            'count' => $queryOthersUsage->func()->count('id'),
                        ]
                    )
                    ->where(
                        function (QueryExpression $exp, Query $query) use ($topUsage, $scope, $options) {
                            if (!empty($options['ignoreNull'])) {
                                return $exp
                                    ->isNotNull($scope)
                                    ->notEq($scope, '')
                                    ->notIn($scope, Hash::extract($topUsage, "{n}.{$scope}"));
                            } else {
                                return $exp->or(
                                    [
                                        $query->newExpr()->isNull($scope),
                                        $query->newExpr()->eq($scope, ''),
                                        $query->newExpr()->notIn($scope, Hash::extract($topUsage, "{n}.{$scope}")),
                                    ]
                                );
                            }
                        }
                    )
                    ->enableHydration(false);
                $othersUsage = $queryOthersUsage->all()->toList();
                if (!empty($othersUsage)) {
                    $stats[$scope][] = [
                        $scope => __('Others'),
                        'count' => $othersUsage[0]['count'],
                    ];
                }
            }
        }
        return $stats;
    }

    private function getOptions($defaults = [], $options = []): array
    {
        return array_merge($defaults, $options);
    }

    // Move this into a tool
    public function getActivityStatisticsForModel(object $table, int $days = 30): array
    {
        $statistics = [];
        if ($table->hasBehavior('Timestamp')) {
            if ($table->getSchema()->getColumnType('created') == 'datetime') {
                $statistics['created'] = $this->getActivityStatistic($table, $days, 'created');
            }
            if ($table->getSchema()->getColumnType('modified') == 'datetime') {
                $statistics['modified'] = $this->getActivityStatistic($table, $days, 'modified');
            }
        }
        return $statistics;
    }

    public function getActivityStatistic(object $table, int $days = 30, string $field = 'modified', bool $includeTimeline = true): array
    {
        $statistics = [];
        $statistics['days'] = $days;
        $statistics['amount'] = $table->find()->all()->count();
        if ($table->behaviors()->has('Timestamp') && $includeTimeline) {
            $statistics['timeline'] = $this->buildTimeline($table, $days, $field);
            $statistics['variation'] = $table->find()->where(["{$field} >" => FrozenTime::now()->subDays($days)])->all()->count();
        } else {
            $statistics['timeline'] = [];
            $statistics['variation'] = 0;
        }
        return $statistics;
    }

    public function buildTimeline(object $table, int $days = 30, string $field = 'modified'): array
    {
        $timeline = [];
        $authorizedFields = ['modified', 'created'];
        if ($table->behaviors()->has('Timestamp')) {
            if (!in_array($field, $authorizedFields)) {
                throw new MethodNotAllowedException(__('Cannot construct timeline for field `{0}`', $field));
            }
            $days = $days - 1;
            $query = $table->find();
            $query->select(
                [
                    'count' => $query->func()->count('id'),
                    'date' => "DATE({$field})",
                ]
            )
                ->where(["{$field} >" => FrozenTime::now()->subDays($days)])
                ->group(['date'])
                ->order(['date']);
            $data = $query->all()->toArray();
            $interval = new \DateInterval('P1D');
            $period = new \DatePeriod(FrozenTime::now()->subDays($days), $interval, FrozenTime::now()->addDays(1));
            foreach ($period as $date) {
                $timeline[$date->format("Y-m-d")] = [
                    'time' => $date->format("Y-m-d"),
                    'count' => 0
                ];
            }
            foreach ($data as $entry) {
                $timeline[$entry->date]['count'] = $entry->count;
            }
            $timeline = array_values($timeline);
        }
        return $timeline;
    }

    public function saveMetaFields($id, $input)
    {
        $this->MetaFields = TableRegistry::getTableLocator()->get('MetaFields');
        $this->MetaTemplates = TableRegistry::getTableLocator()->get('MetaTemplates');
        foreach ($input['metaFields'] as $templateID => $metaFields) {
            $metaTemplates = $this->MetaTemplates->find()->where(
                [
                    'id' => $templateID,
                    'enabled' => 1
                ]
            )->contain(['MetaTemplateFields'])->first();
            $fieldNameToId = [];
            foreach ($metaTemplates->meta_template_fields as $i => $metaTemplateField) {
                $fieldNameToId[$metaTemplateField->field] = $metaTemplateField->id;
            }
            foreach ($metaFields as $metaField => $values) {
                if (!is_array($values)) {
                    $values = [$values];
                }
                foreach ($values as $value) {
                    if ($value !== '') {
                        $temp = $this->MetaFields->newEmptyEntity();
                        $temp->field = $metaField;
                        $temp->value = $value;
                        $temp->scope = $this->metaFields;
                        $temp->parent_id = $id;
                        $temp->meta_template_id = $templateID;
                        $temp->meta_template_field_id = $fieldNameToId[$metaField];
                        $res = $this->MetaFields->save($temp);
                    }
                }
            }
        }
    }

    public function isValidUrl($value, array $context): bool
    {
        return filter_var($value, FILTER_VALIDATE_URL);
    }

    /**
     * @param string $field
     * @param Cake\ORM\Table $model
     * @param array $conditions
     */
    public function addCountField(string $field, Table $model, array $conditions)
    {
        $subQuery = $this->buildStatement(
            [
                'fields'     => ['COUNT(*)'],
                'table'      => $model->table(),
                'alias'      => $model->alias,
                'conditions' => $conditions,
            ],
            $model
        );

        $subQuery->select(['count' => $subQuery->func()->count('*')]);


        $this->virtualFields[$field] = $subQuery;
    }


    /**
     * Find method that allows to fetch just one column from database.
     * @param $state
     * @param $query
     * @param array $results
     * @return \Cake\ORM\Query The query builder
     * @throws InvalidArgumentException
     */
    protected function findColumn(Query $query, array $options): Query
    {
        $fields = $query->clause('select');
        if (!isset($fields)) {
            throw new InvalidArgumentException("This method requires `fields` option defined.");
        }

        if (!is_array($fields) || count($fields) != 1) {
            throw new InvalidArgumentException("Not a valid array or invalid number of columns, expected one, " . count($fields) . " given");
        }

        if (isset($options['unique']) && $options['unique']) {
            $query->distinct();
        }
        $query->enableHydration(false);

        $query->formatResults(
            function (CollectionInterface $results) use ($fields) {
                return $results->map(
                    function ($row) use ($fields) {
                        return $row[$fields[0]];
                    }
                );
            },
            $query::APPEND
        );

        return $query;
    }

    public function findOrder($order, $order_model, $valid_order_fields)
    {
        if (!is_array($order)) {
            $order_rules = explode(' ', strtolower($order));
            $order_field = explode('.', $order_rules[0]);
            $order_field = end($order_field);
            if (in_array($order_field, $valid_order_fields)) {
                $direction = 'asc';
                if (!empty($order_rules[1]) && trim($order_rules[1]) === 'desc') {
                    $direction = 'desc';
                }
            } else {
                return null;
            }
            return $order_model . '.' . $order_field . ' ' . $direction;
        }
        return null;
    }

    /**
     * @return LogsTable
     */
    protected function loadLog()
    {
        if (!isset($this->Log)) {
            $this->Log = $this->fetchTable('Logs');
        }
        return $this->Log;
    }

    /**
     * Returns MISP version from VERSION.json file as array with major, minor and hotfix keys.
     *
     * @return array
     * @throws Exception
     */
    public function checkMISPVersion()
    {
        static $versionArray;
        if ($versionArray === null) {
            $versionArray = FileAccessTool::readJsonFromFile(ROOT . DS . 'VERSION.json', true);
        }
        return $versionArray;
    }

    /**
     * Returns MISP commit hash.
     *
     * @return false|string
     */
    public function checkMISPCommit()
    {
        static $commit;
        if ($commit === null) {
            try {
                $commit = GitTool::currentCommit();
            } catch (Exception $e) {
                $this->logException('Could not get current git commit', $e, LOG_NOTICE);
                $commit = false;
            }
        }
        return $commit;
    }

    /**
     * @return BackgroundJobsTool
     */
    public function getBackgroundJobsTool(): BackgroundJobsTool
    {
        if (!self::$loadedBackgroundJobsTool) {
            self::$loadedBackgroundJobsTool = new BackgroundJobsTool(Configure::read('BackgroundJobs'));
            ;
        }

        return self::$loadedBackgroundJobsTool;
    }

    public function validateAuthkey($value)
    {
        if (empty($value)) {
            return 'Empty authkey found. Make sure you set the 40 character long authkey.';
        }
        if (!preg_match('/[a-z0-9]{40}/i', $value)) {
            return 'The authkey has to be exactly 40 characters long and consist of alphanumeric characters.';
        }
        return true;
    }

    public function valueIsID($value)
    {
        if (!is_numeric($value) || $value < 0) {
            return 'Invalid ' . ucfirst($value) . ' ID';
        }
        return true;
    }

    /**
     * @param array $server
     * @param string $model
     * @return array[]
     * @throws JsonException
     */
    public function setupSyncRequest(array $server)
    {
        $version = implode('.', $this->checkMISPVersion());
        $commit = $this->checkMISPCommit();

        $authkey = $server['authkey'];
        if (EncryptedValue::isEncrypted($authkey)) {
            $authkey = (string)new EncryptedValue($authkey);
        }

        return [
            'headers' => [
                'Authorization' => $authkey,
                'Accept' => 'application/json',
                'Content-Type' => 'application/json',
                'User-Agent' => 'MISP ' . $version . (empty($commit) ? '' : ' - #' . $commit),
            ]
        ];
    }

    /**
     * @param string $name
     * @return bool
     */
    protected function pubToZmq($name)
    {
        static $zmqEnabled;
        if ($zmqEnabled === null) {
            $zmqEnabled = (bool)Configure::read('Plugin.ZeroMQ_enable');
        }
        if ($zmqEnabled) {
            return Configure::read("Plugin.ZeroMQ_{$name}_notifications_enable");
        }
        return false;
    }

    protected function isTriggerCallable($trigger_id): bool
    {
        static $workflowEnabled;
        if ($workflowEnabled === null) {
            $workflowEnabled = (bool)Configure::read('Plugin.Workflow_enable');
        }

        if (!$workflowEnabled) {
            return false;
        }

        if ($this->Workflow === null) {
            $this->Workflow = $this->fetchTable('Workflows');
        }
        return $this->Workflow->checkTriggerEnabled($trigger_id) &&
            $this->Workflow->checkTriggerListenedTo($trigger_id);
    }

    public function publishKafkaNotification($topicName, $data, $action = false)
    {
        $kafkaTopic = $this->kafkaTopic($topicName);
        if ($kafkaTopic) {
            $this->getKafkaPubTool()->publishJson($kafkaTopic, $data, $action);
        }
    }

    /**
     * @param string $name
     * @return string|null Null when Kafka is not enabled, topic is not enabled or topic is not defined
     */
    protected function kafkaTopic($name)
    {
        static $kafkaEnabled;
        if ($kafkaEnabled === null) {
            $kafkaEnabled = (bool)Configure::read('Plugin.Kafka_enable');
        }
        if ($kafkaEnabled) {
            if (!Configure::read("Plugin.Kafka_{$name}_notifications_enable")) {
                return null;
            }
            return Configure::read("Plugin.Kafka_{$name}_notifications_topic") ?: null;
        }
        return null;
    }
}
