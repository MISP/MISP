<?php

namespace App\Model\Table;

use App\Model\Entity\AccessLog;
use App\Model\Table\AppTable;
use Cake\Datasource\EntityInterface;
use Cake\Event\EventInterface;
use ArrayObject;
use App\Lib\Tools\JsonTool;
use Cake\Collection\CollectionInterface;
use Cake\ORM\Query;
use Cake\Chronos\Chronos;
use Cake\Http\ServerRequest;
use Cake\Core\Configure;
use Exception;
use Cake\Datasource\ConnectionManager;
use DebugKit\Database\Log\DebugLog;
use App\Lib\Tools\LogExtendedTrait;

class AccessLogsTable extends AppTable
{
    use LogExtendedTrait;

    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->belongsTo(
            'Users',
            [
                'className' => 'User',
                'foreignKey' => 'user_id',
                'propertyName' => 'User',
            ]
        );
        $this->belongsTo(
            'Organisations',
            [
                'className' => 'Organisation',
                'foreignKey' => 'org_id',
                'propertyName' => 'Organisation',
            ]
        );
    }

    public function beforeMarshal(EventInterface $event, ArrayObject $data, ArrayObject $options)
    {
        // Truncate
        foreach (['request_id', 'user_agent', 'url'] as $field) {
            if (isset($entity[$field]) && strlen($entity[$field]) > 255) {
                $entity[$field] = substr($entity[$field], 0, 255);
            }
        }

        if (isset($data['ip'])) {
            $data['ip'] = inet_pton($data['ip']);
        }

        if (isset($data['request_method'])) {
            $requestMethodIds = array_flip(AccessLog::REQUEST_TYPES);
            $data['request_method'] = $requestMethodIds[$data['request_method']] ?? 0;
        }

        if (!empty($data['request'])) {
            $data['request'] = $this->compress($data['request']);
        }

        if (!empty($data['query_log'])) {
            $data['query_log'] = $this->compress(JsonTool::encode($data['query_log']));
        }

        // In database save size in kb to avoid overflow signed int type
        if (isset($data['memory_usage'])) {
            $data['memory_usage'] = $data['memory_usage'] >> 10; // same as /= 1024
        }
    }

    public function beforeFind(EventInterface $event, Query $query, ArrayObject $options)
    {
        $query->formatResults(
            function (CollectionInterface $results) {
                return $results->map(
                    function ($row) {
                        if (isset($row['ip'])) {
                            $row['ip'] = inet_ntop($row['ip']);
                        }
                        if (isset($row['request_method'])) {
                            $row['request_method'] = AccessLog::REQUEST_TYPES[$row['request_method']];
                        }
                        if (!empty($row['request'])) {
                            $decoded = $this->decodeRequest($row['request']);
                            if ($decoded) {
                                list($contentType, $encoding, $data) = $decoded;
                                $row['request'] = $data;
                                $row['request_content_type'] = $contentType;
                                $row['request_content_encoding'] = $encoding;
                            } else {
                                $row['request'] = false;
                            }
                        }
                        if (!empty($row['query_log'])) {
                            $row['query_log'] = JsonTool::decode($this->decompress(stream_get_contents($row['query_log'])));
                        }
                        if (!empty($row['memory_usage'])) {
                            $row['memory_usage'] = $row['memory_usage'] * 1024;
                        }

                        return $row;
                    }
                );
            },
            $query::APPEND
        );
    }

    /**
     * @param array $user
     * @param string $remoteIp
     * @param ServerRequest $request
     * @param bool $includeRequestBody
     * @return bool
     * @throws Exception
     */
    public function logRequest(array $user, $remoteIp, ServerRequest $request, $includeRequestBody = true)
    {
        $requestTime = $this->requestTime();
        $logClientIp = Configure::read('MISP.log_client_ip');
        $includeSqlQueries = Configure::read('MISP.log_paranoid_include_sql_queries');

        if ($includeSqlQueries) {
            ConnectionManager::get('default')->enableQueryLogging(); // Enable SQL logging
        }

        $dataToSave = [
            'created' => $requestTime,
            'request_id' => $_SERVER['HTTP_X_REQUEST_ID'] ?? null,
            'user_id' => (int)$user['id'],
            'org_id' => (int)$user['org_id'],
            'authkey_id' => isset($user['authkey_id']) ? (int)$user['authkey_id'] : null,
            'ip' => $logClientIp ? $remoteIp : null,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
            'request_method' => $_SERVER['REQUEST_METHOD'],
            'controller' => $request->getParam('controller'),
            'action' => $request->getParam('action'),
            'url' => $request->getAttribute('here'),
        ];

        if ($includeRequestBody && $request->is(['post', 'put', 'delete'])) {
            $dataToSave['request'] = $this->requestBody($request);
        } else {
            $dataToSave['request'] = null;
        }

        // Save data on shutdown
        register_shutdown_function(function () use ($dataToSave, $requestTime, $includeSqlQueries) {
            session_write_close(); // close session to allow concurrent requests
            $this->saveOnShutdown($dataToSave, $requestTime, $includeSqlQueries);
        });

        return true;
    }

    /**
     * @param Chronos $duration
     * @return int Number of deleted entries
     */
    public function deleteOldLogs(Chronos $duration)
    {
        $this->deleteAll([
            ['created <' => $duration->format('Y-m-d H:i:s.u')],
        ], false);

        $deleted = $this->getAffectedRows();
        if ($deleted > 100) {
            $dataSource = $this->getDataSource();
            $dataSource->query('OPTIMIZE TABLE ' . $dataSource->name($this->table));
        }
        return $deleted;
    }

    /**
     * @param CakeRequest $request
     * @return string
     */
    private function requestBody(ServerRequest $request)
    {
        $requestContentType = $_SERVER['CONTENT_TYPE'] ?? null;
        $requestEncoding = $_SERVER['HTTP_CONTENT_ENCODING'] ?? null;

        if (substr($requestContentType, 0, 19) === 'multipart/form-data') {
            $input = http_build_query($request->getBody(), '', '&');
        } else {
            $input = $request->getData();
            if (is_array($input)) {
                $input = JsonTool::encode($input);
            }
        }

        return "$requestContentType\n$requestEncoding\n$input";
    }

    /**
     * @param array $data
     * @param Chronos $requestTime
     * @param bool $includeSqlQueries
     * @return bool
     * @throws Exception
     */
    private function saveOnShutdown(array $data, Chronos $requestTime, $includeSqlQueries)
    {
        $sqlLog = ConnectionManager::get('default')->getLogger();

        if ($sqlLog === null) {
            return false;
        }

        $queries = [];
        $queryCount = 0;
        $queryTotalTime = 0;

        if ($sqlLog instanceof DebugLog) {
            $queries = $sqlLog->queries();
            $queryCount = $sqlLog->totalRows();
            $queryTotalTime = $sqlLog->totalTime();
        }

        if ($includeSqlQueries && !empty($queries)) {
            foreach ($queries as &$log) {
                $log['query'] = $this->escapeNonUnicode($log['query']);
                unset($log['affected']); // affected is the same as numRows
                unset($log['params']); // no need to save for your use case
            }
            $data['query_log'] = ['time' => $queryTotalTime, 'log' => $queries];
        }

        $data['response_code'] = http_response_code();
        $data['memory_usage'] = memory_get_peak_usage();
        $data['query_count'] = $queryCount;
        $data['duration'] = (int)((microtime(true) - $requestTime->format('U.u')) * 1000); // in milliseconds

        $accessLogEntity = $this->newEntity($data);

        try {
            return $this->save($accessLogEntity, ['atomic' => false]);
        } catch (Exception $e) {
            $this->logException("Could not insert access log to database", $e, LOG_WARNING);
            return false;
        }
    }

    /**
     * @param array $data
     * @return void
     */
    public function externalLog(array $data)
    {
        if ($this->pubToZmq('audit')) {
            $this->getPubSubTool()->publish($data, 'audit', 'log');
        }

        $this->publishKafkaNotification('audit', $data, 'log');
        // In future add support for sending logs to elastic
    }

    /**
     * @return Chronos
     */
    private function requestTime()
    {
        $requestTime = $_SERVER['REQUEST_TIME_FLOAT'] ?? microtime(true);
        $requestTime = (string) $requestTime;
        // Fix string if float value doesnt contain decimal part
        if (strpos($requestTime, '.') === false) {
            $requestTime .= '.0';
        }
        return Chronos::createFromFormat('U.u', $requestTime);
    }

    /**
     * @param string $request
     * @return array|false
     */
    private function decodeRequest($request)
    {
        $request = $this->decompress(stream_get_contents($request));
        if ($request === false) {
            return false;
        }

        list($contentType, $encoding, $data) = explode("\n", $request, 3);

        if ($encoding === 'gzip') {
            $data = gzdecode($data);
        } elseif ($encoding === 'br') {
            if (function_exists('brotli_uncompress')) {
                $data = brotli_uncompress($data);
            } else {
                $data = false;
            }
        }

        return [$contentType, $encoding, $data];
    }

    /**
     * @param string $data
     * @return false|string
     */
    private function decompress($data)
    {
        $header = substr($data, 0, 4);
        if ($header === AccessLog::BROTLI_HEADER) {
            if (function_exists('brotli_uncompress')) {
                $data = brotli_uncompress(substr($data, 4));
                if ($data === false) {
                    return false;
                }
            } else {
                return false;
            }
        }
        return $data;
    }

    /**
     * @param string $data
     * @return string
     */
    private function compress($data)
    {
        $compressionEnabled = Configure::read('MISP.log_new_audit_compress') &&
            function_exists('brotli_compress');

        if ($compressionEnabled && strlen($data) >= AccessLog::COMPRESS_MIN_LENGTH) {
            return AccessLog::BROTLI_HEADER . brotli_compress($data, 4, BROTLI_TEXT);
        }
        return $data;
    }

    /**
     * @param $string
     * @return string
     */
    private function escapeNonUnicode($string)
    {
        if (json_encode($string, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_LINE_TERMINATORS) !== false) {
            return $string; // string is valid unicode
        }

        if (function_exists('mb_str_split')) {
            $result = mb_str_split($string);
        } else {
            $result = [];
            $length = mb_strlen($string);
            for ($i = 0; $i < $length; $i++) {
                $result[] = mb_substr($string, $i, 1);
            }
        }

        $string = '';
        foreach ($result as $char) {
            if (strlen($char) === 1 && !preg_match('/[[:print:]]/', $char)) {
                $string .= '\x' . bin2hex($char);
            } else {
                $string .= $char;
            }
        }

        return $string;
    }
}
