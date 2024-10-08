<?php
App::uses('AppModel', 'Model');

/**
 * @property Organisation $Organisation
 * @property User $User
 */
class AccessLog extends AppModel
{
    const BROTLI_HEADER = "\xce\xb2\xcf\x81";
    const COMPRESS_MIN_LENGTH = 256;

    const REQUEST_TYPES = [
        0 => 'Unknown',
        1 => 'GET',
        2 => 'HEAD',
        3 => 'POST',
        4 => 'PUT',
        5 => 'DELETE',
        6 => 'OPTIONS',
        7 => 'TRACE',
        8 => 'PATCH',
    ];

    public $actsAs = [
        'Containable',
    ];

    public $belongsTo = [
        'User' => [
            'className' => 'User',
            'foreignKey' => 'user_id',
        ],
        'Organisation' => [
            'className' => 'Organisation',
            'foreignKey' => 'org_id',
        ],
    ];

    public function afterFind($results, $primary = false)
    {
        foreach ($results as &$result) {
            if (isset($result['AccessLog']['ip'])) {
                $result['AccessLog']['ip'] = inet_ntop($result['AccessLog']['ip']);
            }
            if (isset($result['AccessLog']['request_method'])) {
                $result['AccessLog']['request_method'] = self::REQUEST_TYPES[$result['AccessLog']['request_method']];
            }
            if (!empty($result['AccessLog']['request'])) {
                $decoded = $this->decodeRequest($result['AccessLog']['request']);
                if ($decoded) {
                    list($contentType, $encoding, $data) = $decoded;
                    $result['AccessLog']['request'] = $data;
                    $result['AccessLog']['request_content_type'] = $contentType;
                    $result['AccessLog']['request_content_encoding'] = $encoding;
                } else {
                    $result['AccessLog']['request'] = false;
                }
            }
            if (!empty($result['AccessLog']['query_log'])) {
                $result['AccessLog']['query_log'] = JsonTool::decode($this->decompress($result['AccessLog']['query_log']));
            }
            if (!empty($result['AccessLog']['memory_usage'])) {
                $result['AccessLog']['memory_usage'] = $result['AccessLog']['memory_usage'] * 1024;
            }
        }
        return $results;
    }

    public function beforeSave($options = [])
    {
        $accessLog = &$this->data['AccessLog'];

        // Truncate
        foreach (['request_id', 'user_agent', 'url'] as $field) {
            if (isset($accessLog[$field]) && strlen($accessLog[$field]) > 255) {
                $accessLog[$field] = substr($accessLog[$field], 0, 255);
            }
        }

        if (isset($accessLog['ip'])) {
            $accessLog['ip'] = inet_pton($accessLog['ip']);
        }

        if (isset($accessLog['request_method'])) {
            $requestMethodIds = array_flip(self::REQUEST_TYPES);
            $accessLog['request_method'] = $requestMethodIds[$accessLog['request_method']] ?? 0;
        }

        if (!empty($accessLog['request'])) {
            $accessLog['request'] = $this->compress($accessLog['request']);
        }

        if (!empty($accessLog['query_log'])) {
            $accessLog['query_log'] = $this->compress(JsonTool::encode($accessLog['query_log']));
        }

        // In database save size in kb to avoid overflow signed int type
        if (isset($accessLog['memory_usage'])) {
            $accessLog['memory_usage'] = $accessLog['memory_usage'] >> 10; // same as /= 1024
        }
    }

    /**
     * @param array $user
     * @param string $remoteIp
     * @param CakeRequest $request
     * @param bool $includeRequestBody
     * @return bool
     * @throws Exception
     */
    public function logRequest(array $user, $remoteIp, CakeRequest $request, $includeRequestBody = true)
    {
        $requestTime = $this->requestTime();
        $logClientIp = Configure::read('MISP.log_client_ip');
        $includeSqlQueries = Configure::read('MISP.log_paranoid_include_sql_queries');

        if ($includeSqlQueries) {
            $this->getDataSource()->fullDebug = true; // Enable SQL logging
        }

        $dataToSave = [
            'created' => $requestTime->format('Y-m-d H:i:s.u'),
            'request_id' => $_SERVER['HTTP_X_REQUEST_ID'] ?? null,
            'user_id' => (int)$user['id'],
            'org_id' => (int)$user['org_id'],
            'authkey_id' => isset($user['authkey_id']) ? (int)$user['authkey_id'] : null,
            'ip' => $logClientIp ? $remoteIp : null,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
            'request_method' => $_SERVER['REQUEST_METHOD'],
            'controller' => $request->params['controller'],
            'action' => $request->params['action'],
            'url' => $request->here,
        ];

        if ($includeRequestBody && $request->is(['post', 'put', 'delete'])) {
            $dataToSave['request'] = $this->requestBody($request);
        }

        // Save data on shutdown
        register_shutdown_function(function () use ($dataToSave, $requestTime, $includeSqlQueries) {
            session_write_close(); // close session to allow concurrent requests
            $this->saveOnShutdown($dataToSave, $requestTime, $includeSqlQueries);
        });

        return true;
    }

    /**
     * @param DateTime $duration
     * @return int Number of deleted entries
     */
    public function deleteOldLogs(DateTime $duration)
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
    private function requestBody(CakeRequest $request)
    {
        $requestContentType = $_SERVER['CONTENT_TYPE'] ?? null;
        $requestEncoding = $_SERVER['HTTP_CONTENT_ENCODING'] ?? null;

        if (str_starts_with($requestContentType, 'multipart/form-data')) {
           $input = http_build_query($request->data, '', '&');
        } else {
            $input = $request->input();
        }

        return "$requestContentType\n$requestEncoding\n$input";
    }

    /**
     * @param array $data
     * @param DateTime $requestTime
     * @param bool $includeSqlQueries
     * @return bool
     * @throws Exception
     */
    private function saveOnShutdown(array $data, DateTime $requestTime, $includeSqlQueries)
    {
        $sqlLog = $this->getDataSource()->getLog(false, false);
        $queryCount = $sqlLog['count'];

        if ($includeSqlQueries && !empty($sqlLog['log'])) {
            foreach ($sqlLog['log'] as &$log) {
                $log['query'] = JsonTool::escapeNonUnicode($log['query']);
                unset($log['affected']); // affected is the same as numRows
                unset($log['params']); // no need to save for your use case
            }
            $data['query_log'] = ['time' => $sqlLog['time'], 'log' => $sqlLog['log']];
        }

        $data['response_code'] = http_response_code();
        $data['memory_usage'] = memory_get_peak_usage();
        $data['query_count'] = $queryCount;
        $data['duration'] = (int)((microtime(true) - $requestTime->format('U.u')) * 1000); // in milliseconds

        $this->externalLog($data);

        if (Configure::read('MISP.log_paranoid_skip_db')) {
            return true; // do not save access log to database
        }

        try {
            return $this->save($data, ['atomic' => false]);
        } catch (Exception $e) {
            $this->logException("Could not insert access log to database", $e, LOG_WARNING);
            return false;
        }
    }

    /**
     * @param array $data
     * @return void
     */
    private function externalLog(array $data)
    {
        if ($this->pubToZmq('audit')) {
            $this->getPubSubTool()->publish($data, 'audit', 'log');
        }

        $this->publishKafkaNotification('audit', $data, 'log');
        // In future add support for sending logs to elastic
    }

    /**
     * @return DateTime
     */
    private function requestTime()
    {
        $requestTime = $_SERVER['REQUEST_TIME_FLOAT'] ?? microtime(true);
        $requestTime = (string) $requestTime;
        // Fix string if float value doesnt contain decimal part
        if (!str_contains($requestTime, '.')) {
            $requestTime .= '.0';
        }
        return DateTime::createFromFormat('U.u', $requestTime);
    }

    /**
     * @param string $request
     * @return array|false
     */
    private function decodeRequest($request)
    {
        $request = $this->decompress($request);
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
        if (str_starts_with($data, self::BROTLI_HEADER)) {
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

        if ($compressionEnabled && strlen($data) >= self::COMPRESS_MIN_LENGTH) {
            return self::BROTLI_HEADER . brotli_compress($data, 4, BROTLI_TEXT);
        }
        return $data;
    }
}