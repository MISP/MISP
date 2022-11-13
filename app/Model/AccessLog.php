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
                $request = $this->decodeRequest($result['AccessLog']['request']);
                list($contentType, $encoding, $data) = explode("\n", $request, 3);
                $result['AccessLog']['request'] = $data;
                $result['AccessLog']['request_content_type'] = $contentType;
                $result['AccessLog']['request_content_encoding'] = $encoding;
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

        $this->externalLog($accessLog);

        if (Configure::read('MISP.log_paranoid_skip_db')) {
            return;
        }

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

        if (isset($accessLog['request'])) {
            $accessLog['request'] = $this->encodeRequest($accessLog['request']);
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
        $requestTime = $_SERVER['REQUEST_TIME_FLOAT'] ?? microtime(true);
        $now = DateTime::createFromFormat('U.u', $requestTime);
        $logClientIp = Configure::read('MISP.log_client_ip');

        $dataToSave = [
            'created' => $now->format('Y-m-d H:i:s.u'),
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
        register_shutdown_function(function () use ($dataToSave, $requestTime) {
            session_write_close(); // close session to allow concurrent requests
            $this->saveOnShutdown($dataToSave, $requestTime);
        });

        return true;
    }

    /**
     * @param CakeRequest $request
     * @return string
     */
    private function requestBody(CakeRequest $request)
    {
        $requestContentType = $_SERVER['CONTENT_TYPE'] ?? null;
        $requestEncoding = $_SERVER['HTTP_CONTENT_ENCODING'] ?? null;

        if (substr($requestContentType, 0, 19) === 'multipart/form-data') {
           $input = http_build_query($request->data, '', '&');
        } else {
            $input = $request->input();
        }

        return "$requestContentType\n$requestEncoding\n$input";
    }

    /**
     * @param array $data
     * @param float $requestTime
     * @return bool
     * @throws Exception
     */
    private function saveOnShutdown(array $data, $requestTime)
    {
        $queryCount = $this->getDataSource()->getLog(false, false)['count'];

        $data['response_code'] = http_response_code();
        $data['memory_usage'] = memory_get_peak_usage();
        $data['query_count'] = $queryCount;
        $data['duration'] = (int)((microtime(true) - $requestTime) * 1000); // in milliseconds

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
    public function externalLog(array $data)
    {
        if ($this->pubToZmq('audit')) {
            $this->getPubSubTool()->publish($data, 'audit', 'log');
        }

        $this->publishKafkaNotification('audit', $data, 'log');
        // In future add support for sending logs to elastic
    }

    /**
     * @param string $request
     * @return string
     */
    private function decodeRequest($request)
    {
        $header = substr($request, 0, 4);
        if ($header === self::BROTLI_HEADER) {
            if (function_exists('brotli_uncompress')) {
                $request = brotli_uncompress(substr($request, 4));
                if ($request === false) {
                    return 'Compressed';
                }
            } else {
                return 'Compressed';
            }
        }
        return $request;
    }

    /**
     * @param string $request
     * @return string
     */
    private function encodeRequest($request)
    {
        $compressionEnabled = Configure::read('MISP.log_new_audit_compress') &&
            function_exists('brotli_compress');

        if ($compressionEnabled && strlen($request) >= self::COMPRESS_MIN_LENGTH) {
            return self::BROTLI_HEADER . brotli_compress($request, 4, BROTLI_TEXT);
        }
        return $request;
    }
}