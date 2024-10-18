<?php
App::uses('JsonTool', 'Tools');

/**
 * Logging class that sends logs in JSON format to UNIX socket in Elastic Common Schema (ECS) format
 * Logs are separated by new line characters, so basically it is send as JSONL
 */
class EcsLog implements CakeLogInterface
{
    const ECS_VERSION = '8.11';

    /** @var string Unix socket path where logs will be send in JSONL format */
    const SOCKET_PATH = '/run/vector';

    /** @var false|resource */
    private static $socket;

    /** @var string[]  */
    private static $messageBuffer = [];

    /** @var array[] */
    private static $meta;

    const LOG_LEVEL_STRING = [
        LOG_EMERG => 'emergency',
        LOG_ALERT => 'alert',
        LOG_CRIT => 'critical',
        LOG_ERR => 'error',
        LOG_WARNING => 'warning',
        LOG_NOTICE => 'notice',
        LOG_INFO => 'info',
        LOG_DEBUG => 'debug',
    ];

    /**
     * @param string $type The type of log you are making.
     * @param string $message The message you want to log.
     * @return void
     */
    public function write($type, $message)
    {
        if (str_contains($message, 'Could not convert ECS log message into JSON: ')) {
            return; // prevent recursion when saving logs
        }

        $message = [
            '@timestamp' => self::now(),
            'ecs' => [
                'version' => self::ECS_VERSION,
            ],
            'event' => [
                'kind' => 'event',
                'provider' => 'misp',
                'module' => 'system',
                'dataset' => 'system.logs',
            ],
            'log' => [
                'level' => $type,
            ],
            'message' => JsonTool::escapeNonUnicode($message),
        ];

        static::writeMessage($message);
    }

    /**
     * @param string $type
     * @param string $action
     * @param string $message
     * @return void
     */
    public static function writeApplicationLog($type, $action, $message)
    {
        $message = [
            '@timestamp' => self::now(),
            'ecs' => [
                'version' => self::ECS_VERSION,
            ],
            'event' => [
                'kind' => 'event',
                'provider' => 'misp',
                'module' => 'application',
                'dataset' => 'application.logs',
                'action' => $action,
            ],
            'log' => [
                'level' => $type,
            ],
            'message' => $message,
        ];

        if (in_array($action, Log::AUTH_ACTIONS, true)) {
            $message['event']['category'] = 'authentication';

            if (in_array($action, ['auth_fail', 'login_fail'], true)) {
                $message['event']['outcome'] = 'failure';
            }
        }

        static::writeMessage($message);
    }

    /**
     * Include more meta information about email than would provide default `writeApplicationLog` log
     * @param string $logTitle
     * @param array $emailResult
     * @param string|null $replyTo
     * @return void
     */
    public static function writeEmailLog($logTitle, array $emailResult, $replyTo = null)
    {
        $message = [
            '@timestamp' => self::now(),
            'ecs' => [
                'version' => self::ECS_VERSION,
            ],
            'event' => [
                'kind' => 'event',
                'provider' => 'misp',
                'module' => 'application',
                'dataset' => 'application.logs',
                'category' => 'email',
                'action' => 'email',
                'type' => 'info',
            ],
            'email' => [
                'message_id' => $emailResult['message_id'],
                'subject' => $emailResult['subject'],
                'to' => [
                    'address' => $emailResult['to'],
                ],
            ],
            'message' => $logTitle,
        ];

        if ($replyTo) {
            $message['email']['reply_to'] = ['address' => $replyTo];
        }

        static::writeMessage($message);
    }

    /**
     * @param int $code
     * @param string $description
     * @param string|null $file
     * @param int|null $line
     * @return void
     */
    public static function handleError($code, $description, $file = null, $line = null)
    {
        list($name, $log) = ErrorHandler::mapErrorCode($code);
        $level = self::LOG_LEVEL_STRING[$log];

        $message = [
            '@timestamp' => self::now(),
            'ecs' => [
                'version' => self::ECS_VERSION,
            ],
            'event' => [
                'kind' => 'event',
                'provider' => 'misp',
                'module' => 'system',
                'dataset' => 'system.logs',
                'type' => 'error',
            ],
            'error' => [
                'code' => $code,
                'message' => $description,
            ],
            'log' => [
                'level' => $level,
                'origin' => [
                    'file' => [
                        'name' => $file,
                        'line' => $line,
                    ],
                ],
            ],
        ];
        static::writeMessage($message);
    }

    /**
     * @param Throwable $exception
     * @return void
     */
    public static function handleException(Throwable $exception)
    {
        $code = $exception->getCode();
        $code = ($code && is_int($code)) ? $code : 1;

        $message = [
            '@timestamp' => self::now(),
            'ecs' => [
                'version' => self::ECS_VERSION,
            ],
            'event' => [
                'kind' => 'event',
                'provider' => 'misp',
                'module' => 'system',
                'dataset' => 'system.logs',
                'type' => 'error',
            ],
            'error' => [
                'code' => $code,
                'type' => get_class($exception),
                'message' => $exception->getMessage(),
                'stack_trace' => $exception->getTraceAsString(),
            ],
            'log' => [
                'level' => 'error',
                'origin' => [
                    'file' => [
                        'name' => $exception->getFile(),
                        'line' => $exception->getLine(),
                    ],
                ],
            ],
        ];
        static::writeMessage($message);
    }

    /**
     * @return array|null
     */
    private static function clientIpFromHeaders()
    {
        $ipHeader = Configure::read('MISP.log_client_ip_header') ?: null;
        if ($ipHeader && isset($_SERVER[$ipHeader])) {
            return array_map('trim', explode(',', $_SERVER[$ipHeader]));
        }
        return null;
    }

    /**
     * @return array[]
     */
    private static function createLogMeta()
    {
        if (self::$meta) {
            return self::$meta;
        }

        $meta = ['process' => ['pid' => getmypid()]];

        // Add metadata if log was generated because of HTTP request
        if (PHP_SAPI !== 'cli') {
            if (isset($_SERVER['HTTP_X_REQUEST_ID'])) {
                $meta['http'] = ['request' => ['id' => $_SERVER['HTTP_X_REQUEST_ID']]];
            }

            $meta['client'] = self::createClientMeta();
            $meta['url'] = self::createUrlMeta();

        } else {
            $meta['process']['argv'] = $_SERVER['argv'];
        }

        $userMeta = self::createUserMeta();
        if ($userMeta) {
            $meta['user'] = $userMeta;
        }

        return self::$meta = $meta;
    }

    /**
     * @return array
     */
    private static function createClientMeta()
    {
        $client = [
            'ip' => $_SERVER['REMOTE_ADDR'],
            'port' => (int) $_SERVER['REMOTE_PORT'],
        ];

        $clientIps = static::clientIpFromHeaders();
        if ($clientIps) {
            $clientIps[] = $_SERVER['REMOTE_ADDR'];
            return [
                'address' => $clientIps,
                'ip' => $clientIps[0], // consider first IP as real client IP address
                'nat' => $client,
            ];
        }

        $client['address'] = [$client['ip']];
        return $client;
    }

    /**
     * @return array
     */
    private static function createUrlMeta()
    {
        if (str_contains($_SERVER['REQUEST_URI'], '?')) {
            list($path, $query) = explode('?', $_SERVER['REQUEST_URI'], 2);
            $url = [
                'path' => $path,
                'query' => $query,
            ];
        } else {
            $url = ['path' => $_SERVER['REQUEST_URI']];
        }

        if (str_contains($_SERVER['HTTP_HOST'], ':')) {
            list($domain, $port) = explode(':', $_SERVER['HTTP_HOST'], 2);
            $url['domain'] = $domain;
            $url['port'] = (int) $port;
        } else {
            $url['domain'] = $_SERVER['HTTP_HOST'];
        }

        return $url;
    }

    /**
     * Get user metadata (use unique id and email address)
     * @return array|null
     */
    private static function createUserMeta()
    {
        if (PHP_SAPI === 'cli') {
            $currentUserId = Configure::read('CurrentUserId');
            if (!empty($currentUserId)) {
                /** @var User $userModel */
                $userModel = ClassRegistry::init('User');
                $user = $userModel->find('first', [
                    'recursive' => -1,
                    'conditions' => ['id' => $currentUserId],
                    'fields' => ['sub', 'email'],
                ]);
                if (!empty($user)) {
                    return [
                        'id' => $user['User']['sub'] ?? $currentUserId,
                        'email' => $user['User']['email'],
                    ];
                }
            }
        } else if (session_status() === PHP_SESSION_ACTIVE) {
            // include session data just when session is active to avoid unnecessary session starting
            App::uses('AuthComponent', 'Controller/Component');
            $authUser = AuthComponent::user();
            if (!empty($authUser)) {
                return [
                    'id' => $authUser['sub'] ?? $authUser['id'],
                    'email' => $authUser['email'],
                ];
            }
        }

        return null;
    }

    /**
     * ISO 8601 timestamp with microsecond precision
     * @return string
     */
    private static function now()
    {
        return (new DateTime())->format('Y-m-d\TH:i:s.uP');
    }

    /**
     * @param array $message
     * @return bool True when message was successfully send to socket, false if message was saved to buffer
     */
    private static function writeMessage(array $message)
    {
        $message = array_merge($message, self::createLogMeta());
        try {
            $data = JsonTool::encode($message) . "\n";
        } catch (JsonException $e) {
            CakeLog::error('Could not convert ECS log message into JSON: ' . $e->getMessage());
            return null;
        }

        if (static::$socket === null) {
            static::connect();
        }

        if (static::$socket) {
            $bytesWritten = fwrite(static::$socket, $data);
            if ($bytesWritten !== false) {
                return true;
            }

            // In case of failure, try reconnect and send log again
            static::connect();
            if (static::$socket) {
                $bytesWritten = fwrite(static::$socket, $data);
                if ($bytesWritten !== false) {
                    return true;
                }
            }
        }

        // If sending message was not successful, save to buffer
        self::$messageBuffer[] = $data;
        if (count(self::$messageBuffer) > 100) {
            array_shift(self::$messageBuffer); // remove oldest log
        }

        return false;
    }

    private static function connect()
    {
        static::$socket = null;

        if (!file_exists(static::SOCKET_PATH)) {
            return;
        }

        static::$socket = stream_socket_client('unix://' . static::SOCKET_PATH, $errorCode, $errorMessage);
        if (static::$socket) {
            foreach (self::$messageBuffer as $message) {
                fwrite(static::$socket, $message);
            }
            self::$messageBuffer = [];
        }
    }
}