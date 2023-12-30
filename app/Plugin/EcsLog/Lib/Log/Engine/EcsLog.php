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

    /**
     * @param string $type The type of log you are making.
     * @param string $message The message you want to log.
     * @return void
     * @throws JsonException
     */
    public function write($type, $message)
    {
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
            'message' => $message,
        ];

        static::writeMessage($message);
    }

    /**
     * @param string $type
     * @param string $action
     * @param string $message
     * @return void
     * @throws JsonException
     */
    public static function writeApplicationLog($type, $action, $message)
    {
        if ($action === 'email') {
            return; // do not log email actions as it is logged with more details by `writeEmailLog` function
        }

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

        if (in_array($action, ['auth', 'auth_fail', 'auth_alert', 'change_pw', 'login', 'login_fail', 'logout', 'password_reset'], true)) {
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
     * @throws JsonException
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
     * @return string|null
     */
    private static function clientIp()
    {
        $ipHeader = Configure::read('MISP.log_client_ip_header') ?: 'REMOTE_ADDR';
        return isset($_SERVER[$ipHeader]) ? trim($_SERVER[$ipHeader]) : $_SERVER['REMOTE_ADDR'];
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

            $clientIp = static::clientIp();
            $client = [
                'ip' => $_SERVER['REMOTE_ADDR'],
                'port' => (int) $_SERVER['REMOTE_PORT'],
            ];

            if ($clientIp === $_SERVER['REMOTE_ADDR']) {
                $meta['client'] = $client;
            } else {
                $meta['client'] = [
                    'ip' => $clientIp,
                    'nat' => $client,
                ];
            }
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
    private static function createUrlMeta()
    {
        if (strpos($_SERVER['REQUEST_URI'], '?') !== false) {
            list($path, $query) = explode('?', $_SERVER['REQUEST_URI'], 2);
            $url = [
                'path' => $path,
                'query' => $query,
            ];
        } else {
            $url = ['path' => $_SERVER['REQUEST_URI']];
        }

        if (strpos($_SERVER['HTTP_HOST'], ':') !== false) {
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

        } else {
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
     * @throws JsonException
     */
    private static function writeMessage(array $message)
    {
        $message = array_merge($message, self::createLogMeta());
        $data = JsonTool::encode($message) . "\n";

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