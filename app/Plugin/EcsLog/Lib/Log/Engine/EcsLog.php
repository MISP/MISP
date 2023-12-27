<?php
App::uses('JsonTool', 'Tools');

/**
 * Logging class that sends logs in JSON format to UNIX socket in Elastic Common Schema (ECS) format
 * Logs are separated by new line characters, so basically it is send as JSONL
 */
class EcsLog implements CakeLogInterface
{
    const ECS_VERSION = '8.11';

    const SOCKET_PATH = '/run/vector';

    /** @var false|resource */
    private static $socket;

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
            '@timestamp' => self::timestamp(),
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
            '@timestamp' => self::timestamp(),
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
            '@timestamp' => self::timestamp(),
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
                'port' => $_SERVER['REMOTE_PORT'],
            ];

            if ($clientIp === $_SERVER['REMOTE_ADDR']) {
                $meta['client'] = $client;
            } else {
                $meta['client'] = [
                    'ip' => $clientIp,
                    'nat' => $client,
                ];
            }

            if (strpos($_SERVER['HTTP_HOST'], ':') !== 0) {
                list($domain, $port) = explode(':', $_SERVER['HTTP_HOST'], 2);
                $meta['url'] = [
                    'domain' => $domain,
                    'port' => (int) $port,
                    'path' => $_SERVER['REQUEST_URI'],
                ];
            } else {
                $meta['url'] = [
                    'domain' => $_SERVER['HTTP_HOST'],
                    'path' => $_SERVER['REQUEST_URI'],
                ];
            }
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
     * @return string
     */
    public static function timestamp()
    {
        return date('Y-m-d\TH:i:s.uP');
    }

    /**
     * @param array $message
     * @return void
     * @throws JsonException
     */
    private static function writeMessage(array $message)
    {
        if (static::$socket === null) {
            static::connect();
        }

        if (static::$socket) {
            $message = array_merge($message, self::createLogMeta());
            $data = JsonTool::encode($message) . "\n";
            $bytesWritten = fwrite(static::$socket, $data);

            // In case of failure, try reconnect and send log again
            if ($bytesWritten === false) {
                static::connect();
                if (static::$socket) {
                    fwrite(static::$socket, $data);
                }
            }
        }
    }

    private static function connect()
    {
        static::$socket = stream_socket_client('unix://' . static::SOCKET_PATH, $errorCode, $errorMessage);
    }
}