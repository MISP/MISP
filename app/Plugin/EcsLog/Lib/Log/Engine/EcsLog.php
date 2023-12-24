<?php

/**
 * Logging class that sends logs in JSON format to UNIX socket in Elastic Common Schema (ECS) format
 * Logs are separated by new line characters, so basically it is send as JSONL
 */
class EcsLog implements CakeLogInterface
{
    const SOCKET_PATH = '/run/vector';

    /** @var false|resource */
    private static $socket;

    /** @var array[] */
    private static $meta;

    /** @var string|null */
    private static $ip;

    /**
     * @param string $type The type of log you are making.
     * @param string $message The message you want to log.
     * @return void
     * @throws JsonException
     */
    public function write($type, $message)
    {
        $message = [
            '@timestamp' => date('Y-m-d\TH:i:s.uP'),
            'ecs' => [
                'version' => '8.11',
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
     * @param string $message
     * @return void
     * @throws JsonException
     */
    public static function writeApplicationLog($type, $message)
    {
        $message = [
            '@timestamp' => date('Y-m-d\TH:i:s.uP'),
            'ecs' => [
                'version' => '8.11',
            ],
            'event' => [
                'kind' => 'event',
                'provider' => 'misp',
                'module' => 'application',
                'dataset' => 'application.logs',
            ],
            'log' => [
                'level' => $type,
            ],
            'message' => $message,
        ];

        static::writeMessage($message);
    }

    /**
     * @return string|null
     */
    private static function clientIp()
    {
        if (static::$ip) {
            return static::$ip;
        }

        $ipHeader = Configure::read('MISP.log_client_ip_header') ?: 'REMOTE_ADDR';
        return static::$ip = isset($_SERVER[$ipHeader]) ? trim($_SERVER[$ipHeader]) : $_SERVER['REMOTE_ADDR'];
    }

    /**
     * @return array[]
     */
    private static function generateMeta()
    {
        if (self::$meta) {
            return self::$meta;
        }

        $meta = [
            'process' => [
                'pid' => getmypid(),
            ],
        ];

        // Add metadata if log was generated because of HTTP request
        if (PHP_SAPI !== 'cli') {
            if (isset($_SERVER['HTTP_X_REQUEST_ID'])) {
                $meta['http'] = ['request' => ['id' => $_SERVER['HTTP_X_REQUEST_ID']]];
            }

            $clientIp = static::clientIp();
            if ($clientIp === $_SERVER['REMOTE_ADDR']) {
                $meta['client'] = ['ip' => static::clientIp()];
            } else {
                $meta['client'] = [
                    'ip' => static::clientIp(),
                    'nat' => [
                        'ip' => $_SERVER['REMOTE_ADDR'],
                    ],
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
        }

        return self::$meta = $meta;
    }

    /**
     * @param array $message
     * @return void
     * @throws JsonException
     */
    private static function writeMessage(array $message)
    {
        if (static::$socket === null) {
            static::$socket = stream_socket_client('unix://' . static::SOCKET_PATH, $errorCode, $errorMessage);
        }

        $message = array_merge($message, self::generateMeta());

        if (static::$socket) {
            fwrite(static::$socket, JsonTool::encode($message) . "\n");
        }
    }
}