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

    /** @var false|int */
    private static $pid;

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

        $this->writeMessage($message);
    }

    /**
     * @return string|null
     */
    private function ip()
    {
        if (static::$ip) {
            return static::$ip;
        }

        $ipHeader = Configure::read('MISP.log_client_ip_header') ?: 'REMOTE_ADDR';
        return static::$ip = isset($_SERVER[$ipHeader]) ? trim($_SERVER[$ipHeader]) : $_SERVER['REMOTE_ADDR'];
    }

    /**
     * @param array $message
     * @return void
     * @throws JsonException
     */
    private function writeMessage(array $message)
    {
        if (static::$socket === null) {
            static::$socket = stream_socket_client('unix://' . static::SOCKET_PATH, $errorCode, $errorMessage);
        }

        if (static::$pid === null) {
            static::$pid = getmypid();
        }

        $message['process'] = ['id' => self::$pid];

        $isShell = defined('CAKEPHP_SHELL') && CAKEPHP_SHELL;
        if (!$isShell) {
            if (isset($_SERVER['HTTP_X_REQUEST_ID'])) {
                $message['http'] = ['request' => ['id' => $_SERVER['HTTP_X_REQUEST_ID']]];
            }
            $message['client'] = ['ip' => $this->ip()];
        }

        if (static::$socket) {
            fwrite(static::$socket, JsonTool::encode($message) . "\n");
        }
    }
}