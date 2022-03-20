<?php
App::uses('FileAccessTool', 'Tools');
App::uses('JsonTool', 'Tools');
App::uses('ProcessTool', 'Tools');

class PubSubTool
{
    const SCRIPTS_TMP = APP . 'files' . DS . 'scripts' . DS . 'tmp' . DS;
    const OLD_PID_LOCATION = APP . 'files' . DS . 'scripts' . DS . 'mispzmq' . DS . 'mispzmq.pid';

    /**
     * @var Redis
     */
    private $redis;

    public function initTool()
    {
        if (!$this->redis) {
            $settings = $this->getSetSettings();
            $this->setupPubServer($settings);
            $this->redis = $this->createRedisConnection($settings);
        }
    }

    /**
     * Read the pid file, if it exists, check if the process is actually running
     * if either the pid file doesn't exists or the process is not running return false
     * otherwise return the pid.
     *
     * @param string|null $pidFilePath
     * @return bool|int False when process is not running, PID otherwise.
     * @throws Exception
     */
    public function checkIfRunning($pidFilePath = null)
    {
        $pidFile = $pidFilePath ?: self::SCRIPTS_TMP . 'mispzmq.pid';
        clearstatcache(false, $pidFile);
        if (!file_exists($pidFile)) {
            return false;
        }
        $pid = file_get_contents($pidFile);
        if ($pid === false || $pid === '') {
            return false;
        }
        if (!is_numeric($pid)) {
            throw new Exception('Internal error (invalid PID file for the MISP zmq script)');
        }
        clearstatcache(false, "/proc/$pid");
        $result = file_exists("/proc/$pid");
        if ($result === false) {
            return false;
        }
        return $pid;
    }

    public function statusCheck()
    {
        $settings = $this->getSetSettings();
        $redis = $this->createRedisConnection($settings);
        $redis->rPush( 'command', 'status');
        $response = $redis->blPop('status', 5);
        if ($response === null) {
            throw new Exception("No response from status command returned after 5 seconds.");
        }
        return json_decode(trim($response[1]), true);
    }

    public function checkIfPythonLibInstalled()
    {
        $script = APP . 'files' . DS . 'scripts' . DS . 'mispzmq' . DS . 'mispzmqtest.py';
        $result = ProcessTool::execute([ProcessTool::pythonBin(), $script]);
        if (trim($result) === "OK") {
            return true;
        }
        return false;
    }

    public function publishEvent($event)
    {
        App::uses('JSONConverterTool', 'Tools');
        $json = JSONConverterTool::convert($event, false, true);
        return $this->pushToRedis('data:misp_json', $json);
    }

    public function event_save(array $event, $action)
    {
        if (!empty($action)) {
            $event['action'] = $action;
        }
        return $this->pushToRedis('data:misp_json_event', $event);
    }

    public function object_save(array $object, $action)
    {
        if (!empty($action)) {
            $object['action'] = $action;
        }
        return $this->pushToRedis('data:misp_json_object', $object);
    }

    public function object_reference_save(array $object_reference, $action)
    {
        if (!empty($action)) {
            $object_reference['action'] = $action;
        }
        return $this->pushToRedis('data:misp_json_object_reference', $object_reference);
    }

    public function publishConversation(array $message)
    {
        return $this->pushToRedis('data:misp_json_conversation', $message);
    }

    public function attribute_save(array $attribute, $action = false)
    {
        if (!empty($action)) {
            $attribute['action'] = $action;
        }
        return $this->pushToRedis('data:misp_json_attribute', $attribute);
    }

    public function tag_save(array $tag, $action = false)
    {
        if (!empty($action)) {
            $tag['action'] = $action;
        }
        return $this->pushToRedis('data:misp_json_tag', $tag);
    }

    public function sighting_save(array $sighting, $action = false)
    {
        if (!empty($action)) {
            $sighting['action'] = $action;
        }
        return $this->pushToRedis('data:misp_json_sighting', $sighting);
    }

    public function warninglist_save(array $warninglist, $action = false)
    {
        if (!empty($action)) {
            $warninglist['action'] = $action;
        }
        return $this->pushToRedis('data:misp_json_warninglist', $warninglist);
    }

    /**
     * @param array $data
     * @param string $type
     * @param string|false $action
     * @return bool
     * @throws JsonException
     */
    public function modified($data, $type, $action = false)
    {
        if (!empty($action)) {
            $data['action'] = $action;
        }
        return $this->pushToRedis('data:misp_json_' . $type, $data);
    }

    public function publish($data, $type, $action = false)
    {
        if (!empty($action)) {
            $data['action'] = $action;
        }
        return $this->pushToRedis('data:misp_json_' . $type, $data);
    }

    public function killService()
    {
        if ($this->checkIfRunning()) {
            $settings = $this->getSetSettings();
            $redis = $this->createRedisConnection($settings);
            $redis->rPush('command', 'kill');
            sleep(1);
            if ($this->checkIfRunning()) {
                // Still running.
                return false;
            }
        }
        return true;
    }

    /**
     * Reload the server if it is running, if not, start it.
     *
     * @return bool|string
     * @throws Exception
     */
    public function reloadServer()
    {
        $settings = $this->getSetSettings();
        $this->saveSettingToFile($settings);

        if ($this->checkIfRunning()) {
            $redis = $this->createRedisConnection($settings);
            $redis->rPush( 'command', 'reload');
        } else {
            return 'Setting saved, but something is wrong with the ZeroMQ server. Please check the diagnostics page for more information.';
        }
        return true;
    }

    public function restartServer()
    {
        if (!$this->checkIfRunning()) {
            if (!$this->killService()) {
                return 'Could not kill the previous instance of the ZeroMQ script.';
            }
        }
        $settings = $this->getSetSettings();
        $this->setupPubServer($settings);
        if ($this->checkIfRunning() === false) {
            return 'Failed starting the ZeroMQ script.';
        }
        return true;
    }

    /**
     * @param array $settings
     * @throws Exception
     */
    private function setupPubServer(array $settings)
    {
        if ($this->checkIfRunning() === false) {
            if ($this->checkIfRunning(self::OLD_PID_LOCATION)) {
                // Old version is running, kill it and start again new one.
                $redis = $this->createRedisConnection($settings);
                $redis->rPush('command', 'kill');
                sleep(1);
            }

            $this->saveSettingToFile($settings);
            shell_exec(ProcessTool::pythonBin() . ' ' . APP . 'files' . DS . 'scripts' . DS . 'mispzmq' . DS . 'mispzmq.py >> ' . APP . 'tmp' . DS . 'logs' . DS . 'mispzmq.log 2>> ' . APP . 'tmp' . DS . 'logs' . DS . 'mispzmq.error.log &');
        }
    }

    /**
     * @param string $ns
     * @param string|array $data
     * @return bool
     * @throws JsonException
     */
    private function pushToRedis($ns, $data)
    {
        $data = JsonTool::encode($data);
        $this->redis->rPush($ns, $data);
        return true;
    }

    /**
     * @param array $settings
     * @return Redis
     * @throws Exception
     */
    private function createRedisConnection(array $settings)
    {
        if (!class_exists('Redis')) {
            throw new Exception("Class Redis doesn't exists. Please install redis extension for PHP.");
        }

        $redis = new Redis();
        $redis->connect($settings['redis_host'], $settings['redis_port']);
        $redisPassword = $settings['redis_password'];
        if (!empty($redisPassword)) {
            $redis->auth($redisPassword);
        }
        $redis->select($settings['redis_database']);
        $redis->setOption(Redis::OPT_PREFIX, $settings['redis_namespace'] . ':');
        return $redis;
    }

    /**
     * @param array $settings
     * @throws Exception
     */
    private function saveSettingToFile(array $settings)
    {
        $settingFilePath = self::SCRIPTS_TMP . 'mispzmq_settings.json';

        // Because setting file contains secrets, it should be readable just by owner. But because in Travis test,
        // config file is created under one user and then changed under other user, file must be readable and writable
        // also by group.
        FileAccessTool::createFile($settingFilePath, 0660);
        FileAccessTool::writeToFile($settingFilePath, JsonTool::encode($settings));
    }

    private function getSetSettings()
    {
        $settings = array(
            'redis_host' => 'localhost',
            'redis_port' => 6379,
            'redis_password' => '',
            'redis_database' => 1,
            'redis_namespace' => 'mispq',
            'host' => '127.0.0.1',
            'port' => '50000',
            'username' => null,
            'password' => null,
        );

        $pluginConfig = Configure::read('Plugin');
        foreach ($settings as $key => $setting) {
            $temp = isset($pluginConfig['ZeroMQ_' . $key]) ? $pluginConfig['ZeroMQ_' . $key] : null;
            if ($temp) {
                $settings[$key] = $temp;
            }
        }
        return $settings;
    }
}
