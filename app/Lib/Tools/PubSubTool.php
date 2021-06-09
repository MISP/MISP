<?php
class PubSubTool
{
    const SCRIPTS_TMP = APP . 'files' . DS . 'scripts' . DS . 'tmp' . DS;
    const OLD_PID_LOCATION = APP . 'files' . DS . 'scripts' . DS . 'mispzmq' . DS . 'mispzmq.pid';

    /**
     * @var Redis
     */
    private $redis;

    /**
     * @var array
     */
    private $settings;

    public function initTool()
    {
        if (!$this->redis) {
            $settings = $this->getSetSettings();
            $this->setupPubServer($settings);
            $this->redis = $this->createRedisConnection($settings);
            $this->settings = $settings;
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
        $pidFile = new File($pidFilePath ?: self::SCRIPTS_TMP . 'mispzmq.pid');
        if (!$pidFile->exists()) {
            return false;
        }
        $pid = $pidFile->read();
        if ($pid === false || $pid === '') {
            return false;
        }
        if (!is_numeric($pid)) {
            throw new Exception('Internal error (invalid PID file for the MISP zmq script)');
        }
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
        $redis->rPush($settings['redis_namespace'] . ':command', 'status');
        $response = $redis->blPop($settings['redis_namespace'] . ':status', 5);
        if ($response === null) {
            throw new Exception("No response from status command returned after 5 seconds.");
        }
        return json_decode(trim($response[1]), true);
    }

    public function checkIfPythonLibInstalled()
    {
        $my_server = ClassRegistry::init('Server');
        $result = trim(shell_exec($my_server->getPythonVersion() . ' ' . APP . 'files' . DS . 'scripts' . DS . 'mispzmq' . DS . 'mispzmqtest.py'));
        if ($result === "OK") {
            return true;
        }
        return false;
    }

    public function publishEvent($event)
    {
        App::uses('JSONConverterTool', 'Tools');
        $jsonTool = new JSONConverterTool();
        $json = $jsonTool->convert($event);
        return $this->pushToRedis(':data:misp_json', $json);
    }

    public function event_save($event, $action)
    {
        if (!empty($action)) {
            $event['action'] = $action;
        }
        return $this->pushToRedis(':data:misp_json_event', json_encode($event, JSON_PRETTY_PRINT));
    }

    public function object_save($object, $action)
    {
        if (!empty($action)) {
            $object['action'] = $action;
        }
        return $this->pushToRedis(':data:misp_json_object', json_encode($object, JSON_PRETTY_PRINT));
    }

    public function object_reference_save($object_reference, $action)
    {
        if (!empty($action)) {
            $object_reference['action'] = $action;
        }
        return $this->pushToRedis(':data:misp_json_object_reference', json_encode($object_reference, JSON_PRETTY_PRINT));
    }

    public function publishConversation($message)
    {
        return $this->pushToRedis(':data:misp_json_conversation', json_encode($message, JSON_PRETTY_PRINT));
    }

    public function attribute_save($attribute, $action = false)
    {
        if (!empty($action)) {
            $attribute['action'] = $action;
        }
        return $this->pushToRedis(':data:misp_json_attribute', json_encode($attribute, JSON_PRETTY_PRINT));
    }

    public function tag_save($tag, $action = false)
    {
        if (!empty($action)) {
            $tag['action'] = $action;
        }
        return $this->pushToRedis(':data:misp_json_tag', json_encode($tag, JSON_PRETTY_PRINT));
    }

    public function sighting_save($sighting, $action = false)
    {
        if (!empty($action)) {
            $sighting['action'] = $action;
        }
        return $this->pushToRedis(':data:misp_json_sighting', json_encode($sighting, JSON_PRETTY_PRINT));
    }

    public function warninglist_save(array $warninglist, $action = false)
    {
        if (!empty($action)) {
            $warninglist['action'] = $action;
        }
        return $this->pushToRedis(':data:misp_json_warninglist', json_encode($warninglist, JSON_PRETTY_PRINT));
    }

    public function modified($data, $type, $action = false)
    {
        if (!empty($action)) {
            $data['action'] = $action;
        }
        return $this->pushToRedis(':data:misp_json_' . $type, json_encode($data, JSON_PRETTY_PRINT));
    }

    public function publish($data, $type, $action = false)
    {
        if (!empty($action)) {
            $data['action'] = $action;
        }
        return $this->pushToRedis(':data:misp_json_' . $type, json_encode($data, JSON_PRETTY_PRINT));
    }

    public function killService()
    {
        if ($this->checkIfRunning()) {
            $settings = $this->getSetSettings();
            $redis = $this->createRedisConnection($settings);
            $redis->rPush($settings['redis_namespace'] . ':command', 'kill');
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
            $redis->rPush($settings['redis_namespace'] . ':command', 'reload');
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
                $redis->rPush($settings['redis_namespace'] . ':command', 'kill');
                sleep(1);
            }

            $this->saveSettingToFile($settings);
            $server = ClassRegistry::init('Server');
            shell_exec($server->getPythonVersion() . ' ' . APP . 'files' . DS . 'scripts' . DS . 'mispzmq' . DS . 'mispzmq.py >> ' . APP . 'tmp' . DS . 'logs' . DS . 'mispzmq.log 2>> ' . APP . 'tmp' . DS . 'logs' . DS . 'mispzmq.error.log &');
        }
    }

    private function pushToRedis($ns, $data)
    {
        $this->redis->rPush($this->settings['redis_namespace'] . $ns, $data);
        return true;
    }

    /**
     * @param array $settings
     * @return Redis
     */
    private function createRedisConnection(array $settings)
    {
        $redis = new Redis();
        $redis->connect($settings['redis_host'], $settings['redis_port']);
        $redisPassword = $settings['redis_password'];
        if (!empty($redisPassword)) {
            $redis->auth($redisPassword);
        }
        $redis->select($settings['redis_database']);
        return $redis;
    }

    /**
     * @param array $settings
     * @throws Exception
     */
    private function saveSettingToFile(array $settings)
    {
        $settingFilePath = self::SCRIPTS_TMP . 'mispzmq_settings.json';
        $settingsFile = new File($settingFilePath, true, 0644);
        if (!$settingsFile->exists()) {
            throw new Exception("Could not create zmq config file '$settingFilePath'.");
        }
        // Because setting file contains secrets, it should be readable just by owner. But because in Travis test,
        // config file is created under one user and then changed under other user, file must be readable and writable
        // also by group.
        @chmod($settingsFile->pwd(), 0660); // hide error if current user is not file owner
        if (!$settingsFile->write(json_encode($settings))) {
            throw new Exception("Could not write zmq config file '$settingFilePath'.");
        }
        $settingsFile->close();
    }

    private function getSetSettings()
    {
        $settings = array(
            'redis_host' => 'localhost',
            'redis_port' => '6379',
            'redis_password' => '',
            'redis_database' => '1',
            'redis_namespace' => 'mispq',
            'host' => '127.0.0.1',
            'port' => '50000',
            'username' => null,
            'password' => null,
        );

        foreach ($settings as $key => $setting) {
            $temp = Configure::read('Plugin.ZeroMQ_' . $key);
            if ($temp) {
                $settings[$key] = $temp;
            }
        }
        return $settings;
    }
}
