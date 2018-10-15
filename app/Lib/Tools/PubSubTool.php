<?php
class PubSubTool
{
    private $__redis = false;
    private $__settings = false;

    private function __getSetSettings()
    {
        $settings = array(
                'redis_host' => 'localhost',
                'redis_port' => '6379',
                'redis_password' => '',
                'redis_database' => '1',
                'redis_namespace' => 'mispq',
                'port' => '50000',
        );

        foreach ($settings as $key => $setting) {
            $temp = Configure::read('Plugin.ZeroMQ_' . $key);
            if ($temp) {
                $settings[$key] = $temp;
            }
        }
        $settingsFile = new File(APP . 'files' . DS . 'scripts' . DS . 'mispzmq' . DS . 'settings.json', true, 0644);
        $settingsFile->write(json_encode($settings, true));
        $settingsFile->close();
        return $settings;
    }

    public function initTool()
    {
        if (!$this->__redis) {
            $settings = $this->__setupPubServer();
            $redis = new Redis();
            $redis->connect($settings['redis_host'], $settings['redis_port']);
            $redis_pwd = $settings['redis_password'];
            if (!empty($redis_pwd)) {
                $redis->auth($redis_pwd);
            }
            $redis->select($settings['redis_database']);
            $this->__redis = $redis;
            $this->__settings = $settings;
        } else {
            $settings = $this->__settings;
        }
        return $settings;
    }

    // read the pid file, if it exists, check if the process is actually running
    // if either the pid file doesn't exists or the process is not running return false
    // otherwise return the pid
    public function checkIfRunning()
    {
        $pidFile = new File(APP . 'files' . DS . 'scripts' . DS . 'mispzmq' . DS . 'mispzmq.pid');
        $pid = $pidFile->read(true, 'r');
        if ($pid === false || $pid === '') {
            return false;
        }
        if (!is_numeric($pid)) {
            throw new Exception('Internal error (invalid PID file for the MISP zmq script)');
        }
        $result = trim(shell_exec('ps aux | awk \'{print $2}\' | grep "^' . $pid . '$"'));
        if (empty($result)) {
            return false;
        }
        return $pid;
    }

    public function statusCheck()
    {
        $redis = new Redis();
        $settings = $this->__getSetSettings();
        $redis->connect($settings['redis_host'], $settings['redis_port']);
        $redis_pwd = $settings['redis_password'];
        if (!empty($redis_pwd)) {
            $redis->auth($redis_pwd);
        }
        $redis->select($settings['redis_database']);
        $redis->rPush($settings['redis_namespace'] . ':command', 'status');
        sleep(1);
        $response = trim($redis->lPop($settings['redis_namespace'] . ':status'));
        return json_decode($response, true);
    }

    public function checkIfPythonLibInstalled()
    {
        $result = trim(shell_exec('python3 ' . APP . 'files' . DS . 'scripts' . DS . 'mispzmq' . DS . 'mispzmqtest.py'));
        if ($result === "OK") {
            return true;
        }
        return false;
    }

    private function __setupPubServer()
    {
        App::uses('File', 'Utility');
        $settings = $this->__getSetSettings();
        if ($this->checkIfRunning() === false) {
            shell_exec('python3 ' . APP . 'files' . DS . 'scripts' . DS . 'mispzmq' . DS . 'mispzmq.py > ' . APP . 'tmp' . DS . 'logs' . DS . 'mispzmq.log 2> ' . APP . 'tmp' . DS . 'logs' . DS . 'mispzmq.error.log &');
        }
        return $settings;
    }

    public function publishEvent($event)
    {
        App::uses('JSONConverterTool', 'Tools');
        $jsonTool = new JSONConverterTool();
        $json = $jsonTool->convert($event);
        return $this->__pushToRedis(':data:misp_json', $json);
    }

    public function event_save($event, $action)
    {
        if (!empty($action)) {
            $event['action'] = $action;
        }
        return $this->__pushToRedis(':data:misp_json_event', json_encode($event, JSON_PRETTY_PRINT));
    }

    public function object_save($object, $action)
    {
        if (!empty($action)) {
            $object['action'] = $action;
        }
        return $this->__pushToRedis(':data:misp_json_object', json_encode($object, JSON_PRETTY_PRINT));
    }

    public function object_reference_save($object_reference, $action)
    {
        if (!empty($action)) {
            $object_reference['action'] = $action;
        }
        return $this->__pushToRedis(':data:misp_json_object_reference', json_encode($object_reference, JSON_PRETTY_PRINT));
    }

    public function publishConversation($message)
    {
        return $this->__pushToRedis(':data:misp_json_conversation', json_encode($message, JSON_PRETTY_PRINT));
    }

    private function __pushToRedis($ns, $data)
    {
        $settings = $this->__getSetSettings();
        $this->__redis->select($settings['redis_database']);
        $this->__redis->rPush($settings['redis_namespace'] . $ns, $data);
        return true;
    }

    public function attribute_save($attribute, $action = false)
    {
        if (!empty($action)) {
            $attribute['action'] = $action;
        }
        return $this->__pushToRedis(':data:misp_json_attribute', json_encode($attribute, JSON_PRETTY_PRINT));
    }

    public function tag_save($tag, $action = false)
    {
        if (!empty($action)) {
            $tag['action'] = $action;
        }
        return $this->__pushToRedis(':data:misp_json_tag', json_encode($tag, JSON_PRETTY_PRINT));
    }

    public function sighting_save($sighting, $action = false)
    {
        if (!empty($action)) {
            $sighting['action'] = $action;
        }
        return $this->__pushToRedis(':data:misp_json_sighting', json_encode($sighting, JSON_PRETTY_PRINT));
    }

    public function modified($data, $type, $action = false)
    {
        if (!empty($action)) {
            $data['action'] = $action;
        }
        return $this->__pushToRedis(':data:misp_json_' . $type, json_encode($data, JSON_PRETTY_PRINT));
    }

    public function publish($data, $type, $action = false)
    {
        if (!empty($action)) {
            $data['action'] = $action;
        }
        return $this->__pushToRedis(':data:misp_json_' . $type, json_encode($data, JSON_PRETTY_PRINT));
    }

    public function killService($settings = false)
    {
        $redis = new Redis();
        if ($this->checkIfRunning()) {
            if ($settings == false) {
                $settings = $this->__getSetSettings();
            }
            $redis->connect($settings['redis_host'], $settings['redis_port']);
            $redis_pwd = $settings['redis_password'];
            if (!empty($redis_pwd)) {
                $redis->auth($redis_pwd);
            }
            $redis->select($settings['redis_database']);
            $redis->rPush($settings['redis_namespace'] . ':command', 'kill');
            sleep(1);
            if ($this->checkIfRunning()) {
                return false;
            }
        }
        return true;
    }

    // reload the server if it is running, if not, start it
    public function reloadServer()
    {
        if (!$this->checkIfRunning()) {
            $settings = $this->__setupPubServer();
        } else {
            $settings = $this->__getSetSettings();
            $redis = new Redis();
            $redis->connect($settings['redis_host'], $settings['redis_port']);
            $redis_pwd = $settings['redis_password'];
            if (!empty($redis_pwd)) {
                $redis->auth($redis_pwd);
            }
            $redis->select($settings['redis_database']);
            $redis->rPush($settings['redis_namespace'] . ':command', 'reload');
        }
        if (!$this->checkIfRunning()) {
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
        $this->__setupPubServer();
        if (!is_numeric($this->checkIfRunning())) {
            return 'Failed starting the ZeroMQ script.';
        }
        return true;
    }
}
