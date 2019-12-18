<?php

class KafkaPubTool
{
    private $rdkafka = false;

    private function __error($msg)
    {
        error_log($msg, 3, APP . 'tmp' . DS . 'logs' . DS . 'kafka.error.log');
    }

    public function initTool($brokers, $config)
    {
        if (!$this->rdkafka) {
            try {
                $rdConf = new RdKafka\Conf();
                foreach ($config as $key => $val) {
                    if (!empty($val)) {
                        $rdConf->set($key, $val);
                    }
                }
                $rdConf->setErrorCb(function ($kafka, $err, $reason) {
                    $this->__error(sprintf("%s (reason: %s)\n", rd_kafka_err2str($err), $reason));
                });
                $rdkafka = new RdKafka\Producer($rdConf);
                if ($rdkafka->addBrokers($brokers) == 0) {
                    $this->__error("Could not add any Kafka brokers");
                }
                $this->rdkafka = $rdkafka;
            } catch (Exception $e) {
                $this->__error('Exception: ' . $e->getMessage() . "\n");
            }
        }
    }

    public function publishJson($topicName, $data, $action = false)
    {
        try {
            if (!empty($action)) {
                $data['action'] = $action;
            }
            $body = json_encode($data);
            if (!$body) {
                $this->__error("Error encoding to JSON: ". $data);
            }
            if (!empty($this->rdkafka)) {
                $topic = $this->rdkafka->newTopic($topicName);
                $topic->produce(RD_KAFKA_PARTITION_UA, 0, $body);
                $this->rdkafka->poll(0);
            }
        } catch (Exception $e) {
            $this->__error('Exception: ' . $e->getMessage() . "\n");
        }
    }
}
