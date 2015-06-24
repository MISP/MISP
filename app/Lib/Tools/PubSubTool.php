<?php
class PubSubTool {
	private function __setupPub() {
		$context = new ZMQContext();
		$pub = $context->getSocket(ZMQ::SOCKET_PUB);
		$port = Configure::read('Plugin.ZeroMQ_port');
		if (empty($port)) $port = 50000;
		$pub->bind("tcp://*:" . $port);
		return $pub;
	}
	
	public function publishEvent($event) {
		$pub = $this->__setupPub();
		App::uses('JSONConverterTool', 'Tools');
		$jsonTool = new JSONConverterTool();
		$json = $jsonTool->event2JSON($event);
		sleep(1);
		$pub->send('misp_json ' . $json);
	}
	
	public function testZMQ() {
		try {
			$context = new ZMQContext();			
		} catch (Exception $e) {
			return false;
		}
		return true;
	}
}