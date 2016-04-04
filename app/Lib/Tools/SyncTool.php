<?php

class SyncTool {
	// take a server as parameter and return a HttpSocket object using the ssl options defined in the server settings
	public function setupHttpSocket($server = null) {
		$params = array();
		App::uses('HttpSocket', 'Network/Http');
		if(!empty($server)) {
			if ($server['Server']['cert_file']) $params['ssl_cafile'] = APP . "files" . DS . "certs" . DS . $server['Server']['id'] . '.pem';
			if ($server['Server']['self_signed']) $params['ssl_allow_self_signed'] = $server['Server']['self_signed'];
		}
		$HttpSocket = new HttpSocket($params);

		$proxy = Configure::read('Proxy');
		if ($proxy) $HttpSocket->configProxy($proxy['host'], $proxy['port'], $proxy['method'], $proxy['user'], $proxy['password']);

		return $HttpSocket;
	}
}
