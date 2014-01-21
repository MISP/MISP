<?php

class SyncTool {
	// take a server as parameter and return a HttpSocket object using the ssl options defined in the server settings
	public function setupHttpSocket($server) {
		$params = array();
		App::uses('HttpSocket', 'Network/Http');
		if ($server['Server']['cert_file'])	$params['ssl_cafile'] = APP . "files" . DS . "certs" . DS . $server['Server']['id'] . '.pem';
		if ($server['Server']['self_signed']) $params['ssl_allow_self_signed'] = $server['Server']['self_signed'];
		$HttpSocket = new HttpSocket($params);
		return $HttpSocket;
	}
}
