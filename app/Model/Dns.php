<?php

App::uses('AppModel', 'Model');

/*
 * Domain Name System related
 */
class Dns extends AppModel {

	public $useTable = false;

/**
 * Checks for a valid internet name
 * Returns true if Name is an existing Domain Host Name, false otherwise
 * TODO should be renamed
 *
 * @param unknown_type $nametotest The Domain Host Name to check for existence.
 * @return boolean
 */
	public function testipaddress($nametotest) {
		if (intval($nametotest) > 0) {
			return true;
		} else {
			$ipaddress = $nametotest;
			$ipaddress = gethostbyname($nametotest);
			if ($ipaddress == $nametotest) {
				return false;
			} else {
				return true;
			}
		}
	}

/**
 * Name to IP list,
 * get all ip numbers given a certain domain or host $name.
 *
 * @param $name being a hostname
 *
 * @return array of ip numbers
 */
	public function nametoipl($name = '') {
		if ('true' == Configure::read('MISP.dns')) {
			if (!$ips = gethostbynamel($name)) $ips = array();
		} else {
			$ips = array();
		}
		return $ips;
	}
}