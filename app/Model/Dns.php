<?php

App::uses('AppModel', 'Model');

/*
 * Domain Name System related
 */
class Dns extends AppModel {
	var $useTable = false;

	/*
	 * Checks for a valid internet name
	 * Returns true if Name is an existing Domain Host Name, false otherwise
	 * TODO should be renamed
	 * 
     * @param unknown_type $nametotest The Domain Host Name to check for existence.
	 * @return boolean
	 */
	function testipaddress ($nametotest) {
		if(intval($nametotest)>0){
			return true;
		} else {
			$ipaddress = $nametotest;
			$ipaddress = gethostbyname($nametotest);
			if ($ipaddress == $nametotest) {
				return false;
			}
			else {
				return true;
			}
		}
	}

}