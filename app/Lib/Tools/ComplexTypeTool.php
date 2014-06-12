<?php

class ComplexTypeTool {
	
	// checks if the passed input matches a valid file description attribute's pattern (filename, md5, sha1, sha256, filename|md5, filename|sha1, filename|sha256)		
	public function checkComplexFile($input) {
		$type = '';
		$composite = false;
		if (strpos($input, '|')) {
			$composite = true;
			$result = explode('|', $input);
			if (count($result) != 2) $type = 'other';
			if (!preg_match("#^.+#", $result[0])) $type = 'other';
			$type = 'filename|';
			$input = $result[1];
		}
		if (strlen($input) == 32 && preg_match("#[0-9a-f]{32}$#", $input)) $type .= 'md5';
		if (strlen($input) == 40 && preg_match("#[0-9a-f]{40}$#", $input)) $type .= 'sha1';
		if (strlen($input) == 64 && preg_match("#[0-9a-f]{64}$#", $input)) $type .= 'sha256';
		if ($type == '' && !$composite && preg_match("#^.+#", $input)) $type = 'filename';
		if ($type == '') $type = 'other';
		return array($type => $input);
	}
	
	public function checkComplexCnC($input) {
		$type = '';
		$toReturn = array();
		// check if it's an IP address
		if (filter_var($input, FILTER_VALIDATE_IP)) return array('ip-dst' => $input);
		if (preg_match("#^[A-Z0-9.-]+\.[A-Z]{2,4}$#i", $input)) {
			$result = explode('.', $input);
			if (count($result) > 2) {
				$toReturn[] = array('hostname' => $input);
				 $pos = strpos($input, '.');
				 $toReturn[] = array('domain' => substr($input, (1 + $pos)));
				 return $toReturn;
			}
			return array('domain' => $input);
		}
		
		if (!preg_match("#\n#", $input)) return array('url' => $input);
		return array('other' => $input);
	}
}