<?php
// based on the php implementation of the BTC address validation example from 
// http://rosettacode.org/wiki/Bitcoin/address_validation
class BitCoinTool {
	function validate($address){
		$decoded = $this->decodeBase58($address);
		if ($decoded === false) return false;
		
		$d1 = hash("sha256", substr($decoded,0,21), true);
		$d2 = hash("sha256", $d1, true);
	
		if(substr_compare($decoded, $d2, 21, 4)){
			return false;
		}
		return true;
	}
	function decodeBase58($input) {
		$alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
	
		$out = array_fill(0, 25, 0);
		for($i=0;$i<strlen($input);$i++){
			if(($p=strpos($alphabet, $input[$i]))===false){
				return false;
			}
			$c = $p;
			for ($j = 25; $j--; ) {
				$c += (int)(58 * $out[$j]);
				$out[$j] = (int)($c % 256);
				$c /= 256;
				$c = (int)$c;
			}
			if($c != 0){
				return false;
			}
		}
	
		$result = "";
		foreach($out as $val){
			$result .= chr($val);
		}
	
		return $result;
	}
}