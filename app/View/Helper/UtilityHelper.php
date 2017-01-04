<?php
App::uses('AppHelper', 'View/Helper');

	class UtilityHelper extends AppHelper {
		public function space2nbsp($string) {
			$string = str_replace("\t", "    ", $string);
			$string = str_replace(" ", "&nbsp", $string);
			return $string;
		}
	}
?>
