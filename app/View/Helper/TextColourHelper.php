<?php
App::uses('AppHelper', 'View/Helper');

// This helper helps determining the brightness of a colour (initially only used for the tagging) in order to decide
// what text colour to use against the background (black or white)
	class TextColourHelper extends AppHelper {

		public function getTextColour($RGB) {
			$r = hexdec(substr($RGB, 1, 2));
			$g = hexdec(substr($RGB, 3, 2));
			$b = hexdec(substr($RGB, 5, 2));
			$average = ((2 * $r) + $b + (3 * $g))/6;
			if ($average < 128) {
				return 'white';	
			} else {
				return 'black';
			}
		}
	}
?>