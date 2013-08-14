<?php
App::uses('AppHelper', 'View/Helper');

//this helper simply replaces quotes between [QUOTE][/QUOTE] with div tags.

	class CommandHelper extends AppHelper {
		public function convertQuotes($string){
			$string = str_ireplace('[QUOTE]', '<div class="quote">', $string);
			$string = str_ireplace('[/QUOTE]', '</div>', $string);
			return $string;
		}
	}
?>