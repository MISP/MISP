<?php
App::uses('AppHelper', 'View/Helper');

//this helper simply replaces quotes between [QUOTE][/QUOTE] with div tags.

	class CommandHelper extends AppHelper {
		public function convertQuotes($string){
			$string = str_ireplace('[QUOTE]', '<div class="quote">', $string);
			$string = str_ireplace('[/QUOTE]', '</div>', $string);
			$matches = array();
			while (preg_match ('%\[event\](.*?)\[/event\]%is', $string, $matches)) {
				if (!empty($matches) && is_numeric($matches[1])) {
					$string = preg_replace('%\[event\]' . $matches[1] . '\[/event\]%i', '<a href=/events/view/' . $matches[1] . '> Event ' . $matches[1] . '</a>', $string);
				} else {
					$string = preg_replace('%\[event\]' . $matches[1] . '\[/event\]%i', '%Malformed_Event_Link%', $string);
				}
			}
			$matches = array();
			
			while (preg_match ('%\[thread\](.*?)\[/thread\]%is', $string, $matches)) {
				if (!empty($matches) && is_numeric($matches[1])) {
					$string = preg_replace('%\[thread\]' . $matches[1] . '\[/thread\]%i', '<a href=/threads/view/' . $matches[1] . '> Thread ' . $matches[1] . '</a>', $string);
				} else {
					$string = preg_replace('%\[thread\]' . $matches[1] . '\[/thread\]%i', '%Malformed_Thread_Link%', $string);
				}
				$matches = array();
			}
			
			return $string;
		}
	}
?>