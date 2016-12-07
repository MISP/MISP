<?php
App::uses('AppHelper', 'View/Helper');

//this helper simply replaces quotes between [QUOTE][/QUOTE] with div tags.
// And now [thread][/thread], [event][/event], [link][/link], [code][/code]


	class CommandHelper extends AppHelper {
		public function convertQuotes($string) {
			$string = str_ireplace('[QUOTE]', '<div class="quote">', $string);
			$string = str_ireplace('[/QUOTE]', '</div>', $string);
			$matches = array();
			while (preg_match ('%\[event\](.*?)\[/event\]%is', $string, $matches)) {
				if (!empty($matches) && is_numeric($matches[1])) {
					$string = preg_replace('%\[event\]' . $matches[1] . '\[/event\]%i', '<a href=' . h(Configure::read('MISP.baseurl')) . '/events/view/' . $matches[1] . '> Event ' . $matches[1] . '</a>', $string);
				} else {
					$string = preg_replace('%\[event\]' . $matches[1] . '\[/event\]%i', '%Malformed_Event_Link%', $string);
				}
			}
			$matches = array();

			while (preg_match ('%\[thread\](.*?)\[/thread\]%is', $string, $matches)) {
				if (!empty($matches) && is_numeric($matches[1])) {
					$string = preg_replace('%\[thread\]' . $matches[1] . '\[/thread\]%i', '<a href=' . h(Configure::read('MISP.baseurl')) . '/threads/view/' . $matches[1] . '> Thread ' . $matches[1] . '</a>', $string);
				} else {
					$string = preg_replace('%\[thread\]' . $matches[1] . '\[/thread\]%i', '%Malformed_Thread_Link%', $string);
				}
				$matches = array();
			}

			$matches = array();

			// htmlentities = never trust user inputs			
			while (preg_match ('%\[link\]\s*(.*?)\s*\[/link\]%is', $string, $matches)) {
				if (!empty($matches) && preg_match('/^((http|https|git|ftp|ftps):\/\/.*)$/isU', $matches[1])) {
					$string = preg_replace('%\[link\]\s*' . $matches[1] . '\s*\[/link\]%is', '<a href="' . htmlentities($matches[1]) . '">' . htmlentities($matches[1]) . '</a>', $string);
				} else {
					$string = preg_replace('%\[link\]\s*' . $matches[1] . '\s*\[/link\]%is', '%Malformed_Link%', $string);
				}
				$matches = array();
			}

			$matches = array();

			// htmlentities = never trust user inputs			
			while (preg_match ('%\[code\](.*?)\[/code\]%is', $string, $matches)) {
				if (!empty($matches) ) {
					$string = preg_replace('%\[code\]' . $matches[1] . '\[/code\]%is', '<pre>' . htmlentities($matches[1]) . '</pre>', $string);
				} else {
					$string = preg_replace('%\[code\]' . $matches[1] . '\[/code\]%is', '%Empty_Code%', $string);
				}
				$matches = array();
			}

			return $string;
		}
	}
?>
