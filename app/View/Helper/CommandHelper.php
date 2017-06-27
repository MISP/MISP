<?php
App::uses('AppHelper', 'View/Helper');

//this helper simply replaces quotes between [QUOTE][/QUOTE] with div tags.
// And now [thread][/thread], [event][/event], [link][/link], [code][/code]


	class CommandHelper extends AppHelper {
		public function convertQuotes($string) {
			$string = str_ireplace('[QUOTE]', '<div class="quote">', $string);
			$string = str_ireplace('[/QUOTE]', '</div>', $string);
			$string = preg_replace('%\[event\]\s*(\d*)\s*\[/event\]%isU', '<a href="' . h(Configure::read('MISP.baseurl')). '/events/view/$1> Event $1</a>', $string);
			$string = preg_replace('%\[thread\]\s*(\d*)\s*\[/thread\]%isU', '<a href="' . h(Configure::read('MISP.baseurl')). '/threads/view/$1> Thread $1</a>', $string);
			$string = preg_replace('%\[link\]\s*(http|https|ftp|git|ftps)(.*)\s*\[/link\]%isU', '<a href="$1$2">$1$2</a>', $string);
			$string = preg_replace('%\[code\](.*)\[/code\]%isU', '<pre>$1</pre>', $string);

			return $string;
		}
	}
