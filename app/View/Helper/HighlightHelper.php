<?php
App::uses('AppHelper', 'View/Helper');

// This helper accepts a string to be processed and an single or an array of strings that get turned into regex search patterns.
// It will then run each of those through the string with preg_replaces, highlighting all the matched terms in red
// Used for things such as searches in the logs to highlight found terms

	class HighlightHelper extends AppHelper {
		public function highlighter($str, $keyWords) {
			if (is_array($keyWords)) {
				foreach ($keyWords as $keyword) {
					$keyword = trim($keyword);
					$str = preg_replace('%' . $keyword . '%i', '<span style="color:red">' . $keyword . '</span>', $str);
				}
				return $str;
			} else {
				$str = preg_replace('%' . $keyWords . '%i', '<span style="color:red">' . $keyWords . '</span>', $str);
				return $str;
			}
		}
	}
?>