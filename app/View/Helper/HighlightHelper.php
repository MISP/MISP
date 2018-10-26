<?php
App::uses('AppHelper', 'View/Helper');

// This helper accepts a string to be processed and an single or an array of strings that get turned into regex search patterns.
// It will then run each of those through the string with preg_replaces, highlighting all the matched terms in red
// Used for things such as searches in the logs to highlight found terms

	class HighlightHelper extends AppHelper {

		/**
		 * Important: data needs to be sanitized using the h() function before entering this function
		 * @param unknown_type $keywordArray
		 */
		public function build_replace_pairs($keywordArray) {
			// build the $replacePairs variable used to highlight the keywords
			$replacementArray = array();
			if (!is_array($keywordArray)) {
				$keywordArray = array($keywordArray);
			}
			foreach ($keywordArray as $k => $keywordArrayElement) {
				$keywordArrayElement = trim($keywordArrayElement);
				if ("" == $keywordArrayElement) {
					unset($keywordArray[$k]);
					continue;
				} else {
					$keywordArray[$k] = $keywordArrayElement;
				}
				$replacementArray[] = '<span style="color:red">'.$keywordArrayElement.'</span>';
			}
			if (!empty($replacementArray))
				return array_combine($keywordArray, $replacementArray);
		}

		public function highlighter($str, $replacePairs) {
			if (is_array($replacePairs)) {
				return strtr($str, $replacePairs);
			} else {
				return $str;
			}

		}
	}
?>
