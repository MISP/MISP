<?php
App::uses('AppHelper', 'View/Helper');
	class XmlOutputHelper extends AppHelper {
		public function recursiveEcho($array) {
			foreach ($array as $k => $v) {
				if (is_array($v)) {
					if (empty($v)) echo '<' . $k . '/>';
					else {
						foreach ($v as $element) {
							echo '<' . $k . '>';
							$this->recursiveEcho($element);
							echo '</' . $k . '>';
						}
					}
				} else {
					if ($v === false) $v = 0;
					if ($v === "" || $v === null) echo '<' . $k . '/>';
					else {
						echo '<' . $k . '>' . $v . '</' . $k . '>';
					}
				}
			}
		}
	}
?>
