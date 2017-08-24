<?php
App::uses('AppHelper', 'View/Helper');

//this helper simply replaces quotes between [QUOTE][/QUOTE] with div tags.
// And now [thread][/thread], [event][/event], [link][/link], [code][/code]


	class CommandHelper extends AppHelper {
		var $helpers = array('Html');

		private $__replacement;

		private function __buildReplacements() {
			$this->__replacement = array(
				'link' => array('type' => 'url', 'url' => '$1', 'text' => '$1'),
				'thread' => array('type' => 'url', 'url' => h(Configure::read('MISP.baseurl')). '/threads/view/$1', 'text' => ' Thread $1'),
				'event' => array('type' => 'url', 'url' => h(Configure::read('MISP.baseurl')). '/events/view/$1', 'text' => ' Event $1'),
				'code' => array('type' => 'replace', 'text' => '<pre>$1</pre>'),
				'quote' => array('type' => 'replace', 'text' => '<div class="quote">$1</div>')
			);
		}


		public function convertQuotes($string) {
			$this->__buildReplacements();
			foreach ($this->__replacement as $trigger => $replacement) {
				$result = $this->__handleLinks($string, $trigger);
				if (!$result) return 'Malformed syntax.';
			}
			return $string;
		}

		private function __handleLinks(&$string, $trigger) {
			$opening = preg_match('%\[' . $trigger . '\]%isU', $string, $opening_matches, PREG_OFFSET_CAPTURE);
			$closing = preg_match('%\[/' . $trigger . '\]%isU', $string, $closing_matches, PREG_OFFSET_CAPTURE);
			$opening_len = strlen($trigger) + 2;
			$closing_len = $opening_len + 1;
			if ((count($opening) !== count($closing))) return false;
			$pairs = array();
			$rearrangedTags = array();
			foreach ($opening_matches as $opening_tag) {
				$rearrangedTags[$opening_tag[1]] = 'open';
			}
			foreach ($closing_matches as $closing_tag) {
				$rearrangedTags[$closing_tag[1]] = 'close';
			}
			foreach ($opening_matches as $opening_tag) {
				$counter = 1;
				foreach ($rearrangedTags as $pos => $type) {
					if ($opening_tag[1] == $pos) continue;
					if ($type == 'close') $counter--;
					else $counter++;
					if ($counter == 0) {
						$pairs[] = array($opening_tag[1], $pos);
						continue 2;
					}
				}
			}
			foreach ($pairs as $pair) {
				$temp = substr($string, 0, $pair[0]);
				if ($this->__replacement[$trigger]['type'] == 'url') {
					$data = substr($string, $pair[0] + $opening_len, $pair[1] - ($pair[0] + $opening_len));
					if (empty($data)) {
						$replacement = '';
					} else {
						if (!is_numeric($data) && ($trigger == 'event' || $trigger == 'thread')) {
							$replacement = '%MALFORMED URL%';
						} else {
							if (filter_var(str_replace('$1', $data, $this->__replacement[$trigger]['url']), FILTER_VALIDATE_URL)) {
								$replacement = $this->Html->link(
									str_replace('$1', $data, $this->__replacement[$trigger]['text']),
									str_replace('$1', $data, $this->__replacement[$trigger]['url'])
								);
							} else {
								$replacement = '%MALFORMED URL%';
							}
						}
					}
				} else {
					$data = substr($string, $pair[0] + $opening_len, $pair[1] - ($pair[0] + $opening_len));
					if (empty($data)) {
						$replacement = '';
					} else {
						$replacement = str_replace('$1', $data, $this->__replacement[$trigger]['text']);
					}
				}
				$temp .= $replacement;
				$temp .= substr($string, $pair[1] + $closing_len, strlen($string));
				$string = $temp;
			}
			return true;
		}
	}
