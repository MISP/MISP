<?php
App::uses('AppHelper', 'View/Helper');

	class PivotHelper extends AppHelper {
		
		private function __doConvert($pivot, $currentEvent, $activeText=false) {
			$data = null;
			$text = $pivot['id'] . ': ';
			$active = '';
			$pivot['info'] = h($pivot['info']);
			// Truncate string if longer than (11 - length of event id) chars to fit the pivot bubble
			if (strlen($pivot['info']) > (11 - strlen((string)$pivot['id']))) {
				$text .= substr($pivot['info'], 0, 7) . '...';				
			} else {
				$text .= $pivot['info'];
			}
			
			// Colour the text white if it is a highlighted pivot element
			$pivotType = 'pivotText';
			$pivotSpanType = '';
			if ($activeText) {
				$pivotType = 'pivotTextBlue';
				$pivotSpanType = 'pivotSpanBlue';
			}
			
			$data[] = '<span class ="'.$pivotSpanType.'">';
			if ($pivot['deletable']) {
				$data[] = '<a class="pivotDelete icon-remove" href="/events/removePivot/' . $pivot['id'] . '/' . $currentEvent . '"></a>';
			}
			$data[] = '<a class="' . $pivotType . '" href="/events/view/' . $pivot['id'] . '/1/' . $currentEvent . '" title="' . h($pivot['info']) . ' (' . $pivot['date'] . ')">' . h($text) . '</a>';
			$data[] = '</span>';
			if (!empty($pivot['children'])) {
				foreach ($pivot['children'] as $k => $v) {
					$extra = '';
					if ($v['id'] == $currentEvent) {
						$active = ' activePivot';
					}
					if ($k > 0) {
						$pixelDifference = $pivot['children'][$k]['height'] - $pivot['children'][$k-1]['height'];
						$lineDifference = $pixelDifference / 50;
						$extra = ' distance' . $lineDifference;
					}
					$data[] = '<div class="pivotElement' . $extra . $active . '" style="top:' . $pivot['children'][$k]['height'] . 'px;">';
					if ($active != '') $temp = $this->__doConvert($v, $currentEvent, true);
					else $temp = $this->__doConvert($v, $currentEvent);
					$data = array_merge($data, $temp);
					$data[] = '</div>';
					$active = '';
				}
			}
			return $data;
		}
		
		public function convertPivotToHTML($pivot, $currentEvent) {
			$lookingAtRoot = false;
			$pivotType = '';
			if ($pivot['id'] == $currentEvent) {
				$lookingAtRoot = true;
				$pivotType = ' activePivot';
			}
			$temp = $this->__doConvert($pivot, $currentEvent, $lookingAtRoot);
			$height = $this->__findMaxHeight($pivot);
			$height = $height + 50;
			$data = array('<div class="pivotElement firstPivot ' . $pivotType . '" style="height:' . $height . 'px;">');
			$data = array_merge($data, $temp);
			$data = array_merge($data, array('</div>'));
			foreach ($data as $k => $v) {
				echo ($v);
			}		
		}

		private function __findMaxHeight($pivot) {
			$height = $pivot['height'];
			$heightToAdd = 0;
			$temp = 0;
			foreach ($pivot['children'] as $k => $v) {
				$temp = $this->__findMaxHeight($v);
				if ($temp > $heightToAdd) $heightToAdd = $temp;
			}
			return $height + $heightToAdd;
		}
	}
	
?>

