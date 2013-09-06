<?php
App::uses('AppHelper', 'View/Helper');

	class PivotHelper extends AppHelper {
		
		private function __doConvert($pivot, $currentEvent) {
			$data = null;
			$text = $pivot['id'] . ': ';
			if (strlen($pivot['info']) > 10) {
				$text .= substr($pivot['info'], 0, 7) . '...';				
			} else {
				$text .= $pivot['info'];
			}
			$data[] = '<span>';
			$data[] = '<a class="pivotDelete icon-remove" href="/events/removePivot/' . $pivot['id'] . '/' . $currentEvent . '"></a>';
			$data[] = '<a class="pivotText" href="/events/view/' . $pivot['id'] . '/1/' . $currentEvent . '" title="' . $pivot['info'] . ' (' . $pivot['date'] . ')">' . $text . '</a>';
			$data[] = '</span>';
			if (!empty($pivot['children'])) {
				foreach ($pivot['children'] as $k => $v) {
					$extra = '';
					if ($k > 0) {
						$pixelDifference = $pivot['children'][$k]['height'] - $pivot['children'][$k-1]['height'];
						$lineDifference = $pixelDifference / 50;
						$extra = ' distance' . $lineDifference;
					}
					$data[] = '<div class="pivotElement' . $extra . '" style="top:' . $pivot['children'][$k]['height'] . 'px;">';
					$temp = $this->__doConvert($v, $currentEvent);
					$data = array_merge($data, $temp);
					$data[] = '</div>';
				}
			}
			return $data;
		}
		
		public function convertPivotToHTML($pivot, $currentEvent) {
			$temp = $this->__doConvert($pivot, $currentEvent);
			$height = $this->__findMaxHeight($pivot);
			$height = $height + 50;
			$data = array('<div class="pivotElement firstPivot" style="height:' . $height . 'px;">');
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

