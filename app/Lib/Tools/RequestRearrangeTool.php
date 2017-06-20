<?php
class RequestRearrangeTool {
	public function rearrangeArray($data, $rules) {
		foreach ($rules as $from => $to) {
			if (isset($data[$from])) {
				if ($to !== false) {
					$data[$to] = $data[$from];
					unset($data[$from]);
				} else {
					$data = $data[$from];
				}
			}
		}
		return $data;
	}
}
