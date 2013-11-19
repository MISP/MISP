<?php

App::uses('NidsExport', 'Export');

class NidsSnortExport extends NidsExport {

	public function export($items, $startSid, $format = "suricata", $continue = false) {
		// set the specific format
		$this->format = 'snort';
		// call the generic function
		return parent::export($items, $startSid, $format, $continue);
	}

}
