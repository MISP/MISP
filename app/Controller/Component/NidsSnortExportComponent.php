<?php

App::uses('NidsExportComponent', 'Controller/Component');


class NidsSnortExportComponent extends NidsExportComponent {

	public function export($items, $startSid, $format = 'suricata') {
		// set the specific format
		$this->format = 'snort';
		// call the generic function
		return parent::export($items, $startSid);
	}

	// below overwrite functions from NidsExportComponent

}
