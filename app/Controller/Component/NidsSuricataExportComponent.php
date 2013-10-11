<?php

App::uses('NidsExportComponent', 'Controller/Component');


class NidsSuricataExportComponent extends NidsExportComponent {

	public function export($items, $startSid) {
		// set the specific format
		$this->format = 'suricata';
		// call the generic function
		return parent::export(&$items, $startSid);
	}

	// below overwrite functions from NidsExportComponent

}
