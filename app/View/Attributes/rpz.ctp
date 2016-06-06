<?php
	App::uses('RPZExport', 'Export');
	$rpzExport = new RPZExport();
	echo ($rpzExport->export($values, $rpzSettings));
