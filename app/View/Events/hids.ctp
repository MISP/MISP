<?php
	if (count($rules) >= 1) {
		foreach ($rules as &$rule)
			echo $rule .  PHP_EOL;
		echo "#" . PHP_EOL;
	} else {
		echo "No exportable " . $type . "s found. " . PHP_EOL;
	}
?>
