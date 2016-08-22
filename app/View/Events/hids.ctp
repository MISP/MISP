<?php
	if (count($rules) >= 1) {
		echo ("#This part is not finished and might be buggy. Please report any issues." . PHP_EOL);

		echo "# " . PHP_EOL;
		foreach ($rules as &$rule)
			echo $rule .  PHP_EOL;
		echo "#" . PHP_EOL;
	} else {
		echo "No exportable " . $type . "s found. " . PHP_EOL;
	}
?>
