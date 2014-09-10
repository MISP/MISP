<div style="border:1px solid #dddddd; margin-top:1px; width:100%; padding:10px">
	<h3>Writeable Directories</h3>
	<p>The following directories have to be writeable for MISP to function properly. Make sure that the apache user has write privileges for the directories below.</p>
	<div style="background-color:#f7f7f9;width:300px;">
		<?php 
			foreach ($writeableDirs as $dir => $error) {
				$colour = 'green';
				$message = 'OK';
				if ($error > 0) {
					$colour = 'red';
					if ($error == 1) {
						$message = 'Directory doesn\'t exist';
					} else {
						$message = 'Directory is not writeable';
					}
				}
				echo 'app/' . $dir . '.....<span style="color:' . $colour . ';">' . $message . '</span><br />';
			} 
		?>
	</div>
	<h3>
	STIX and Cybox libraries
	</h3>
	<p>Mitre's STIX and Cybox python libraries have to be installed in order for MISP's STIX export to work. Make sure that you install them (as described in the MISP installation instructions) if you receive an error below.</p>
	<div style="background-color:#f7f7f9;width:300px;">
		<?php 
			$colour = 'green';
			$message = 'OK';
			if ($stix == 0) {
				$colour = 'red';
				$message = 'FAIL.';
			}
			echo 'Testing STIX and Cybox libraries....<span style="color:' . $colour . ';">' . $message . '</span>';
		?>
	</div>
	<h3>
	GnuPG
	</h3>
	<p>This tool tests whether your GnuPG is set up correctly or not.</p>
	<div style="background-color:#f7f7f9;width:300px;">
		<?php 
			$colour = 'green';
			$message = 'OK';
			if ($gpgStatus > 0) {
				$colour = 'red';
				switch ($gpgStatus) {
					case 1:
						$message = 'FAIL: settings not set';
						break;
					case 2:
						$message = 'FAIL: bad GnuPG.*';
						break;
					case 3:
						$message = 'FAIL: encrypt failed';
						break;
				}
			}
			echo 'GnuPG installation and settings....<span style="color:' . $colour . ';">' . $message . '</span>';
		?>
	</div>
</div>