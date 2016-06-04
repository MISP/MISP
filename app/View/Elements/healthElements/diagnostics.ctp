<div style="border:1px solid #dddddd; margin-top:1px; width:95%; padding:10px">
	<h3>MISP version</h3>
	<p>Since version 2.3.14, every version of MISP includes a json file with the current version. This is checked against the latest tag on github, if there is a version mismatch the tool will warn you about it. Make sure that you update MISP regularly.</p>
	<div style="background-color:#f7f7f9;width:300px;">
		<span>Currently installed version.....
			<?php

				switch ($version['upToDate']) {
					case 'newer':
						$fontColour = 'orange';
						$versionText = 'Upcoming development version';
						break;
					case 'older':
						$fontColour = 'red';
						$versionText = 'Outdated version';
						break;
					case 'same':
						$fontColour = 'green';
						$versionText = 'OK';
						break;
					default:
						$fontColour = 'red';
						$versionText = 'Could not retrieve version from github';
				}
			?>
			<span style="color:<?php echo $fontColour; ?>;">
				<?php
					echo $version['current'];
				?>
			</span>
		</span><br />
		<span>Latest available version.....
			<span style="color:<?php echo $fontColour; ?>;">
				<?php
					echo $version['newest'];
				?>
			</span>
		</span><br />
		<span>Status.....
			<span style="color:<?php echo $fontColour; ?>;">
				<?php
					echo $versionText;
				?>
			</span>
		</span>
	</div>
	<h3>Writeable Directories and files</h3>
	<p>The following directories and files have to be writeable for MISP to function properly. Make sure that the apache user has write privileges for the directories below.</p>
	<p><b>Directories</b></p>
	<div style="background-color:#f7f7f9;width:300px;">
		<?php
			foreach ($writeableDirs as $dir => $error) {
				$colour = 'green';
				$message = $writeableErrors[$error];
				if ($error > 0) {
					$message = 'Directory ' . $message;
					$colour = 'red';
				}
				echo 'app/' . $dir . '.....<span style="color:' . $colour . ';">' . $message . '</span><br />';
			}
		?>
	</div>
	<br />
	<p><b>Files</b></p>
	<div style="background-color:#f7f7f9;width:300px;">
		<?php
			foreach ($writeableFiles as $file => $error) {
				$colour = 'green';
				$message = $writeableErrors[$error];
				if ($error > 0) {
					$message = 'File ' . $message;
					$colour = 'red';
				}
				echo 'app/' . $file . '.....<span style="color:' . $colour . ';">' . $message . '</span><br />';
			}
		?>
	</div>
	<h3>PHP Settings</h3>
	<p>The following settings might have a negative impact on certain functionalities of MISP with their current and recommended minimum settings. You can adjust these in your php.ini. Keep in mind that the recommendations are not requirements, just recommendations. Depending on usage you might want to go beyond the recommended values.</p>
	<?php
		foreach ($phpSettings as $settingName => &$phpSetting):
			echo $settingName . ' (<span class="bold">' . $phpSetting['value'] . ($phpSetting['unit'] ? $phpSetting['unit'] : '') . '</span>' .')' . '.....';
			if ($phpSetting['value'] < $phpSetting['recommended']) $pass = false;
			else $pass = true;
	?>
	<span style="color:<?php echo $pass ? 'green': 'orange'; ?>"><?php echo $pass ? 'OK' : 'Low'; ?> (recommended: <?php echo strval($phpSetting['recommended']) . ($phpSetting['unit'] ? $phpSetting['unit'] : '') . ')'; ?></span><br />
	<?php
		endforeach;
	?>
	<h3>
	STIX and Cybox libraries
	</h3>
	<p>Mitre's STIX and Cybox python libraries have to be installed in order for MISP's STIX export to work. Make sure that you install them (as described in the MISP installation instructions) if you receive an error below.<br />
	If you run into any issues here, make sure that both STIX and CyBox are installed as described in the INSTALL.txt file. The required versions are:<br /><b>STIX</b>: <?php echo $stix['stix']['expected'];?><br /><b>CyBox</b>: <?php echo $stix['cybox']['expected'];?><br />
	Other versions might work but are not tested / recommended.</p>
	<div style="background-color:#f7f7f9;width:300px;">
		<?php
			$colour = 'green';
			if ($stix['operational'] == 0) $colour = 'red';
			echo 'STIX and Cybox libraries....<span style="color:' . $colour . ';">' . $stixOperational[$stix['operational']] . '</span><br />';
			if ($stix['operational'] == 1) {
				foreach (array('stix', 'cybox') as $package) {
					$colour = 'green';
					if ($stix[$package]['status'] == 0) $colour = 'red';
					echo strtoupper($package) . ' library version....<span style="color:' . $colour . ';">' . ${$package . 'Version'}[$stix[$package]['status']] . '</span><br />';
				}
			}
		?>
	</div>
	<h3>
	GnuPG
	</h3>
	<p>This tool tests whether your GnuPG is set up correctly or not.</p>
	<div style="background-color:#f7f7f9;width:300px;">
		<?php
			$colour = 'green';
			$message = $gpgErrors[$gpgStatus];
			if ($gpgStatus > 0) {
				$colour = 'red';
			}
			echo 'GnuPG installation and settings....<span style="color:' . $colour . ';">' . $message . '</span>';
		?>
	</div>
	<h3>
	ZeroMQ
	</h3>
	<p>This tool tests whether the ZeroMQ extension is installed and functional.</p>
	<div style="background-color:#f7f7f9;width:300px;">
		<?php
			$colour = 'green';
			$message = $zmqErrors[$zmqStatus];
			if ($zmqStatus > 1) {
				$colour = 'red';
			}
			echo 'ZeroMQ settings....<span style="color:' . $colour . ';">' . $message . '</span>';
		?>
	</div>
	<div>
		<span class="btn btn-inverse" style="padding-top:1px;padding-bottom:1px;" onClick = "zeroMQServerAction('start')">Start / Restart</span>
		<span class="btn btn-inverse" style="padding-top:1px;padding-bottom:1px;" onClick = "zeroMQServerAction('stop')">Stop</span>
		<span class="btn btn-inverse" style="padding-top:1px;padding-bottom:1px;" onClick = "zeroMQServerAction('status')">Status</span>
	</div>
	<h3>
	Proxy
	</h3>
	<p>This tool tests whether your HTTP proxy settings are correct.</p>
	<div style="background-color:#f7f7f9;width:300px;">
		<?php
			$colour = 'green';
			$message = $proxyErrors[$proxyStatus];
			if ($proxyStatus > 1) {
				$colour = 'red';
			}
			echo 'Proxy settings....<span style="color:' . $colour . ';">' . $message . '</span>';
		?>
	</div>
	<h3>
	Session table
	</h3>
	<p>This tool checks how large your database's session table is. <br />Sessions in CakePHP rely on PHP's garbage collection for cleanup and in certain distributions this can be disabled by default resulting in an ever growing cake session table. <br />If you are affected by this, just click the clean session table button below.</p>
	<div style="background-color:#f7f7f9;width:300px;">
		<?php
			$colour = 'green';
			$message = $sessionErrors[$sessionStatus];
			$sessionColours = array(0 => 'green', 1 => 'red', 2 => 'orange', 3 => 'red');
			$colour = $sessionColours[$sessionStatus];
			echo 'Expired sessions....<span style="color:' . $colour . ';">' . $sessionCount . ' (' . $message . ')' . '</span>';
		?>
	</div>
	<?php
		if ($sessionStatus < 2):
	?>
	<a href="<?php echo $baseurl;?>/servers/purgeSessions"><span class="btn btn-inverse" style="padding-top:1px;padding-bottom:1px;">Purge sessions</span></a>
	<?php
		endif;
	?>
	<h3>
	Clean model cache
	</h3>
	<p>If you ever run into issues with missing database fields / tables, please run the following script to clean the model cache.</p>
	<?php echo $this->Form->postLink('<span class="btn btn-inverse" style="padding-top:1px;padding-bottom:1px;">Clean cache</span>', $baseurl . '/events/cleanModelCaches', array('escape' => false));?>
</div>
