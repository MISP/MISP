<div style="border:1px solid #dddddd; margin-top:1px; width:95%; padding:10px">
<?php
	if (!$dbEncodingStatus):
?>
		<div style="font-size:12pt;padding-left:3px;width:100%;background-color:red;color:white;font-weight:bold;">Incorrect database encoding setting: Your database connection is currently NOT set to UTF-8. Please make sure to uncomment the 'encoding' => 'utf8' line in <?php echo APP; ?>Config/database.php</div>
<?php
	endif;
?>
	<h3>MISP version</h3>
	<p>Every version of MISP includes a json file with the current version. This is checked against the latest tag on github, if there is a version mismatch the tool will warn you about it. Make sure that you update MISP regularly.</p>
	<div style="background-color:#f7f7f9;width:100%;">
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
					echo $version['current'] . ' (' . h($commit) . ')';
				?>
			</span>
		</span><br />
		<span>Latest available version.....
			<span style="color:<?php echo $fontColour; ?>;">
				<?php
					echo $version['newest'] . ' (' . $latestCommit . ')';
				?>
			</span>
		</span><br />
		<span>Status.....
			<span style="color:<?php echo $fontColour; ?>;">
				<?php
					echo $versionText;
				?>
			</span>
		</span><br />
		<span>Current branch.....
			<?php
				$branchColour = $branch == '2.4' ? 'green' : 'red bold';
			?>
			<span class="<?php echo h($branchColour); ?>">
				<?php
					echo h($branch);
				?>
			</span>
		</span><br />
		<pre class="hidden green bold" id="gitResult"></pre>
		<button title="Pull the latest MISP version from github" class="btn btn-inverse" style="padding-top:1px;padding-bottom:1px;" onClick = "updateMISP();">Update MISP</button>
	</div>
	<h3>Writeable Directories and files</h3>
	<p>The following directories and files have to be writeable for MISP to function properly. Make sure that the apache user has write privileges for the directories below.</p>
	<p><b>Directories</b></p>
	<div style="background-color:#f7f7f9;width:400px;">
		<?php
			foreach ($writeableDirs as $dir => $error) {
				$colour = 'green';
				$message = $writeableErrors[$error];
				if ($error > 0) {
					$message = 'Directory ' . $message;
					$colour = 'red';
				}
				echo $dir . '.....<span style="color:' . $colour . ';">' . $message . '</span><br />';
			}
		?>
	</div>
	<br />
	<p><b>Writeable Files</b></p>
	<div style="background-color:#f7f7f9;width:400px;">
		<?php
			foreach ($writeableFiles as $file => $error) {
				$colour = 'green';
				$message = $writeableErrors[$error];
				if ($error > 0) {
					$message = 'File ' . $message;
					$colour = 'red';
				}
				echo $file . '.....<span style="color:' . $colour . ';">' . $message . '</span><br />';
			}
		?>
	</div>
	<p><b>Readable Files</b></p>
	<div style="background-color:#f7f7f9;width:400px;">
		<?php
			foreach ($readableFiles as $file => $error) {
				$colour = 'green';
				$message = $readableErrors[$error];
				if ($error > 0) {
					$message = 'File ' . $message;
					$colour = 'red';
				}
				echo $file . '.....<span style="color:' . $colour . ';">' . $message . '</span><br />';
			}
		?>
	</div>

	<h3>PHP Settings</h3>
	<?php
		$phpcolour = 'green';
		$phptext = 'Up to date';
		$phpversions = array();
		$phpversions['web']['phpversion'] = $phpversion;
		$phpversions['cli']['phpversion'] = isset($extensions['cli']['phpversion']) ? $extensions['cli']['phpversion'] : false;
		foreach (array('web', 'cli') as $source) {
			if (!$phpversions[$source]['phpversion']) {
				$phpversions[$source]['phpversion'] = 'Unknown';
				$phpversions[$source]['phpcolour'] = 'red';
				$phpversions[$source]['phptext'] = 'Issues determining version';
				continue;
			}
			$phpversions[$source]['phpcolour'] = 'green';
			$phpversions[$source]['phptext'] = 'Up to date';
			if (version_compare($phpversions[$source]['phpversion'], $phprec) < 1) {
				$phpversions[$source]['phpcolour'] = 'orange';
				$phpversions[$source]['phptext'] = 'Update highly recommended';
				if (version_compare($phpversions[$source]['phpversion'], $phpmin) < 1) {
					$phpversions[$source]['phpcolour'] = 'red';
					$phpversions[$source]['phptext'] = 'Version unsupported, update ASAP';
				}
			}
		}
		if (version_compare($phpversion, $phprec) < 1) {
			$phpcolour = 'orange';
			$phptext = 'Update highly recommended';
			if (version_compare($phpversion, $phpmin) < 1) {
				$phpcolour = 'red';
				$phptext = 'Version unsupported, update ASAP';
			}
		}
	?>
	<p><span class="bold">PHP ini path</span>:..... <span class="green"><?php echo h($php_ini); ?></span><br />
	<span class="bold">PHP Version (><?php echo $phprec; ?> recommended): </span><span class="<?php echo $phpversions['web']['phpcolour']; ?>"><?php echo h($phpversions['web']['phpversion']) . ' (' . $phpversions['web']['phptext'] . ')';?></span><br />
	<span class="bold">PHP CLI Version (><?php echo $phprec; ?> recommended): </span><span class="<?php echo $phpversions['cli']['phpcolour']; ?>"><?php echo h($phpversions['cli']['phpversion']) . ' (' . $phpversions['cli']['phptext'] . ')';?></span></p>
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
	<h4>PHP Extensions</h4>
		<?php
			foreach (array('web', 'cli') as $context):
		?>
			<div style="background-color:#f7f7f9;width:400px;">
				<b><?php echo ucfirst(h($context));?></b><br />
				<?php
					if (isset($extensions[$context]['extensions'])):
						foreach ($extensions[$context]['extensions'] as $extension => $status):
				?>
							<?php echo h($extension); ?>:.... <span style="color:<?php echo $status ? 'green' : 'red';?>;font-weight:bold;"><?php echo $status ? 'OK' : 'Not loaded'; ?></span>
				<?php
						endforeach;
					else:
				?>
						<span class="red">Issues reading PHP settings. This could be due to the test script not being readable.</span>
				<?php
					endif;
				?>
			</div><br />
		<?php
			endforeach;
		?>
	<h3>
		Advanced attachment handler
	</h3>
		The advanced attachment tools are used by the add attachment functionality to extract additional data about the uploaded sample.
		<div style="background-color:#f7f7f9;width:400px;">
			<?php
				if (empty($advanced_attachments)):
			?>
					<b>PyMISP</b>:..... <span class="red bold">Not installed or version outdated.</span><br />
			<?php
				endif;
				if (!empty($advanced_attachments)):
					foreach ($advanced_attachments as $k => $v):
			?>
						<b><?php echo h($k); ?></b>:..... <?php echo $v === false ? '<span class="green bold">OK</span>' : '<span class="red bold">' . h($v) . '</span>'; ?><br />
			<?php
					endforeach;
				endif;
			?>
		</div>
	<h3>
	STIX and Cybox libraries
	</h3>
	<p>Mitre's STIX and Cybox python libraries have to be installed in order for MISP's STIX export to work. Make sure that you install them (as described in the MISP installation instructions) if you receive an error below.<br />
	If you run into any issues here, make sure that both STIX and CyBox are installed as described in the INSTALL.txt file. The required versions are:<br /><b>STIX</b>: <?php echo $stix['stix']['expected'];?><br /><b>CyBox</b>: <?php echo $stix['cybox']['expected'];?><br /><b>mixbox</b>: <?php echo $stix['mixbox']['expected'];?><br />
	Other versions might work but are not tested / recommended.</p>
	<div style="background-color:#f7f7f9;width:400px;">
		<?php
			$colour = 'green';
			$testReadError = false;
			foreach ($readableFiles as $file => $data) {
				if (substr($file, -strlen('/stixtest.py')) == '/stixtest.py') {
					if ($data > 0) {
						$colour = 'red';
						echo 'STIX and CyBox.... <span class="red">Could not read test script (stixtest.py).</span>';
						$testReadError = true;
					}
				}
			}
			if (!$testReadError) {
				if ($stix['operational'] == 0) {
					$colour = 'red';
				}
				echo 'STIX and Cybox libraries....<span style="color:' . $colour . ';">' . $stixOperational[$stix['operational']] . '</span><br />';
				if ($stix['operational'] == 1) {
					foreach (array('stix', 'cybox', 'mixbox') as $package) {
						$colour = 'green';
						if ($stix[$package]['status'] == 0) $colour = 'red';
						echo strtoupper($package) . ' library version....<span style="color:' . $colour . ';">' . ${$package . 'Version'}[$stix[$package]['status']] . '</span><br />';
					}
				}
			}
		?>
	</div>
	<h3>
	GnuPG
	</h3>
	<p>This tool tests whether your GnuPG is set up correctly or not.</p>
	<div style="background-color:#f7f7f9;width:400px;">
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
	<div style="background-color:#f7f7f9;width:400px;">
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
		<span class="btn btn-inverse" role="button" tabindex="0" aria-label="Start ZMQ service" title="Start ZeroMQ service" style="padding-top:1px;padding-bottom:1px;" onClick = "zeroMQServerAction('start')">Start</span>
		<span class="btn btn-inverse" role="button" tabindex="0" aria-label="Stop ZeroMQ service" title="Stop ZeroMQ service" style="padding-top:1px;padding-bottom:1px;" onClick = "zeroMQServerAction('stop')">Stop</span>
		<span class="btn btn-inverse" role="button" tabindex="0" aria-label="Check ZeroMQ service status" title="Check ZeroMQ service status" style="padding-top:1px;padding-bottom:1px;" onClick = "zeroMQServerAction('status')">Status</span>
	</div>
	<h3>
	Proxy
	</h3>
	<p>This tool tests whether your HTTP proxy settings are correct.</p>
	<div style="background-color:#f7f7f9;width:400px;">
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
	Module System
	</h3>
	<p>This tool tests the various module systems and whether they are reachable based on the module settings.</p>
	<?php
		foreach ($moduleTypes as $type):
	?>
		<div style="background-color:#f7f7f9;width:400px;">
			<?php
				$colour = 'green';
				if (isset($moduleErrors[$moduleStatus[$type]])) {
					$message = $moduleErrors[$moduleStatus[$type]];
				} else {
					$message = h($moduleStatus[$type]);
				}
				if ($moduleStatus[$type] > 0) {
					$colour = 'red';
				}
				echo $type . ' module system....<span style="color:' . $colour . ';">' . $message . '</span>';
			?>
		</div>
	<?php
		endforeach;
	?>
	<h3>
	Session table
	</h3>
	<p>This tool checks how large your database's session table is. <br />Sessions in CakePHP rely on PHP's garbage collection for cleanup and in certain distributions this can be disabled by default resulting in an ever growing cake session table. <br />If you are affected by this, just click the clean session table button below.</p>
	<div style="background-color:#f7f7f9;width:400px;">
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
	<h3>
		Orphaned attributes
	</h3>
	<p>In some rare cases attributes can remain in the database after an event is deleted becoming orphaned attributes. This means that they do not belong to any event, which can cause issues with the correlation engine (known cases include event deletion directly in the database without cleaning up the attributes and situtations involving a race condition with an event deletion happening before all attributes are synchronised over).</p>
	<div style="background-color:#f7f7f9;width:400px;">
		Orphaned attributes....<span id="orphanedAttributeCount"><span style="color:orange;">Run the test below</span></span>
	</div><br />
	<span class="btn btn-inverse" role="button" tabindex="0" aria-label="Check for orphaned attribute" title="Check for orphaned attributes" style="padding-top:1px;padding-bottom:1px;" onClick="checkOrphanedAttributes();">Check for orphaned attributes</span><br /><br />
	<?php echo $this->Form->postButton('Remove orphaned attributes', $baseurl . '/attributes/pruneOrphanedAttributes', $options = array('class' => 'btn btn-primary', 'style' => 'padding-top:1px;padding-bottom:1px;')); ?>
	<h3>
		Verify PGP keys
	</h3>
	<p>Run a full validation of all PGP keys within this instance's userbase. The script will try to identify possible issues with each key and report back on the results.</p>
	<span class="btn btn-inverse" onClick="location.href='<?php echo $baseurl;?>/users/verifyGPG';">Verify PGP keys</span> (Check whether every user's PGP key is usable)</li>
	<h3>
		Database cleanup scripts
	</h3>
	<p>If you run into an issue with an infinite upgrade loop (when upgrading from version ~2.4.50) that ends up filling your database with upgrade script log messages, run the following script.</p>
	<?php echo $this->Form->postButton('Prune upgrade logs', $baseurl . '/logs/pruneUpdateLogs', $options = array('class' => 'btn btn-primary', 'style' => 'padding-top:1px;padding-bottom:1px;')); ?>
	<h3>
		Legacy Administrative Tools
	</h3>
	<p>Click the following button to go to the legacy administrative tools page. There should in general be no need to do this unless you are upgrading a very old MISP instance (<2.4), all updates are done automatically with more current versions.</p>
	<span class="btn btn-inverse" style="padding-top:1px;padding-bottom:1px;" onClick="location.href = '<?php echo $baseurl; ?>/pages/display/administration';">Legacy Administrative Tools</span>
    <h3>
		Verify bad link on attachments
	</h3>
	<p>Verify each attachment referenced in database is accessible on filesystem.</p>
	<div style="background-color:#f7f7f9;width:400px;">
        Non existing attachments referenced in Database....<span id="orphanedFileCount"><span style="color:orange;">Run the test below</span></span>
    </div><br>
	<span class="btn btn-inverse" role="button" tabindex="0" aria-label="Check bad link on attachments" title="Check bad link on attachments" style="padding-top:1px;padding-bottom:1px;" onClick="checkAttachments();">Check bad link on attachments</span>

</div>
