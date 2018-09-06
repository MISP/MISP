<div style="border:1px solid #dddddd; margin-top:1px; width:95%; padding:10px">
<?php
    if (!$dbEncodingStatus):
?>
        <div style="font-size:12pt;padding-left:3px;width:100%;background-color:red;color:white;font-weight:bold;"><?php echo __('Incorrect database encoding setting: Your database connection is currently NOT set to UTF-8. Please make sure to uncomment the \'encoding\' => \'utf8\' line in ') . APP; ?>Config/database.php</div>
<?php
    endif;
?>
    <h3><?php echo __('MISP version');?></h3>
    <p><?php echo __('Every version of MISP includes a json file with the current version. This is checked against the latest tag on github, if there is a version mismatch the tool will warn you about it. Make sure that you update MISP regularly.');?></p>
    <div style="background-color:#f7f7f9;width:100%;">
        <span><?php echo __('Currently installed version…');?>
            <?php

                switch ($version['upToDate']) {
                    case 'newer':
                        $fontColour = 'orange';
                        $versionText = __('Upcoming development version');
                        break;
                    case 'older':
                        $fontColour = 'red';
                        $versionText = __('Outdated version');
                        break;
                    case 'same':
                        $fontColour = 'green';
                        $versionText = __('OK');
                        break;
                    default:
                        $fontColour = 'red';
                        $versionText = __('Could not retrieve version from github');
                }
            ?>
            <span style="color:<?php echo $fontColour; ?>;">
                <?php
                    echo $version['current'] . ' (' . h($commit) . ')';
                ?>
            </span>
        </span><br />
        <span><?php echo __('Latest available version…');?>
            <span style="color:<?php echo $fontColour; ?>;">
                <?php
                    echo $version['newest'] . ' (' . $latestCommit . ')';
                ?>
            </span>
        </span><br />
        <span><?php echo __('Status…');?>
            <span style="color:<?php echo $fontColour; ?>;">
                <?php
                    echo $versionText;
                ?>
            </span>
        </span><br />
        <span><?php echo __('Current branch…');?>
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
        <button title="<?php echo __('Pull the latest MISP version from github');?>" class="btn btn-inverse" style="padding-top:1px;padding-bottom:1px;" onClick = "updateMISP();"><?php echo __('Update MISP');?></button>
    </div>
    <h3><?php echo __('Writeable Directories and files');?></h3>
    <p><?php echo __('The following directories and files have to be writeable for MISP to function properly. Make sure that the apache user has write privileges for the directories below.');?></p>
    <p><b><?php echo __('Directories');?></b></p>
    <div style="background-color:#f7f7f9;width:400px;">
        <?php
            foreach ($writeableDirs as $dir => $error) {
                $colour = 'green';
                $message = $writeableErrors[$error];
                if ($error > 0) {
                    $message = __('Directory ') . $message;
                    $colour = 'red';
                }
                echo $dir . '…<span style="color:' . $colour . ';">' . $message . '</span><br />';
            }
        ?>
    </div>
    <br />
    <p><b><?php echo __('Writeable Files');?></b></p>
    <div style="background-color:#f7f7f9;width:400px;">
        <?php
            foreach ($writeableFiles as $file => $error) {
                $colour = 'green';
                $message = $writeableErrors[$error];
                if ($error > 0) {
                    $message = __('File ') . $message;
                    $colour = 'red';
                }
                echo $file . '…<span style="color:' . $colour . ';">' . $message . '</span><br />';
            }
        ?>
    </div>
    <p><b><?php echo __('Readable Files');?></b></p>
    <div style="background-color:#f7f7f9;width:400px;">
        <?php
            foreach ($readableFiles as $file => $error) {
                $colour = 'green';
                $message = $readableErrors[$error];
                if ($error > 0) {
                    $message = __('File ') . $message;
                    $colour = 'red';
                }
                echo $file . '…<span style="color:' . $colour . ';">' . $message . '</span><br />';
            }
        ?>
    </div>

    <h3><?php echo __('PHP Settings');?></h3>
    <?php
        $phpcolour = 'green';
        $phptext = __('Up to date');
        $phpversions = array();
        $phpversions['web']['phpversion'] = $phpversion;
        $phpversions['cli']['phpversion'] = isset($extensions['cli']['phpversion']) ? $extensions['cli']['phpversion'] : false;
        foreach (array('web', 'cli') as $source) {
            if (!$phpversions[$source]['phpversion']) {
                $phpversions[$source]['phpversion'] = __('Unknown');
                $phpversions[$source]['phpcolour'] = 'red';
                $phpversions[$source]['phptext'] = __('Issues determining version');
                continue;
            }
            $phpversions[$source]['phpcolour'] = 'green';
            $phpversions[$source]['phptext'] = __('Up to date');
            if (version_compare($phpversions[$source]['phpversion'], $phprec) < 1) {
                $phpversions[$source]['phpcolour'] = 'orange';
                $phpversions[$source]['phptext'] = __('Update highly recommended');
                if (version_compare($phpversions[$source]['phpversion'], $phpmin) < 1) {
                    $phpversions[$source]['phpcolour'] = 'red';
                    $phpversions[$source]['phptext'] = __('Version unsupported, update ASAP');
                }
            }
        }
        if (version_compare($phpversion, $phprec) < 1) {
            $phpcolour = 'orange';
            $phptext = __('Update highly recommended');
            if (version_compare($phpversion, $phpmin) < 1) {
                $phpcolour = 'red';
                $phptext = __('Version unsupported, update ASAP');
            }
        }
    ?>
    <p><span class="bold"><?php echo __('PHP ini path');?></span>:… <span class="green"><?php echo h($php_ini); ?></span><br />
    <span class="bold"><?php echo __('PHP Version');?> (><?php echo $phprec; ?> <?php echo __('recommended');?>): </span><span class="<?php echo $phpversions['web']['phpcolour']; ?>"><?php echo h($phpversions['web']['phpversion']) . ' (' . $phpversions['web']['phptext'] . ')';?></span><br />
    <span class="bold"><?php echo __('PHP CLI Version');?> (><?php echo $phprec; ?> <?php echo __('recommended');?>): </span><span class="<?php echo $phpversions['cli']['phpcolour']; ?>"><?php echo h($phpversions['cli']['phpversion']) . ' (' . $phpversions['cli']['phptext'] . ')';?></span></p>
    <p><?php echo __('The following settings might have a negative impact on certain functionalities of MISP with their current and recommended minimum settings. You can adjust these in your php.ini. Keep in mind that the recommendations are not requirements, just recommendations. Depending on usage you might want to go beyond the recommended values.');?></p>
    <?php
        foreach ($phpSettings as $settingName => &$phpSetting):
            echo $settingName . ' (<span class="bold">' . $phpSetting['value'] . ($phpSetting['unit'] ? $phpSetting['unit'] : '') . '</span>' .')' . '…';
            if ($phpSetting['value'] < $phpSetting['recommended']) $pass = false;
            else $pass = true;
    ?>
    <span style="color:<?php echo $pass ? 'green': 'orange'; ?>"><?php echo $pass ? __('OK') : __('Low'); ?> (recommended: <?php echo strval($phpSetting['recommended']) . ($phpSetting['unit'] ? $phpSetting['unit'] : '') . ')'; ?></span><br />
    <?php
        endforeach;
    ?>
    <h4><?php echo __('PHP Extensions');?></h4>
        <?php
            foreach (array('web', 'cli') as $context):
        ?>
            <div style="background-color:#f7f7f9;width:400px;">
                <b><?php echo ucfirst(h($context));?></b><br />
                <?php
                    if (isset($extensions[$context]['extensions'])):
                        foreach ($extensions[$context]['extensions'] as $extension => $status):
                ?>
                            <?php echo h($extension); ?>:… <span style="color:<?php echo $status ? 'green' : 'red';?>;font-weight:bold;"><?php echo $status ? __('OK') : __('Not loaded'); ?></span>
                <?php
                        endforeach;
                    else:
                ?>
                        <span class="red"><?php echo __('Issues reading PHP settings. This could be due to the test script not being readable.');?></span>
                <?php
                    endif;
                ?>
            </div><br />
        <?php
            endforeach;
        ?>
    <h3><?php echo __('Advanced attachment handler');?></h3>
        <?php echo __('The advanced attachment tools are used by the add attachment functionality to extract additional data about the uploaded sample.');?>
        <div style="background-color:#f7f7f9;width:400px;">
            <?php
                if (empty($advanced_attachments)):
            ?>
                    <b><?php echo __('PyMISP');?></b>:… <span class="red bold"><?php echo __('Not installed or version outdated.');?></span><br />
            <?php
                endif;
                if (!empty($advanced_attachments)):
                    foreach ($advanced_attachments as $k => $v):
            ?>
                        <b><?php echo h($k); ?></b>:… <?php echo $v === false ? '<span class="green bold">' . __('OK') . '</span>' : '<span class="red bold">' . h($v) . '</span>'; ?><br />
            <?php
                    endforeach;
                endif;
            ?>
        </div>
    <h3><?php echo __('STIX and Cybox libraries');?></h3>
    <p><?php echo __('Mitre\'s STIX and Cybox python libraries have to be installed in order for MISP\'s STIX export to work. Make sure that you install them (as described in the MISP installation instructions) if you receive an error below.');?><br />
    <?php echo __('If you run into any issues here, make sure that both STIX and CyBox are installed as described in the INSTALL.txt file. The required versions are');?>:<br />
    <b>STIX</b>: <?php echo $stix['stix']['expected'];?><br />
    <b>CyBox</b>: <?php echo $stix['cybox']['expected'];?><br />
    <b>mixbox</b>: <?php echo $stix['mixbox']['expected'];?><br />
    <b>maec</b>: <?php echo $stix['maec']['expected'];?><br />
    <b>PyMISP</b>: <?php echo $stix['pymisp']['expected'];?><br />
    <?php echo __('Other versions might work but are not tested / recommended.');?></p>
    <div style="background-color:#f7f7f9;width:400px;">
        <?php
            $colour = 'green';
            $testReadError = false;
            foreach ($readableFiles as $file => $data) {
                if (substr($file, -strlen('/stixtest.py')) == '/stixtest.py') {
                    if ($data > 0) {
                        $colour = 'red';
                        echo __('STIX and CyBox') . '… <span class="red">' . __('Could not read test script (stixtest.py).') . '</span>';
                        $testReadError = true;
                    }
                }
            }
            if (!$testReadError) {
                $error_count = 0;
                $libraries = '';
                foreach (array('stix', 'cybox', 'mixbox', 'maec', 'pymisp') as $package) {
                    $lib_colour = 'green';
                    if ($stix[$package]['status'] == 0) {
                        $lib_colour = 'red';
                        $error_count += 1;
                    }
                    $libraries = $libraries . strtoupper($package) . __(' library version') . '…<span style="color:' . $lib_colour . ';">' . ${$package . 'Version'}[$stix[$package]['status']] . '</span><br />';
                }
                if ($stix['operational'] == 0) {
                    $colour = 'red';
                    echo '<b>Current libraries status</b>…<span style="color:' . $colour . ';">' . $stixOperational[$stix['operational']] . '</span><br />';
                } else {
                    if ($error_count > 0) {
                        $colour = 'orange';
                        echo '<b>Current libraries status</b>…<span style="color:' . $colour . ';">Some versions should be updated</span>:<br />';
                    } else {
                        echo '<b>Current libraries status</b>…<span style="color:' . $colour . ';">' . $stixOperational[$stix['operational']] . '</span><br />';
                    }
                }
                echo $libraries;
            }
        ?>
    </div>
    <h3><?php echo __('GnuPG');?></h3>
    <p><?php echo __('This tool tests whether your GnuPG is set up correctly or not.');?></p>
    <div style="background-color:#f7f7f9;width:400px;">
        <?php
            $colour = 'green';
            $message = $gpgErrors[$gpgStatus];
            if ($gpgStatus > 0) {
                $colour = 'red';
            }
            echo __('GnuPG installation and settings') . '…<span style="color:' . $colour . ';">' . $message . '</span>';
        ?>
    </div>
    <h3><?php echo __('ZeroMQ');?></h3>
    <p><?php echo __('This tool tests whether the ZeroMQ extension is installed and functional.');?></p>
    <div style="background-color:#f7f7f9;width:400px;">
        <?php
            $colour = 'green';
            $message = $zmqErrors[$zmqStatus];
            if ($zmqStatus > 1) {
                $colour = 'red';
            }
            echo __('ZeroMQ settings') . '…<span style="color:' . $colour . ';">' . $message . '</span>';
        ?>
    </div>
    <div>
        <span class="btn btn-inverse" role="button" tabindex="0" aria-label="<?php echo __('Start ZMQ service');?>" title="<?php echo __('Start ZeroMQ service');?>" style="padding-top:1px;padding-bottom:1px;" onClick = "zeroMQServerAction('start')"><?php echo __('Start');?></span>
        <span class="btn btn-inverse" role="button" tabindex="0" aria-label="<?php echo __('Stop ZeroMQ service');?>" title="<?php echo __('Stop ZeroMQ service');?>" style="padding-top:1px;padding-bottom:1px;" onClick = "zeroMQServerAction('stop')"><?php echo __('Stop');?></span>
        <span class="btn btn-inverse" role="button" tabindex="0" aria-label="<?php echo __('Check ZeroMQ service status');?>" title="<?php echo __('Check ZeroMQ service status');?>" style="padding-top:1px;padding-bottom:1px;" onClick = "zeroMQServerAction('status')"><?php echo __('Status');?></span>
    </div>
    <h3><?php echo __('Proxy');?></h3>
    <p><?php echo __('This tool tests whether your HTTP proxy settings are correct.');?></p>
    <div style="background-color:#f7f7f9;width:400px;">
        <?php
            $colour = 'green';
            $message = $proxyErrors[$proxyStatus];
            if ($proxyStatus > 1) {
                $colour = 'red';
            }
            echo __('Proxy settings') . '…<span style="color:' . $colour . ';">' . $message . '</span>';
        ?>
    </div>
    <h3><?php echo __('Module System');?></h3>
    <p><?php echo __('This tool tests the various module systems and whether they are reachable based on the module settings.');?></p>
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
                echo $type . __(' module system') . '…<span style="color:' . $colour . ';">' . $message . '</span>';
            ?>
        </div>
    <?php
        endforeach;
    ?>
    <h3><?php echo __('Session table');?></h3>
    <p><?php echo __('This tool checks how large your database\'s session table is. <br />Sessions in CakePHP rely on PHP\'s garbage collection for clean-up and in certain distributions this can be disabled by default resulting in an ever growing cake session table. <br />If you are affected by this, just click the clean session table button below.');?></p>
    <div style="background-color:#f7f7f9;width:400px;">
        <?php
            $colour = 'green';
            $message = $sessionErrors[$sessionStatus];
            $sessionColours = array(0 => 'green', 1 => 'red', 2 => 'orange', 3 => 'red');
            $colour = $sessionColours[$sessionStatus];
            echo __('Expired sessions') . '…<span style="color:' . $colour . ';">' . $sessionCount . ' (' . $message . ')' . '</span>';
        ?>
    </div>
    <?php
        if ($sessionStatus < 2):
    ?>
    <a href="<?php echo $baseurl;?>/servers/purgeSessions"><span class="btn btn-inverse" style="padding-top:1px;padding-bottom:1px;"><?php echo __('Purge sessions');?></span></a>
    <?php
        endif;
    ?>
    <h3><?php echo __('Clean model cache');?></h3>
    <p><?php echo __('If you ever run into issues with missing database fields / tables, please run the following script to clean the model cache.');?></p>
    <?php echo $this->Form->postLink('<span class="btn btn-inverse" style="padding-top:1px;padding-bottom:1px;">' . __('Clean cache') . '</span>', $baseurl . '/events/cleanModelCaches', array('escape' => false));?>
    <h3><?php echo __('Overwritten objects');?></h3>
    <p><?php echo __('Prior to 2.4.89, due to a bug a situation could occur where objects got overwritten on a sync pull. This tool allows you to inspect whether you are affected and if yes, remedy the issue.');?></p>
    <a href="<?php echo $baseurl; ?>/objects/orphanedObjectDiagnostics"><span class="btn btn-inverse">Reconstruct overwritten objects</span></a>
    <h3><?php echo __('Orphaned attributes');?></h3>
    <p><?php echo __('In some rare cases attributes can remain in the database after an event is deleted becoming orphaned attributes. This means that they do not belong to any event, which can cause issues with the correlation engine (known cases include event deletion directly in the database without cleaning up the attributes and situations involving a race condition with an event deletion happening before all attributes are synchronised over).');?></p>
    <div style="background-color:#f7f7f9;width:400px;">
        <?php echo __('Orphaned attributes');?>…<span id="orphanedAttributeCount"><span style="color:orange;"><?php echo __('Run the test below');?></span></span>
    </div><br />
    <span class="btn btn-inverse" role="button" tabindex="0" aria-label="<?php echo __('Check for orphaned attribute');?>" title="<?php echo __('Check for orphaned attributes');?>" style="padding-top:1px;padding-bottom:1px;" onClick="checkOrphanedAttributes();"><?php echo __('Check for orphaned attributes');?></span><br /><br />
    <?php echo $this->Form->postButton(__('Remove orphaned attributes'), $baseurl . '/attributes/pruneOrphanedAttributes', $options = array('class' => 'btn btn-primary', 'style' => 'padding-top:1px;padding-bottom:1px;')); ?>
    <h3><?php echo __('Verify GnuPG keys');?></h3>
    <p><?php echo __('Run a full validation of all GnuPG keys within this instance\'s userbase. The script will try to identify possible issues with each key and report back on the results.');?></p>
    <span class="btn btn-inverse" onClick="location.href='<?php echo $baseurl;?>/users/verifyGPG';"><?php echo __('Verify GnuPG keys');?></span> (<?php echo __('Check whether every user\'s GnuPG key is usable');?>)</li>
    <h3><?php echo __('Database cleanup scripts');?></h3>
    <p><?php echo __('If you run into an issue with an infinite upgrade loop (when upgrading from version ~2.4.50) that ends up filling your database with upgrade script log messages, run the following script.');?></p>
    <?php echo $this->Form->postButton(__('Prune upgrade logs'), $baseurl . '/logs/pruneUpdateLogs', $options = array('class' => 'btn btn-primary', 'style' => 'padding-top:1px;padding-bottom:1px;')); ?>
    <h3><?php echo __('Legacy Administrative Tools');?></h3>
    <p><?php echo __('Click the following button to go to the legacy administrative tools page. There should in general be no need to do this unless you are upgrading a very old MISP instance (<2.4), all updates are done automatically with more current versions.');?></p>
    <span class="btn btn-inverse" style="padding-top:1px;padding-bottom:1px;" onClick="location.href = '<?php echo $baseurl; ?>/pages/display/administration';"><?php echo __('Legacy Administrative Tools');?></span>
    <h3><?php echo __('Verify bad link on attachments');?></h3>
    <p><?php echo __('Verify each attachment referenced in database is accessible on filesystem.');?></p>
    <div style="background-color:#f7f7f9;width:400px;">
        <?php echo __('Non existing attachments referenced in Database');?>…<span id="orphanedFileCount"><span style="color:orange;"><?php echo __('Run the test below');?></span></span>
    </div><br>
    <span class="btn btn-inverse" role="button" tabindex="0" aria-label="<?php echo __('Check bad link on attachments');?>" title="<?php echo __('Check bad link on attachments');?>" style="padding-top:1px;padding-bottom:1px;" onClick="checkAttachments();"><?php echo __('Check bad link on attachments');?></span>

</div>
