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
                $upToDate = isset($version['upToDate']) ? $version['upToDate'] : null;
                switch ($upToDate) {
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
                        $versionText = __('Could not retrieve version from GitHub');
                }
            ?>
            <span style="color:<?php echo $fontColour; ?>;">
                <?= (isset($version['current']) ? $version['current'] : __('Unknown')) . ' (' . h($commit) . ')';
                ?>
                <?php if ($commit === ''): ?>
                    <br>
                    <span class="red bold apply_css_arrow">
                        <?php echo __('Unable to fetch current commit ID, check apache user read privilege.'); ?>
                    </span>
                <?php endif; ?>
            </span>
        </span><br />
        <span><?php echo __('Latest available version…');?>
            <span style="color:<?php echo $fontColour; ?>;">
                <?= (isset($version['newest']) ? $version['newest'] : __('Unknown')) . ' (' . (isset($latestCommit) ? $latestCommit : __('Unknown')) . ')' ?>
            </span>
        </span><br />
        <span><?php echo __('Status…');?>
            <span style="color:<?php echo $fontColour; ?>;"><?= $versionText ?></span>
        </span><br />
        <span><?php echo __('Current branch…');?>
            <?php
                $branchColour = $branch == '2.4' ? 'green' : 'red bold';
            ?>
            <span class="<?php echo h($branchColour); ?>">
                <?=($branch == '2.4') ? h($branch) : __('You are not on a branch, Update MISP will fail'); ?>
            </span>
        </span><br />
        <pre class="hidden green bold" id="gitResult"></pre>
        <button title="<?php echo __('Pull the latest MISP version from GitHub');?>" class="btn btn-inverse" style="padding-top:1px;padding-bottom:1px;" onClick = "updateMISP();"><?php echo __('Update MISP');?></button>
        <a title="<?php echo __('Click the following button to go to the update progress page. This page lists all updates that are currently queued and executed.'); ?>" style="margin-left: 5px;" href="<?php echo $baseurl; ?>/servers/updateProgress/"><i class="fas fa-tasks"></i> <?php echo __('View Update Progress');?></a>
    </div>
    <h3><?php echo __('Submodules version');?>
        <it id="refreshSubmoduleStatus" class="fas fa-sync useCursorPointer" style="font-size: small; margin-left: 5px;" title="<?php echo __('Refresh submodules version.'); ?>"></it>
    </h3>
    <div id="divSubmoduleVersions" style="background-color:#f7f7f9;"></div>
    <span id="updateAllJson" class="btn btn-inverse" title="<?php echo __('Load all JSON into the database.'); ?>">
        <it class="fas fa-file-upload"></it> <?php echo __("Load JSON into database"); ?>
    </span>

    <h3><?php echo __('Writeable Directories and files');?></h3>
    <p><?php echo __('The following directories and files have to be writeable for MISP to function properly. Make sure that the apache user has write privileges for the directories below.');?></p>
    <p><b><?php echo __('Directories');?></b></p>
    <div class="diagnostics-box">
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
    <div class="diagnostics-box">
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
    <div class="diagnostics-box">
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

    <h3><?= __('Security Audit') ?></h3>
    <?php if (empty($securityAudit)):
        echo __('Congratulation, your instance pass all security checks.');
    else: ?>
    <table class="table table-condensed table-bordered" style="width: 40vw">
        <thead>
        <tr>
            <th><?= __('Area') ?></th>
            <th><?= __('Level') ?></th>
            <th><?= __('Message') ?></th>
        </tr>
        </thead>
        <tbody>
        <?php foreach ($securityAudit as $field => $errors): foreach ($errors as $error): list($level, $message) = $error; ?>
        <tr>
            <?php if (isset($field)): ?><th rowspan="<?= count($errors) ?>" style="white-space: nowrap;"><?= h($field) ?></th><?php unset($field); endif; ?>
            <td style="text-align: center">
                <?php if ($level === 'error'): ?>
                <i class="red fa fa-times" role="img" aria-label="<?= __('Error') ?>" title="<?= __('Error') ?>"></i>
                <?php elseif ($level === 'warning'): ?>
                <i class="fas fa-exclamation-triangle" style="color: #c09853;" role="img" aria-label="<?= __('Warning') ?>" title="<?= __('Warning') ?>"></i>
                <?php elseif ($level === 'hint'): ?>
                <i class="fas fa-lightbulb" style="color: #FCC111" role="img" aria-label="<?= __('Hint') ?>"  title="<?= __('Hint') ?>"></i>
                <?php endif; ?>
            </td>
            <td><?= h($message) ?><?php if (isset($error[2])): ?> <a href="<?= h($error[2]) ?>"><?= __('More info') ?></a><?php endif; ?></td>
        </tr>
        <?php endforeach; endforeach; ?>
        </tbody>
    </table>
    <?php endif; ?>

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
            if (version_compare($phpversions[$source]['phpversion'], $phprec) < 0) {
                $phpversions[$source]['phpcolour'] = 'orange';
                $phpversions[$source]['phptext'] = __('Update highly recommended');
                if (version_compare($phpversions[$source]['phpversion'], $phpmin) < 0) {
                    $phpversions[$source]['phpcolour'] = 'red';
                    $phpversions[$source]['phptext'] = __('Version unsupported, update ASAP');
                }
            }
            if (version_compare($phpversions[$source]['phpversion'], $phptoonew) >= 0) {
                $phpversions[$source]['phpcolour'] = 'red';
                $phpversions[$source]['phptext'] = __('Version unsupported, 8.x support not available yet.');
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
            echo $settingName . ' (<b>' . $phpSetting['value'] . ($phpSetting['unit'] ? ' ' . $phpSetting['unit'] : '') . '</b>' .')' . '…';
            if ($phpSetting['value'] < $phpSetting['recommended']) $pass = false;
            else $pass = true;
    ?>
    <span style="color:<?php echo $pass ? 'green': 'orange'; ?>"><?php echo $pass ? __('OK') : __('Low'); ?> (recommended: <?php echo strval($phpSetting['recommended']) . ($phpSetting['unit'] ? ' ' . $phpSetting['unit'] : '') . ')'; ?></span><br>
    <?php
        endforeach;
    ?>
    <h4><?= __('PHP Extensions') ?></h4>
    <table class="table table-condensed table-bordered" style="width: 40vw">
        <thead>
            <tr>
                <th><?= __('Extension') ?></th>
                <th><?= __('Required') ?></th>
                <th><?= __('Why to install') ?></th>
                <th><?= __('Web') ?></th>
                <th><?= __('CLI') ?></th>
            </tr>
        </thead>
        <tbody>
        <?php foreach ($extensions['extensions'] as $extension => $info): ?>
        <tr>
            <td class="bold"><?= h($extension) ?></td>
            <td><?= $info['required'] ? '<i class="black fa fa-check" role="img" aria-label="' .  __('Yes') . '"></i>' : '<i class="black fa fa-times" role="img" aria-label="' .  __('No') . '"></i>' ?></td>
            <td><?= $info['info'] ?></td>
            <?php foreach (['web', 'cli'] as $type): ?>
            <td><?php
                $version = $info["{$type}_version"];
                $outdated = $info["{$type}_version_outdated"];
                if ($version && !$outdated) {
                    echo '<i class="green fa fa-check" role="img" aria-label="' .  __('Yes') . '"></i> (' . h($version) .')';
                } else {
                    echo '<i class="red fa fa-times" role="img" aria-label="' .  __('No') . '"></i>';
                    if ($outdated) {
                        echo '<br>' . __("Version %s installed, but required at least %s", h($version), h($info['required_version']));
                    }
                }
            ?></td>
            <?php endforeach; ?>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table>

    <div style="width:400px;">
    <?= $this->element('/genericElements/IndexTable/index_table', array(
            'data' => array(
                'data' => $dbDiagnostics,
                'skip_pagination' => 1,
                'max_height' => '400px',
                'fields' => array(
                    array(
                        'name' => __('Table'),
                        'class' => 'bold',
                        'data_path' => 'table'
                    ),
                    array(
                        'name' => __('Used'),
                        'class' => 'align-right short',
                        'header_class' => 'align-right',
                        'data_path' => 'used'
                    ),
                    array(
                        'name' => __('Reclaimable'),
                        'data_path' => 'reclaimable',
                        'class' => 'align-right',
                        'header_class' => 'align-right'
                    )
                ),
                'title' => __('SQL database status'),
                'description' => __('Size of each individual table on disk, along with the size that can be freed via SQL optimize. Make sure that you always have at least 3x the size of the largest table in free space in order for the update scripts to work as expected.')
            )
        ));
    ?>
    </div>

    <h4><?php echo __('Schema status');?></h4>
    <div id="schemaStatusDiv" style="width: 70vw; padding-left: 10px;">
        <?= $this->element('/healthElements/db_schema_diagnostic', array(
            'checkedTableColumn' => $dbSchemaDiagnostics['checked_table_column'],
            'dbSchemaDiagnostics' => $dbSchemaDiagnostics['diagnostic'],
            'expectedDbVersion' => $dbSchemaDiagnostics['expected_db_version'],
            'actualDbVersion' => $dbSchemaDiagnostics['actual_db_version'],
            'error' => $dbSchemaDiagnostics['error'],
            'remainingLockTime' => $dbSchemaDiagnostics['remaining_lock_time'],
            'updateFailNumberReached' => $dbSchemaDiagnostics['update_fail_number_reached'],
            'updateLocked' => $dbSchemaDiagnostics['update_locked'],
            'dataSource' => $dbSchemaDiagnostics['dataSource'],
            'columnPerTable' => $dbSchemaDiagnostics['columnPerTable'],
            'dbIndexDiagnostics' => $dbSchemaDiagnostics['diagnostic_index'],
            'indexes' => $dbSchemaDiagnostics['indexes'],
        )); ?>
    </div>

    <h3><?= __("Redis info") ?></h3>
    <div class="diagnostics-box">
        <b><?= __('PHP extension version') ?>:</b> <?= $redisInfo['extensionVersion'] ?: ('<span class="red bold">' . __('Not installed.') . '</span>') ?><br>
        <?php if ($redisInfo['connection']): ?>
        <b><?= __('Redis version') ?>:</b> <?= $redisInfo['redis_version'] ?><br>
        <b><?= __('Memory allocator') ?>:</b> <?= $redisInfo['mem_allocator'] ?><br>
        <b><?= __('Memory usage') ?>:</b> <?= $redisInfo['used_memory_human'] ?>B<br>
        <b><?= __('Peak memory usage') ?>:</b> <?= $redisInfo['used_memory_peak_human'] ?>B<br>
        <b><?= __('Fragmentation ratio') ?>:</b> <?= $redisInfo['mem_fragmentation_ratio'] ?><br>
        <b><?= __('Total system memory') ?>:</b> <?= $redisInfo['total_system_memory_human'] ?>B
        <?php elseif ($redisInfo['extensionVersion']): ?>
        <span class="red bold">Redis is not available. <?= $redisInfo['connection_error'] ?></span>
        <?php endif; ?>
    </div>
    <h3><?php echo __('Advanced attachment handler');?></h3>
        <?php echo __('The advanced attachment tools are used by the add attachment functionality to extract additional data about the uploaded sample.');?>
        <div class="diagnostics-box">
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
    <h3><?= __('Attachment scan module') ?></h3>
    <div class="diagnostics-box">
        <?php if ($attachmentScan['status']): ?>
        <b>Status:</b> <span class="green bold"><?= __('OK') ?></span><br>
        <b>Software</b>: <?= implode(", ", $attachmentScan['software']) ?>
        <?php else: ?>
        <b>Status:</b> <span class="red bold"><?= __('Not available.') ?></span><br>
        <b>Reason:</b> <?= $attachmentScan['error'] ?>
        <?php endif; ?>
    </div>
    <h3><?php echo __('STIX and Cybox libraries');?></h3>
    <p><?php echo __('Mitre\'s STIX and Cybox python libraries have to be installed in order for MISP\'s STIX export to work. Make sure that you install them (as described in the MISP installation instructions) if you receive an error below.');?><br />
    <?php echo __('If you run into any issues here, make sure that both STIX and CyBox are installed as described in the INSTALL.txt file. The required versions are');?>:<br />
    <b>STIX</b>: <?php echo $stix['stix']['expected'];?><br />
    <b>CyBox</b>: <?php echo $stix['cybox']['expected'];?><br />
    <b>mixbox</b>: <?php echo $stix['mixbox']['expected'];?><br />
    <b>maec</b>: <?php echo $stix['maec']['expected'];?><br />
    <b>STIX2</b>: <?php echo $stix['stix2']['expected'];?><br />
    <b>PyMISP</b>: <?php echo $stix['pymisp']['expected'];?><br />
    <?php echo __('Other versions might work but are not tested / recommended.');?></p>
    <div class="diagnostics-box">
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
                foreach (array('stix', 'cybox', 'mixbox', 'maec', 'stix2', 'pymisp') as $package) {
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
    <h3><?php echo __('Yara');?></h3>
    <p><?php echo __('This tool tests whether plyara, the library used by the yara export tool is installed or not.');?></p>
    <div class="diagnostics-box">
        <?php
            $colour = 'green';
            $message = __('OK');
            if ($yaraStatus['operational'] == 0) {
                $colour = 'red';
                $message = __('Invalid plyara version / plyara not installed. Please run pip3 install plyara');
            }
            echo __('plyara library installed') . '…<span style="color:' . $colour . ';">' . $message . '</span>';
        ?>
    </div>

    <h3><?php echo __('GnuPG');?></h3>
    <p><?php echo __('This tool tests whether your GnuPG is set up correctly or not.');?></p>
    <div class="diagnostics-box">
        <?php
            $message = $gpgErrors[$gpgStatus['status']];
            $color = $gpgStatus['status'] === 0 ? 'green' : 'red';
            echo __('GnuPG installation and settings') . '…<span style="color:' . $color . '">' . $message . '</span><br>';
            if ($gpgStatus['version']) {
                echo __('GnuPG version: %s', $gpgStatus['version'] ?: __('N/A'));
            }
        ?>
    </div>
    <h3><?php echo __('ZeroMQ');?></h3>
    <p><?php echo __('This tool tests whether the ZeroMQ extension is installed and functional.');?></p>
    <div class="diagnostics-box">
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
    <div class="diagnostics-box">
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
    <div class="diagnostics-box">
    <?php
        foreach ($moduleTypes as $type) {
            $colour = 'red';
            if (isset($moduleErrors[$moduleStatus[$type]])) {
                $message = $moduleErrors[$moduleStatus[$type]];
            } else {
                $message = h($moduleStatus[$type]);
            }
            if ($moduleStatus[$type] === 0) {
                $colour = 'green';
            }
            echo $type . __(' module system') . '…<span style="color:' . $colour . ';">' . $message . '</span><br>';
        }
    ?>
    </div>

    <h3><?php echo __('Session table');?></h3>
    <p><?php echo __('This tool checks how large your database\'s session table is. <br />Sessions in CakePHP rely on PHP\'s garbage collection for clean-up and in certain distributions this can be disabled by default resulting in an ever growing cake session table. <br />If you are affected by this, just click the clean session table button below.');?></p>
    <div class="diagnostics-box">
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
    <h3><?php echo __('Upgrade authkeys keys to the advanced keys format'); ?><a id="advanced_authkey_update">&nbsp</a></h3>
    <p>
        <?php
            echo __('MISP can store the user API keys either in the clear directly attached to the users, or as of recently, it can generate a list of hashed keys for different purposes. If the latter feature is enabled, it might be useful to move all existing keys over to the new format so that users do not lose access to the system. In order to do so, run the following functionality.');
        ?>
        <?php echo $this->Form->postLink('<span class="btn btn-inverse" style="padding-top:1px;padding-bottom:1px;">' . __('Update Authkeys to advanced Authkeys') . '</span>', $baseurl . '/users/updateToAdvancedAuthKeys', array('escape' => false));?>
    </p>
    <h3><?php echo __('Clean model cache');?></h3>
    <p><?php echo __('If you ever run into issues with missing database fields / tables, please run the following script to clean the model cache.');?></p>
    <?php echo $this->Form->postLink('<span class="btn btn-inverse" style="padding-top:1px;padding-bottom:1px;">' . __('Clean cache') . '</span>', $baseurl . '/events/cleanModelCaches', array('escape' => false));?>
    <?php
        echo sprintf(
            '<h3>%s</h3><p>%s</p><div id="deprecationResults"></div>%s',
            __('Check for deprecated function usage'),
            __('In an effort to identify the usage of deprecated functionalities, MISP has started aggregating the count of access requests to these endpoints. Check the frequency of their use below along with the users to potentially warn about better ways of achieving their goals.'),
            sprintf(
                '<span class="btn btn-inverse" role="button" tabindex="0" aria-label="%s" title="%s" onClick="%s">%s</span>',
                __('View deprecated endpoint usage'),
                __('View deprecated endpoint usage'),
                'queryDeprecatedEndpointUsage();',
                __('View deprecated endpoint usage')
            )
        );
    ?>
    <h3><?php echo __('Orphaned attributes');?></h3>
    <p><?php echo __('In some rare cases attributes can remain in the database after an event is deleted becoming orphaned attributes. This means that they do not belong to any event, which can cause issues with the correlation engine (known cases include event deletion directly in the database without cleaning up the attributes and situations involving a race condition with an event deletion happening before all attributes are synchronised over).');?></p>
    <div class="diagnostics-box">
        <?php echo __('Orphaned attributes');?>…<span id="orphanedAttributeCount"><span style="color:orange;"><?php echo __('Run the test below');?></span></span>
    </div><br />
    <span class="btn btn-inverse" role="button" tabindex="0" aria-label="<?php echo __('Check for orphaned attribute');?>" title="<?php echo __('Check for orphaned attributes');?>" style="padding-top:1px;padding-bottom:1px;" onClick="checkOrphanedAttributes();"><?php echo __('Check for orphaned attributes');?></span><br /><br />
    <?php echo $this->Form->postButton(__('Remove orphaned attributes'), $baseurl . '/attributes/pruneOrphanedAttributes', $options = array('class' => 'btn btn-primary', 'style' => 'padding-top:1px;padding-bottom:1px;')); ?>
    <?php echo $this->Form->postButton(__('Remove published empty events'), $baseurl . '/events/cullEmptyEvents', $options = array('class' => 'btn btn-primary', 'style' => 'padding-top:1px;padding-bottom:1px;')); ?>
    <h3><?php echo __('Administrator On-demand Action');?></h3>
    <p><?php echo __('Click the following button to go to the Administrator On-demand Action page.');?></p>
    <span class="btn btn-inverse" style="padding-top:1px;padding-bottom:1px;" onClick="location.href = '<?php echo $baseurl; ?>/servers/ondemandAction/';"><?php echo __('Administrator On-demand Action');?></span>
    <h3><?php echo __('Legacy Administrative Tools');?></h3>
    <p><?php echo __('Click the following button to go to the legacy administrative tools page. There should in general be no need to do this unless you are upgrading a very old MISP instance (<2.4), all updates are done automatically with more current versions.');?></p>
    <span class="btn btn-inverse" style="padding-top:1px;padding-bottom:1px;" onClick="location.href = '<?php echo $baseurl; ?>/pages/display/administration';"><?php echo __('Legacy Administrative Tools');?></span>
    <h3><?php echo __('Verify bad link on attachments');?></h3>
    <p><?php echo __('Verify each attachment referenced in database is accessible on filesystem.');?></p>
    <div class="diagnostics-box">
        <?php echo __('Non existing attachments referenced in Database');?>…<span id="orphanedFileCount"><span style="color:orange;"><?php echo __('Run the test below');?></span></span>
    </div><br>
    <span class="btn btn-inverse" role="button" tabindex="0" aria-label="<?php echo __('Check bad link on attachments');?>" title="<?php echo __('Check bad link on attachments');?>" style="padding-top:1px;padding-bottom:1px;" onClick="checkAttachments();"><?php echo __('Check bad link on attachments');?></span>
    <h3><?php echo __('Recover deleted events'); ?></h3>
    <p><?php echo __('Due to a bug introduced after 2.4.129, users could occasionally accidentally and unknowingly trigger event deletions. Use the tool below to display any events deleted during the timeframe when the bug was active and optionally recover individual events if you believe they were removed in error.')?></p>
    <span class="btn btn-inverse" role="button" tabindex="0" aria-label="<?php echo __('Recover deleted events');?>" title="<?php echo __('Recover deleted events');?>" style="padding-top:1px;padding-bottom:1px;" onClick="location.href = '<?php echo $baseurl; ?>/events/restoreDeletedEvents';"><?php echo __('Recover deleted events');?></span>
</div>

<script>
    $(function() {
        updateSubModulesStatus();
        $('#refreshSubmoduleStatus').click(function() { updateSubModulesStatus(); });
        $('#updateAllJson').click(function() { updateAllJson(); });
    });

    function updateSubModulesStatus(message, job_sent, sync_result) {
        job_sent = job_sent === undefined ? false : job_sent;
        sync_result = sync_result === undefined ? '' : sync_result;
        $('#divSubmoduleVersions').empty().append('<it class="fa fa-spin fa-spinner" style="font-size: large; left: 50%; top: 50%;"></it>');
        $.get('<?php echo $baseurl . '/servers/getSubmodulesStatus/'; ?>', function(html){
            $('#divSubmoduleVersions').html(html);
            if (message !== undefined) {
                $('#submoduleGitResultDiv').show();
                $('#submoduleGitResult').text(message);

                var $clone = $('#submoduleGitResultDiv').clone();
                $clone.find('strong').text('Synchronization result:');
                if (job_sent) {
                    $clone.find('#submoduleGitResult')
                        .html('> Synchronizing DB with <a href="<?php echo $baseurl . '/jobs/index/'; ?>" target="_blank">workers</a>...');
                } else {
                    $clone.find('#submoduleGitResult')
                        .text(sync_result);
                }
                $clone.appendTo($('#submoduleGitResultDiv').parent());
            }
        });
    }
    function updateAllJson() {
        $.ajax({
            url: '<?php echo $baseurl . '/servers/updateJSON/'; ?>',
            type: "get",
            beforeSend: function() {
                $('#submoduleGitResultDiv').show();
                $('#submoduleGitResult').append('<it class="fa fa-spin fa-spinner" style="font-size: large; left: 50%; top: 50%;"></it>');
            },
            success: function(data, statusText, xhr) {
                Object.keys(data).forEach(function(k) {
                    var val = data[k];
                    data[k] = val ? 'Updated' : 'Update failed';
                });
                $('#submoduleGitResult').html(syntaxHighlightJson(data));
            },
            complete: function() {
                $('#submoduleGitResult').find('fa-spinner').remove();
            }
        });
    }
</script>
