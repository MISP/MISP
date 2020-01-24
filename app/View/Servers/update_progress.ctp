<?php
if (!$isSiteAdmin) exit();
$completeUpdateRemaining = $updateProgress['complete_update_remaining'];
$towardDbVersion = $updateProgress['toward_db_version'];
$updateLocked = $updateProgress['update_locked'];
$lockRemainingTime = $updateProgress['lock_remaining_time'];
$updateFailNumberReached = $updateProgress['update_fail_number_reached'];
if (!empty($updateProgress['total'])) {
    $percentageFail = floor(count($updateProgress['failed_num']) / $updateProgress['total']*100);
    $percentage = floor(($updateProgress['current']) / $updateProgress['total']*100);
} else {
    $percentage = 100;
    $percentageFail = 0;
}

if (isset($updateProgress['preTestSuccess']) && $updateProgress['preTestSuccess'] === false) {
    $percentage = 0;
    $percentageFail = 100;
}
?>

<?php if (!$ajaxHtml): ?>
<div class="servers form">
<?php endif; ?>

<?php if ($updateLocked): ?>
    <div style="width: 55%;margin: 20px auto;max-width: 1000px;" class="alert alert-danger UpdateLockedContainer">
        <button type="button" class="close" data-dismiss="alert">&times;</button>
        <div style="display:flex;flex-direction: row;justify-content: space-between;">
            <span>
                <?php if ($updateFailNumberReached): ?>
                    <h5 style="margin: 5px 0px; display: inline-block"><?php echo __('Update are locked due to to many update fails'); ?></h5>
                <?php else: ?>
                    <h5 style="margin: 5px 0px; display: inline-block"><?php echo __('Update are locked due to an ongoing update process. Release lock only if you know what you are doing'); ?></h5>
                    <i>(<?php echo sprintf(__('automatically unlock in %smin %ssec'), '<span id="unlock_remaining_time_min">-</span>', '<span id="unlock_remaining_time_sec">-</span>'); ?>)</i>
                <?php endif; ?>
            </span>
            <span>
                <?php
                    echo $this->Form->postButton('<i class="fa fa-lock-open"></i> ' . __('Release update lock'), $baseurl . '/servers/releaseUpdateLock', array(
                        'style' => 'margin: 0px 0px;',
                        'class' => 'btn btn-danger',
                        'escape' => false
                    ));
                ?>
            </span>
        </div>
    </div>
<?php endif; ?>

<?php if ($completeUpdateRemaining != 0): ?>
    <div style="width: 55%;margin: 20px auto;background-color: white;max-width: 1000px;" class="panel-container completeUpdateRemainingContainer">
        <h3>
            <?php echo(__('Complete update progression'));?>
            <span style="float: right;font-size: smaller;"><?php echo(sprintf(__('%s remaining'), $completeUpdateRemaining));?></span>
        </h3>
    </div>
<?php endif; ?>

    <div style="width: 55%;margin: 0 auto;max-width: 1000px;">
        <?php if (count($updateProgress['commands']) > 0): ?>
            <h3><?php echo(sprintf(__('Database Update progress for update %s'), h($towardDbVersion)));?></h3>
            <div class="" style="max-width: 1000px;">

                <div>
                    <h5 style='display: inline-block'>Pre update test status:</h5>
                    <?php
                        $icon = isset($updateProgress['preTestSuccess']) ? ($updateProgress['preTestSuccess'] ? 'fa-check' : 'fa-times') : 'fa-check ';
                    ?>
                        <i class='fa <?php echo($icon); ?>' style="font-size: x-large"></i>
                </div>

                <div class="progress progress-striped" style="max-width: 1000px;">
                    <div id="pb-progress" class="bar" style="font-weight: bold; width: <?php echo h($percentage);?>%;"><?php echo h($percentage);?>%</div>
                    <div id="pb-fail" class="bar" style="width: <?php echo h($percentageFail);?>%; background-color: #ee5f5b;"></div>
                </div>

                <table class="table table-bordered table-stripped updateProgressTable" data-towarddbversion="<?php echo h($towardDbVersion); ?>">
                    <thead>
                        <tr>
                            <th></th>
                            <th>
                                Update command
                                <span id="followUpdateSwitchContainer" style="float:right; display:flex; align-items:center;">
                                </span>
                            </th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach($updateProgress['commands'] as $i => $cmd):
                            if (isset($updateProgress['results'][$i])) {
                                $res = $updateProgress['results'][$i];
                            } else {
                                $res = false;
                            }
                            $rowDone = $i < $updateProgress['current'];
                            $rowCurrent = $i === $updateProgress['current'];
                            $rowFail = in_array($i, $updateProgress['failed_num']);
                            $rowClass = '';
                            $rowIcon =  '<i id="icon-' . $i . '" class="fa"></i>';
                            if ($rowDone) {
                                $rowClass =  'class="alert alert-success"';
                                $rowIcon =  '<i id="icon-' . $i . '" class="fa fa-check-circle"></i>';
                            }
                            if ($rowCurrent && !$rowFail) {
                                $rowClass =  'class="alert alert-info"';
                                $rowIcon =  '<i id="icon-' . $i . '" class="fa fa-cogs"></i>';
                            } else if ($rowFail) {
                                $rowClass =  'class="alert alert-danger"';
                                $rowIcon =  '<i id="icon-' . $i . '" class="fa fa-times-circle"></i>';
                            }

                            if (isset($updateProgress['time']['started'][$i])) {
                                $datetimeStart = $updateProgress['time']['started'][$i];
                                if (isset($updateProgress['time']['elapsed'][$i])) {
                                    $updateDuration = $updateProgress['time']['elapsed'][$i];
                                } else { // compute elapsed based on started
                                    $temp = new DateTime();
                                    $diff = $temp->diff(new DateTime($datetimeStart));
                                    $updateDuration = $diff->format('%H:%I:%S');
                                }
                            } else {
                                $datetimeStart = '';
                                $updateDuration = '';
                            }
                        ?>
                            <tr id="row-<?php echo $i; ?>" <?php echo $rowClass; ?> >
                                <td><?php echo $rowIcon; ?></td>
                                <td>
                                    <div>
                                        <a style="cursor: pointer; maring-bottom: 2px;" onclick="toggleVisiblity(<?php echo $i;?>)">
                                            <span class="foldable fa fa-terminal"></span>
                                            <?php echo __('Update ') . ($i+1); ?>
                                            <span class="inline-term"><?php echo h(substr($cmd, 0, 60)) . (strlen($cmd) > 60 ? '[...]' : '' );?></span>
                                            <span class="label">
                                                <?php echo __('Started @ '); ?>
                                                <span id="startedTime-<?php echo $i; ?>"><?php echo h($datetimeStart); ?></span>
                                            </span>
                                            <span class="label">
                                                <?php echo __('Elapsed Time @ '); ?>
                                                <span id="elapsedTime-<?php echo $i; ?>"><?php echo h($updateDuration); ?></span>
                                            </span>

                                        </a>
                                        <div data-terminalid="<?php echo $i;?>" style="display: none; margin-top: 5px;">
                                            <div id="termcmd-<?php echo $i;?>" class="div-terminal">
                                                <?php
                                                    $temp = preg_replace('/^\n*\s+/', '', $cmd);
                                                    $temp = preg_split('/\s{4,}/m', $temp);
                                                    foreach ($temp as $j => $line) {
                                                        $pad = $j > 0 ? '30' : '0';
                                                        if ($line !== '') {
                                                            echo '<span style="margin-left: ' . $pad . 'px;">' . h($line) . '</span>';
                                                        }
                                                    }
                                                ?>
                                            </div>
                                            <div>
                                                <span class="fa fa-level-up terminal-res-icon"></span>
                                                <div id="termres-<?php echo $i;?>" class="div-terminal terminal-res">
                                                    <?php
                                                        if ($res !== false) {
                                                            $temp = preg_replace('/^\n*\s+/', '', $res);
                                                            $temp = preg_split('/\s{2,}/m', $temp);
                                                            foreach ($temp as $j => $line) {
                                                                $pad = $j > 0 ? '30' : '0';
                                                                if ($line !== '') {
                                                                    echo '<span style="margin-left: ' . $pad . 'px;">' . h($line) . '</span>';
                                                                }
                                                            }
                                                        }
                                                    ?>
                                                </div>
                                            </div>
                                        </div>
                                    </div>

                                    <div id="single-update-progress-<?php echo $i;?>" class="single-update-progress hidden">
                                        <div class="small-pb-in-td">
                                            <div id="single-update-pb-<?php echo $i;?>" class="single-update-pb"></div>
                                        </div>

                                        <div id="small-state-text-<?php echo $i;?>" class="small-state-text-in-td badge" class="badge">Filling schema table</div>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
        </div>
        <?php else: ?>
            <h2><?php echo __('No update in progress'); ?></h2>
        <?php endif; ?>
    </div>
<?php if (!$ajaxHtml): ?>
</div>
<?php 
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'admin', 'menuItem' => 'updateProgress'));
    echo $this->element('genericElements/assetLoader', array(
        'css' => array('update_progress', 'taskScheduler'),
        'js' => array('update_progress', 'taskScheduler')
    ));
endif; ?>

<?php
if (!$ajaxHtml) {
}
?>

<script>
    var updateProgress = <?php echo json_encode($updateProgress); ?>;
    var urlGetProgress = "<?php echo $baseurl; ?>/servers/updateProgress";
    var checkboxLabel = "<?php echo __('Follow updates'); ?>";
    $(document).ready(function() {
        var lockRemainingTimeSeconds = "<?php echo h($lockRemainingTime); ?>";
        var timer = setInterval(function() {
            lockRemainingTimeSeconds--;
            var parsedTime = parseRemainingTime(lockRemainingTimeSeconds)
            $('#unlock_remaining_time_min').text(parsedTime.mins);
            $('#unlock_remaining_time_sec').text(parsedTime.secs);
        }, 1000);
    });

    function parseRemainingTime(seconds) {
        return {
            days : Math.floor(seconds / (60 * 60 * 24)),
            hours: Math.floor((seconds % (60 * 60 * 24)) / (60 * 60)),
            mins : Math.floor((seconds % (60 * 60)) / (60)),
            secs : Math.floor((seconds % (60))),
        };
    }
</script>
