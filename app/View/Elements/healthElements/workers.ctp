<div style="border:1px solid #dddddd; margin-top:1px; width:100%; padding:10px">
    <?php
        if (!$worker_array['proc_accessible']):
    ?>
        <div style="background-color:red !important;color:white;"><b><?php echo __('Warning');?></b>: <?php echo __('MISP cannot access your /proc directory to check the status of the worker processes, which means that dead workers will not be detected by the diagnostic tool. If you would like to regain this functionality, make sure that the open_basedir directive is not set, or that /proc is included in it.');?></div>
    <?php
        endif;
        foreach ($worker_array as $type => $data):
        if ($type == 'proc_accessible') continue;
        $queueStatusMessage = __("Issues prevent jobs from being processed. Please resolve them below.");
        $queueStatus = false;
        if ($data['ok']) {
            if (!$worker_array['proc_accessible']) {
                $queueStatus = 'N/A';
                $queueStatusMessage = __("Worker started with the correct user, but the current status is unknown.");
            } else {
                $queueStatus = true;
                $queueStatusMessage = __("OK");
            }
        } else if (!empty($data['workers'])) {
            foreach ($data['workers'] as $worker) {
                if ($worker['alive']) {
                    $queueStatus = true;
                    $queueStatusMessage = __("There are issues with the worker(s), but at least one healthy worker is monitoring the queue.");
                }
            }
        }

    ?>
    <h3><?php echo __('Worker type: ') . h($type);?></h3>
    <?php if ($type !== 'scheduler'): ?>
        <span><b><?php echo __('Jobs in the queue: ');?></b>
            <?php
                echo h($data['jobCount']);
                if ($data['jobCount'] > 0) {
                    echo $this->Form->postLink('<span class="icon-trash useCursorPointer"></span>', $baseurl . '/servers/clearWorkerQueue/' . h($type), array('escape' => false, 'inline' => true, 'style' => 'margin-left:2px;'));
                }
            ?>
        </span>
        <p><b><?php echo __('Queue status: ');?></b>
            <?php
                $color = "green";
                if ($queueStatus === 'N/A') $color = "orange";
                if ($queueStatus === false) $color = "red";
                echo '<span class="' . $color . '">' . $queueStatusMessage . '</span>';
            ?>
        </p>
    <?php endif; ?>
    <table class="table table-hover table-condensed" style="border:1px solid #dddddd; margin-top:1px; width:100%; padding:10px">
        <tr>
                <th><?php echo __('Worker PID');?></th>
                <th><?php echo __('User');?></th>
                <th><?php echo __('Worker process');?></th>
                <th><?php echo __('Information');?></th>
                <th><?php echo __('Actions');?></th>
        </tr>
    <?php
        if (empty($data['workers'])):
    ?>
        <tr>
            <td class="shortish" style="background-color:red; color:white;"><?php echo __('N/A');?></td>
            <td class="short" style="background-color:red; color:white;"><?php echo __('N/A');?></td>
            <td style="background-color:red; color:white;"><?php echo __('N/A');?></td>
            <td style="background-color:red; color:white;"><?php echo __('Worker not running!');?></td>
            <td style="background-color:red; color:white;">&nbsp;</td>
        </tr>
    <?php
        else:
            foreach ($data['workers'] as $worker):
                $style = "color:green;";
                $process = __('OK');
                $message = __('The worker appears to be healthy.');
                $icon_modifier = '';
                if (!$worker['correct_user']) {
                    $message = __('The worker was started with a user other than the apache user. MISP cannot check whether the worker is alive or not.');
                    $style = "color:white;background-color:red;";
                    $icon_modifier = ' icon-white';
                    $process = __('Unknown');
                } else if ($worker['alive'] === 'N/A') {
                        $process = __('Unknown');
                        $message = __('Cannot check whether the worker is alive or dead.');
                        $style = "color:white;background-color:orange;";
                        $icon_modifier = ' icon-white';
                } else if (!$worker['alive']) {
                    $process = __('Dead');
                    $message = __('The Worker appears to be dead.');
                    $style = "color:white;background-color:red;";
                    $icon_modifier = ' icon-white';
                }

                $status = '<span style="color:green;">OK</span>';
    ?>
        <tr>
            <td class="shortish" style="<?php echo $style; ?>"><?php echo h($worker['pid']);?></td>
            <td class="short" style="<?php echo $style; ?>"><?php echo h($worker['user']); ?></td>
            <td class="short" style="<?php echo $style; ?>"><?php echo $process; ?></td>
            <td style="<?php echo $style; ?>"><?php echo $message; ?></td>
            <td class="actions short" style="<?php echo $style; ?>">
            <?php
                echo $this->Form->postLink('', '/servers/stopWorker/' . h($worker['pid']), array('class' => 'icon-trash' . $icon_modifier, 'title' => __('Stop (if still running) and remove this worker. This will immediately terminate any jobs that are being executed by it.')));
            ?>
            </td>
        </tr>
    <?php
                endforeach;
            endif;
    ?>
    </table>
    <?php
            echo $this->Form->create('Server', array('url' => '/servers/startWorker/' . h($type)));
            echo $this->Form->button(__('Start a worker'), array('class' => 'btn btn-inverse'));
            echo $this->Form->end();
        endforeach;
    ?>

</div>

<?php echo $this->Form->create('Server', array('url' => '/servers/restartWorkers'));
echo $this->Form->button(__('Restart all workers'), array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
