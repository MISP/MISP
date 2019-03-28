<table class="table table-condensed table-bordered table-responsive">
    <thead>
        <tr>
            <th><?php echo __('Submodule'); ?></th>
            <th><?php echo __('Current Version'); ?></th>
            <th><?php echo __('Status'); ?></th>
        </tr>
    </thead>
    <tbody>
        <?php foreach ($submodules as $submodule => $status): ?>
            <?php
            switch ($status['upToDate']) {
                case 'same':
                    $class = '';
                    $versionText = __('OK');
                    break;
                case 'older':
                    if ($status['timeDiff']->format('%d') > 7) {
                        $class = 'error bold';
                    } else {
                        $class = 'warning';
                    }
                    $versionText = __('Outdated version');
                    $versionText .= sprintf(' (%s days, %s hours)', $status['timeDiff']->format('%d'), $status['timeDiff']->format('%h'));
                    break;
                case 'error':
                    $class = 'error bold';
                    $versionText = __('Could not retrieve version from github');
                    break;
                default:
                    $class = '';
                    $versionText = '';
                    break;
            }
            ?>
            <tr class="<?php echo $class;?>" >
                <td><?php echo h($submodule) ?></td>
                <td><?php echo h($status['current']) ?></td>
                <td><?php echo h($versionText) ?></td>
            </tr>
        <?php endforeach; ?>
    </tbody>
</table>
