<table class="table table-condensed table-bordered table-responsive">
    <thead>
        <tr>
            <th><?php echo __('Submodule'); ?></th>
            <th><?php echo __('Current Version'); ?></th>
            <th><?php echo __('Status'); ?></th>
            <th><?php echo __('Action'); ?>
                <?php
                echo $this->Form->create('Server', array('url' => array('action' => 'updateSubmodule'), 'div' => false, 'style' => 'margin: 0px; display: inline-block;'));
                echo $this->Form->hidden('submodule', array('value' => false));
                echo $this->Form->end();
                echo '<it class="fas fa-sync useCursorPointer" title="' . __('Update all submodules') . '" aria-label="Update all" onclick="submitSubmoduleUpdate(this);"></it>';
                ?>
            </th>
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
                    $versionText .= sprintf(_(' (%s days, %s hours older than super project)'), $status['timeDiff']->format('%d'), $status['timeDiff']->format('%h'));
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
                <td>
                    <?php
                    if ($status['upToDate'] != 'same') {
                        echo $this->Form->create('Server', array('url' => array('action' => 'updateSubmodule'), 'div' => false, 'style' => 'margin: 0px; display: inline-block;'));
                        echo $this->Form->hidden('submodule', array('value' => h($submodule)));
                        echo $this->Form->end();
                        echo '<it class="fas fa-sync useCursorPointer" title="' . __('Update submodule') . '" aria-label="Update" onclick="submitSubmoduleUpdate(this);"></it>';
                    }
                    ?>
                </td>
            </tr>
        <?php endforeach; ?>
    </tbody>
</table>
