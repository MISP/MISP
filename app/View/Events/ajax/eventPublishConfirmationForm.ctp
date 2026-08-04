<div class="confirmation">
    <?php
    echo $this->Form->create('Event', ['style' => 'margin:0px;', 'id' => 'PromptForm', 'url' => $baseurl . '/events/' . $type . '/' . $id]);
    if ($type === 'unpublish') {
        $message = __('Unpublish Event');
        $buttonTitle = __('Unpublish');
    } else {
        $extraTitle = $type === 'publish' ? ' (no email)' : '';
        $message = __('Publish Event%s', $extraTitle);
        $buttonTitle = __('Publish');
    }
    ?>
    <legend><?= $message ?></legend>
    <div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
        <p><?php
            if ($type === 'alert') {
                echo __('Are you sure this event is complete and everyone should be informed?');
            } else if ($type === 'unpublish') {
                echo __('Are you sure you wish to unpublish the event?');
            } else if ($type === 'publishSightings') {
                echo __('Are you sure you wish publish and synchronise all sightings attached to this event?');
            } else {
                echo __('Publish but do NOT send alert email? Only for minor changes!');
            }
        ?></p>
        <?php if (!empty($servers)): ?>
        <details>
            <summary><?= __('Servers') ?></summary>
            <ul>
                <?php foreach ($servers as $serverName => $reason): ?>
                <li><?= h($serverName) ?>: <?= $reason === true ? '<span style="color:green">' . __('Event will be pushed') . '</span>' : h($reason) ?></li>
                <?php endforeach; ?>
            </ul>
        </details>
        <?php endif; ?>
        <table>
            <tr>
                <td style="vertical-align:top">
                    <button role="button" tabindex="0" aria-label="<?= $buttonTitle ?>" title="<?= $buttonTitle ?>" id="PromptYesButton" class="btn btn-primary"><?= __('Yes') ?></button>
                </td>
                <td style="width:540px;">
                </td>
                <td style="vertical-align:top;">
                    <span role="button" tabindex="0" aria-label="<?= __('Cancel');?>" title="<?= __('Cancel');?>" class="btn btn-inverse" id="PromptNoButton" onclick="cancelPrompt()"><?= __('No');?></span>
                </td>
            </tr>
        </table>
    </div>
    <?= $this->Form->end(); ?>
</div>
