<div class="confirmation">
    <?php
    echo $this->Form->create('Event', array('style' => 'margin:0px;', 'id' => 'PromptForm', 'url' => $baseurl . '/events/' . $type . '/' . $id));
    $extraTitle = "";
    if ($type == 'publish') $extraTitle = ' (no email)';
    $message = __('Publish Event%s', $extraTitle);
    if ($type === 'unpublish') {
        $message = __('Unpublish Event%s', $extraTitle);
    }
    ?>

    <legend><?php echo $message;?></legend>
    <div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
        <?php
            if ($type == 'alert') {
                echo '<p>' . __('Are you sure this event is complete and everyone should be informed?') . '</p>';
            } else if ($type === 'unpublish') {
                echo '<p>' . __('Are you sure you wish to unpublish the event?') . '</p>';
            } else if ($type === 'publishSightings') {
                echo '<p>' . __('Are you sure you wish publish and synchronise all sightings attached to this event?') . '</p>';
            } else {
                echo '<p>' . __('Publish but do NOT send alert email? Only for minor changes!') . '</p>';
            }
        ?>
        <table>
            <tr>
                <td style="vertical-align:top">
                    <span role="button" tabindex="0" aria-label="<?php echo __('Publish');?>" title="<?php echo __('Publish');?>" id="PromptYesButton" class="btn btn-primary" onClick="submitPublish()"><?php echo __('Yes');?></span>
                </td>
                <td style="width:540px;">
                </td>
                <td style="vertical-align:top;">
                    <span role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" title="<?php echo __('Cancel');?>" class="btn btn-inverse" id="PromptNoButton" onClick="cancelPrompt();"><?php echo __('No');?></span>
                </td>
            </tr>
        </table>
    </div>
    <?php
        echo $this->Form->end();
    ?>
</div>
