<div class="confirmation">
    <?php
    echo $this->Form->create('Event', array('style' => 'margin:0px;', 'id' => 'PromptForm', 'url' => '/events/' . $type . '/' . $id));
    $extraTitle = "";
    if ($type == 'publish') $extraTitle = ' (no email)';
    ?>
    <legend><?php echo __('Publish Event%s', $extraTitle);?></legend>
    <div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
        <?php
            if ($type == 'alert'):
        ?>
                <p><?php echo __('Are you sure this event is complete and everyone should be informed?');?></p>
        <?php
            else:
        ?>
                <p><?php echo __('Publish but do NOT send alert email? Only for minor changes!');?></p>
        <?php
            endif;
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
