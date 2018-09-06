<div class="confirmation">
    <?php
    echo $this->Form->create('Event', array('style' => 'margin:0px;', 'id' => 'PromptForm', 'url' => '/events/toggleCorrelation/' . $event['Event']['id']));
    $extraTitle = "";
    ?>
    <legend><?php echo __('Toggle Correlation %s', $event['Event']['disable_correlation'] ? __('on') : __('off'));?></legend>
    <div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
        <p>
    <?php
        if ($event['Event']['disable_correlation']) {
            echo __('Re-enable the correlation for this event. This will automatically re-correlate all contained attributes.');
        } else {
            echo __('This will remove all correlations that already exist for the event and prevent any events to be related via correlations as long as this setting is disabled. Make sure you understand the downsides of disabling correlations.');
        }
    ?>
    </p>
        <table>
            <tr>
                <td style="vertical-align:top">
                    <span role="button" tabindex="0" aria-label="<?php echo __('Toggle correlation');?>" title="<?php echo __('Toggle correlation');?>" id="PromptYesButton" class="btn btn-primary" onClick="submitPublish();"><?php echo __('Yes');?></span>
                </td>
                <td style="width:540px;">
                </td>
                <td style="vertical-align:top;">
                    <span class="btn btn-inverse" role="button" tabindex="0" aria-label="Cancel" title="Cancel" id="PromptNoButton" onClick="cancelPrompt();"><?php echo __('No');?></span>
                </td>
            </tr>
        </table>
    </div>
    <?php
        echo $this->Form->end();
    ?>
</div>
