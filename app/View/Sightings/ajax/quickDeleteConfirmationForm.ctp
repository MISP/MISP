<div class="confirmation">
    <?php
        echo $this->Form->create('Sighting', array('style' => 'margin:0px;', 'id' => 'PromptForm', 'url' => '/sightings/quickDelete/' . $id . '/' . urlencode($rawId) . '/' . $context));
    ?>
    <legend><?php echo __('Remove Sighting');?></legend>
    <div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
    <p><?php echo __('Remove sighting (%s)?', h($id));?></p>
        <table>
            <tr>
                <td style="vertical-align:top">
                    <span id="PromptYesButton" role="button" tabindex="0" aria-label="<?php echo __('Remove sighting');?>" title="<?php echo __('Remove sighting');?>" class="btn btn-primary" data-id="<?php echo h($id); ?>" data-rawid="<?php echo h($rawId); ?>" data-context="<?php echo h($context); ?>" onClick="removeSighting(this);"><?php echo __('Yes');?></span>
                </td>
                <td style="width:540px;">
                </td>
                <td style="vertical-align:top;">
                    <span role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" title="<?php echo __('Cancel');?>" class="btn btn-inverse" id="PromptNoButton" onClick="cancelPrompt(1);"><?php echo __('No');?></span>
                </td>
            </tr>
        </table>
    </div>
    <?php
        echo $this->Form->end();
    ?>
</div>
