<div class="confirmation">
<div class="legend"><?php echo __('Accept Delegation Request');?></div>
<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
<p><?php echo __('Are you sure you would like to accept the request by %s to take ownership of Event #%s', h($delegationRequest['RequesterOrg']['name']), h($delegationRequest['Event']['id']));?>?</p>
        <table>
            <tr>
                <td style="vertical-align:top">
                    <?php
                        echo $this->Form->create('EventDelegation', array('style' => 'margin:0px;', 'id' => 'PromptForm'));
                        echo $this->Form->submit(__('Yes'), array('div' => false, 'class' => 'btn btn-primary'));
                        echo $this->Form->end();
                    ?>
                </td>
                <td style="width:540px;">
                </td>
                <td style="vertical-align:top;">
                    <span title="<?php echo __('Cancel');?>" role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" class="btn btn-inverse" id="PromptNoButton" onClick="cancelPrompt();"><?php echo __('No');?></span>
                </td>
            </tr>
        </table>
    </div>
</div>
