<div class="confirmation">
    <?php
        echo $this->Form->create('Sighting', array('style' => 'margin:0px;', 'id' => 'PromptForm', 'url' => $baseurl . '/sightings/add/' . $id));
    ?>
    <legend><?php echo __('Add Sighting');?></legend>
    <div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
    <p><?php echo __('Add%s sighting (%s)?', $sighting_type ? ' <strong>' . __('false-positive') . '</strong>' : '' , h($tosight));?></p>
        <table>
            <tr>
                <td style="vertical-align:top">
                    <?php
                        echo $this->Form->input('value', array('type' => 'text', 'style' => 'display:none;', 'label' => false, 'value' => $value));
                        echo $this->Form->input('type', array('type' => 'text', 'style' => 'display:none;', 'label' => false, 'value' => $sighting_type));
                        echo $this->Form->button(__('Yes'), array('type' => 'submit', 'class' => 'btn btn-primary', 'title' => __('Add sighting')));
                    ?>
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
