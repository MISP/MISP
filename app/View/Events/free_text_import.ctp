<div class="freetext">
<?php
echo $this->Form->create('Attribute', array('id'));
?>
    <fieldset>
        <legend><?php echo __('Freetext Import Tool'); ?></legend>
        <div class="add_attribute_fields">
        <p><?php echo __('Paste a list of IOCs into the field below for automatic detection.');?></p>
            <?php
            echo $this->Form->hidden('event_id');
            echo $this->Form->input('value', array(
                    'type' => 'textarea',
                    'error' => array('escape' => false),
                    'div' => 'input clear',
                    'class' => 'input-xxlarge',
                    'label' => false
            ));
            ?>
            <div class="input clear"></div>
        </div>
    </fieldset>
    <p style="color:red;font-weight:bold;display:none;" id="warning-message"><?php echo __('Warning: You are about to share data that is of a classified nature (Attribution / targeting data). Make sure that you are authorised to share this.');?></p>
        <div class="overlay_spacing">
            <table>
                <tr>
                <td style="vertical-align:top">
                    <button id="submitButton" class="btn btn-primary"><?php echo __('Submit');?></button>
                </td>
                <td style="width:540px;">
                    <p style="color:red;font-weight:bold;display:none;text-align:center" id="warning-message"></p>
                </td>
                <td style="vertical-align:top;">
                    <span class="btn btn-inverse" id="cancel_attribute_add"><?php echo __('Cancel');?></span>
                </td>
                </tr>
            </table>
        </div>
    <?php
        echo $this->Form->end();
    ?>
</div>

<script type="text/javascript">
$(document).ready(function() {
    $('#cancel_attribute_add').click(function() {
        cancelPopoverForm();
    });
});
</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts
