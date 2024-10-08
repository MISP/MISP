<div class="freetext">
<?= $this->Form->create('MispAttribute', array('id')); ?>
    <fieldset>
        <legend><?php echo __('Freetext Import Tool'); ?></legend>
        <div class="add_attribute_fields">
        <p><?php echo __('Paste a list of IOCs into the field below for automatic detection.');?></p>
            <?php
            echo $this->Form->hidden('Attribute.event_id');
            echo $this->Form->input('Attribute.value', array(
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
    <?= $this->Form->end(); ?>
</div>

<script type="text/javascript">
$(function() {
    $('#cancel_attribute_add').click(function() {
        cancelPopoverForm();
    });
    $('#AttributeValue').focus();
});
</script>
