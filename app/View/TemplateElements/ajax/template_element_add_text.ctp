<div class="template_element_add_text">
<?php
    echo $this->Form->create('TemplateElementText', array('url' => '/templateElements/add/text/' . $id));
?>
    <legend><?php echo __('Add Text Element To Template'); ?></legend>
    <fieldset>
        <div class="add_attribute_fields">
            <?php
                echo $this->Form->input('name', array(
                        'type' => 'text',
                        'error' => array('escape' => false),
                        'div' => 'input clear',
                        'class' => 'input-xxlarge'
                ));

                echo $this->Form->input('text', array(
                        'type' => 'textarea',
                        'error' => array('escape' => false),
                        'div' => 'input clear',
                                'class' => 'input-xxlarge'
                ));
            ?>
        </div>
    </fieldset>
    <div class="overlay_spacing">
        <table>
            <tr>
            <td style="vertical-align:top">
                <span id="submitButton" title="<?php echo __('Add text description element');?>" class="btn btn-primary" onClick="return submitPopoverForm('<?php echo $id;?>', 'addTextElement');"><?php echo __('Submit');?></span>
            </td>
            <td style="width:540px;">
                <p style="color:red;font-weight:bold;display:none;text-align:center" id="warning-message"><?php echo __('Warning: You are about to share data that is of a classified nature (Attribution / targeting data). Make sure that you are authorised to share this.');?></p>
            </td>
            <td style="vertical-align:top;">
                <span class="btn btn-inverse" id="cancel_attribute_add" onClick="return cancelPopoverForm();"><?php echo __('Cancel');?></span>
            </td>
            </tr>
        </table>
    </div>
    <?php
        echo $this->Form->end();
    ?>
</div>
<script type="text/javascript">
    var fieldsArray = new Array('TemplateElementTextName', 'TemplateElementTextText');
</script>
