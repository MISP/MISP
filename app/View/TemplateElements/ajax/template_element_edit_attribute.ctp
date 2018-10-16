<div class="template_element_add_attribute">
<?php
    echo $this->Form->create('TemplateElementAttribute', array('id', 'url' => '/templateElements/edit/attribute/' . $id));
?>
    <legend><?php echo __('Edit Attribute Element'); ?></legend>
    <fieldset>
        <div id="formWarning" class="message ajaxMessage"></div>
        <div class="add_attribute_fields">
            <?php
                echo $this->Form->input('name', array(
                        'type' => 'text',
                        'error' => array('escape' => false),
                        'div' => 'input clear',
                        'class' => 'input-xxlarge'
                ));

                echo $this->Form->input('description', array(
                        'type' => 'textarea',
                        'error' => array('escape' => false),
                        'div' => 'input clear',
                                'class' => 'input-xxlarge'
                ));
            ?>
                <div class="input clear"></div>
            <?php
                echo $this->Form->input('category', array(
                        'options' => array($categories),
                        'label' => __('Category'),
                        'empty' => __('Select Category')
                ));
            ?>
            <div id='typeToggle'>
                <?php
                    echo $this->Form->input('type', array(
                        'options' => array($initialTypes),
                        'label' => 'Type',
                        'default' => $initialValues['type'],
                    ));
                ?>
            </div>
            <div class="input clear"></div>
            <div id='complexToggle' <?php if (!$initialValues['complex']) echo 'style="display:none;"'; ?> title="<?php echo __('Some categories can use complex types. A complex type can define attributes that can be described by various different types, the system will parse the user\'s entry and determine the most suitable type for the found attributes. The list of valid types for the chosen complex type is shown below.');?>">
                <?php
                    echo $this->Form->input('complex', array(
                            'checked' => $initialValues['complex'],
                            'label' => 'Use complex types',
                    ));
                ?>
            </div>
            <div class="input clear"></div>
            <div id="typeJSON" style="display:none"></div>
            <div class="input clear" style="width:100%;display:none" id="outerTypes">
                <?php echo __('Types allowed based on the above setting');?>:
                <div class="templateTypeContainerInner" id="innerTypes">&nbsp;</div>
            </div>
            <div class="input clear"></div>
            <div title="<?php echo __('When checked, attributes created using this element will automatically be marked for IDSes.');?>">
                <?php
                    echo $this->Form->input('to_ids', array(
                            'label' => __('Automatically mark for IDS'),
                    ));
                ?>
            </div>
            <div class="input clear"></div>
            <div title="<?php echo __('This setting will make this element mandatory.');?>">
                <?php
                    echo $this->Form->input('mandatory', array(
                            'label' => 'Mandatory element',
                    ));
                ?>
            <div>
            <div class="input clear"></div>
            <div title="<?php echo __('If this checkbox is checked, then the resulting field in the form will allow several values to be entered (separated by a linebreak).');?>">
                <?php
                    echo $this->Form->input('batch', array(
                            'label' => __('Batch import element'),
                    ));
                ?>
            </div>
        </div>
    </fieldset>
    <div class="overlay_spacing">
        <table>
            <tr>
            <td style="vertical-align:top">
                <span id="submitButton" aria-label="<?php echo __('Submit attribute element changes');?>" title="<?php echo __('Submit attribute element changes');?>" class="btn btn-primary" onClick="return submitPopoverForm('<?php echo $id;?>', 'editAttributeElement', '<?php echo $template_id; ?>')"><?php echo __('Submit');?></span>
            </td>
            <td style="width:540px;">
                <p style="color:red;font-weight:bold;display:none;text-align:center" id="warning-message"><?php echo __('Warning: You are about to share data that is of a classified nature (Attribution / targeting data). Make sure that you are authorised to share this.');?></p>
            </td>
            <td style="vertical-align:top;">
                <span title="<?php echo __('Cancel');?>" class="btn btn-inverse" id="cancel_attribute_add" onClick="cancelPopoverForm();"><?php echo __('Cancel');?></span>
            </td>
            </tr>
        </table>
    </div>
    <?php
        echo $this->Form->end();
    ?>
</div>
<script type="text/javascript">
    var categoryTypes = new Array();
    var typeGroupCategoryMapping = <?php echo json_encode($typeGroupCategoryMapping); ?>;
    var complexTypes = <?php echo json_encode($validTypeGroups); ?>;
    var currentTypes = new Array();
    if (<?php echo ($initialValues['complex'] == true ? 1 : 0); ?> == 1) {
        currentTypes = complexTypes["<?php echo $initialValues['type']; ?>"]['types'];
    }
    var fieldsArray = new Array('TemplateElementAttributeName', 'TemplateElementAttributeDescription', 'TemplateElementAttributeCategory', 'TemplateElementAttributeToIds', 'TemplateElementAttributeMandatory', 'TemplateElementAttributeBatch', 'TemplateElementAttributeType', 'TemplateElementAttributeComplex');

    $(document).ready(function() {
        <?php
            foreach ($categoryDefinitions as $k => $cat) {
                echo 'categoryTypes[\'' . $k . '\'] = [';
                    foreach ($cat['types'] as $k => $type) {
                        if ($k != 0) echo ', ';
                        echo '"' . $type . '"';
                    }
                echo '];';
            }

            foreach ($typeGroupCategoryMapping as $k => $mapping) {
                echo 'typeGroupCategoryMapping["' . $k . '"] = [';
                foreach ($mapping as $l => $map) {
                    if ($l != 0) echo ', ';
                    echo '"' . $map . '"';
                }
                echo '];';
            }
        ?>
        templateUpdateAvailableTypes();
    });

    $("#TemplateElementAttributeCategory").change(function() {
        var category = $(this).val();
        templateElementAttributeCategoryChange(category);
    });

    $("#TemplateElementAttributeComplex").change(function() {
        populateTemplateTypeDropdown();
        templateUpdateAvailableTypes();
    });

    $("#TemplateElementAttributeType").change(function() {
        templateElementAttributeTypeChange();
    });

</script>
