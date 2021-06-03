<div class="attributes">
<?php
    echo $this->Form->create('Attribute', array('url' => $baseurl . '/attributes/editSelected/' . $id));
?>
    <fieldset>
        <legend><?php echo __('Mass Edit Attributes'); ?></legend>
        <div id="formWarning" class="message ajaxMessage"></div>
        <div class="add_attribute_fields">
            <?php
            echo $this->Form->hidden('event_id', array('value' => $id));
            echo $this->Form->hidden('attribute_ids', array('value' => json_encode($selectedAttributeIds)));
            $distributionLevels[] = __('Do not alter current settings');
            echo $this->Form->input('distribution', array(
                'options' => array($distributionLevels),
                'label' => __('Distribution'),
                'selected' => 6,
            ));
            ?>
                <div id="SGContainer" style="display:none;">
            <?php
                if (!empty($sgs)) {
                    echo $this->Form->input('sharing_group_id', array(
                            'options' => array($sgs),
                            'label' => __('Sharing Group'),
                    ));
                }
            ?>
                </div>
            <?php
            echo $this->Form->input('to_ids', array(
                    'options' => array(__('No'), __('Yes'), __('Do not alter current settings')),
                    'data-content' => isset($attrDescriptions['signature']['formdesc']) ? $attrDescriptions['signature']['formdesc'] : $attrDescriptions['signature']['desc'],
                    'label' => __('For Intrusion Detection System'),
                    'selected' => 2,
            ));
            echo $this->Form->input('is_proposal', array(
                'type' => 'checkbox',
                'label' => __('Create proposals'),
                'checked' => false
            ));
            ?>
                <div class="input clear"></div>

                <div class="input clear"></div>
            <?php
            echo $this->Form->input('comment', array(
                    'type' => 'textarea',
                    'placeholder' => __('Leave this field empty to leave the comment field of the selected attributes unaltered.'),
                    'label' => __('Contextual Comment'),
                    'error' => array('escape' => false),
                    'div' => 'input clear',
                    'class' => 'input-xxlarge'
            ));
            ?>
            <div class="input clear"></div>

            <div class="input clear" data-target="pickerContainerTagRemove">
                <label><span class="fa fa-times-circle" style="margin-right: 5px;"></span><?php echo __('Tags to <b>remove</b>') ?></label>
                <?php echo $this->Form->input('tags_ids_remove', array('style' => 'display:none;', 'label' => false)); ?>
                <?php echo $this->element('generic_picker', array('items' => $tagItemsRemove)); ?>
            </div>
            <div class="input clear" style="margin-top: 20px;" data-target="pickerContainerTagAdd">
                <label><span class="fa fa-plus-circle" style="margin-right: 5px;"></span><?php echo __('Tags to <b>add</b>') ?></label>
                <?php echo $this->Form->input('tags_ids_add', array('style' => 'display:none;', 'label' => false)); ?>
                <?php echo $this->element('generic_picker', array('items' => $tagItemsAdd)); ?>
            </div>

            <div class="input clear" style="margin-top: 20px;" data-target="pickerContainerClusterRemove">
                <label><span class="fa fa-times-circle" style="margin-right: 5px;"></span><?php echo __('Clusters to <b>remove</b>') ?></label>
                <?php echo $this->Form->input('clusters_ids_remove', array('style' => 'display:none;', 'label' => false)); ?>
                <?php echo $this->element('generic_picker', array('items' => $clusterItemsRemove)); ?>
            </div>
            <div class="input clear" style="margin-top: 20px;" data-target="pickerContainerClusterAdd">
                <label><span class="fa fa-plus-circle" style="margin-right: 5px;"></span><?php echo __('Clusters to <b>add</b>') ?></label>
                <?php echo $this->Form->input('clusters_ids_add', array('style' => 'display:none;', 'label' => false)); ?>
                <?php echo $this->element('generic_picker', array('items' => $clusterItemsAdd)); ?>
            </div>
        </div>
    </fieldset>
    <p style="color:red;font-weight:bold;display:none;" id="warning-message"><?php echo __('Warning: You are about to share data that is of a classified nature (Attribution / targeting data). Make sure that you are authorised to share this.'); ?></p>
        <div class="overlay_spacing" style="margin-top: 20px;">
            <table>
                <tr>
                <td style="vertical-align:top">
                    <span id="submitButton" class="btn btn-primary" title="<?php echo __('Submit'); ?>" role="button" tabindex="0" aria-label="<?php echo __('Submit'); ?>" onClick="syncMassEditFormAndSubmit(this)"><?php echo __('Submit'); ?></span>
                </td>
                <td style="width:540px;">&nbsp;</td>
                <td style="vertical-align:top;">
                    <span class="btn btn-inverse" title="<?php echo __('Cancel'); ?>" role="button" tabindex="0" aria-label="<?php echo __('Cancel'); ?>" id="cancel_attribute_add"><?php echo __('Cancel'); ?></span>
                </td>
                </tr>
            </table>
        </div>
    <?php
        echo $this->Form->end();
    ?>
</div>

<script type="text/javascript">

//
// Generate tooltip information
//
var formInfoValues = new Array();
var fieldsArrayAttribute = new Array('AttributeDistribution', 'AttributeComment', 'AttributeToIds');
<?php
foreach ($distributionDescriptions as $type => $def) {
    $info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
    echo "formInfoValues['" . addslashes($type) . "'] = \"" . addslashes($info) . "\";\n";  // as we output JS code we need to add slashes
}
?>
function syncMassEditFormAndSubmit(btn) {
    // tag remove
    var $form = $(btn).closest('form');
    var $input = $form.find('#AttributeTagsIdsRemove');
    var $select = $form.find('div[data-target="pickerContainerTagRemove"] select');
    var val = $select.val();
    val = val !== null && val !== "" && val !== undefined ? val : [];
    $input.val(JSON.stringify(val));
    // tag add
    $input = $form.find('#AttributeTagsIdsAdd');
    $select = $form.find('div[data-target="pickerContainerTagAdd"] select');
    val = $select.val();
    val = val !== null && val !== "" && val !== undefined ? val : [];
    $input.val(JSON.stringify(val));
    // cluster remove
    $input = $form.find('#AttributeClustersIdsRemove');
    $select = $form.find('div[data-target="pickerContainerClusterRemove"] select');
    val = $select.val();
    val = val !== null && val !== "" && val !== undefined ? val : [];
    $input.val(JSON.stringify(val));
    // cluster add
    $input = $form.find('#AttributeClustersIdsAdd');
    $select = $form.find('div[data-target="pickerContainerClusterAdd"] select');
    val = $select.val();
    val = val !== null && val !== "" && val !== undefined ? val : [];
    $input.val(JSON.stringify(val));

    submitPopoverForm('<?php echo $id;?>', 'massEdit');
}

$(function() {
    $('#AttributeDistribution').change(function() {
        if ($('#AttributeDistribution').val() == 4) $('#SGContainer').show();
        else $('#SGContainer').hide();
    });

    $('#AttributeAttributeIds').attr('value', getSelected());

    $("#Attribute, #AttributeDistribution").on('mouseover', function(e) {
        var $e = $(e.target);
        if ($e.is('option')) {
            $('#'+e.currentTarget.id).popover('destroy');
            $('#'+e.currentTarget.id).popover({
                trigger: 'focus',
                placement: 'right',
                container: 'body',
                content: formInfoValues[$e.val()],
            }).popover('show');
        }
    });

    $("input, label").on('mouseleave', function(e) {
        if (e.currentTarget.id) {
            $('#' + e.currentTarget.id).popover('destroy');
        }
    }).on('mouseover', function(e) {
        if (e.currentTarget.id) {
            $('#' + e.currentTarget.id).popover('destroy');
            $('#' + e.currentTarget.id).popover({
                trigger: 'focus',
                placement: 'right',
                container: 'body',
            }).popover('show');
        }
    });

    // workaround for browsers like IE and Chrome that do now have an onmouseover on the 'options' of a select.
    // disadvangate is that user needs to click on the item to see the tooltip.
    // no solutions exist, except to generate the select completely using html.
    $("#Attribute, #AttributeDistribution").on('change', function(e) {
        var $e = $(e.target);
        $('#'+e.currentTarget.id).popover('destroy');
        $('#'+e.currentTarget.id).popover({
            trigger: 'focus',
            placement: 'right',
            container: 'body',
            content: formInfoValues[$e.val()],
        }).popover('show');
    });
    $('#cancel_attribute_add').click(function() {
        $('#gray_out').fadeOut();
        $('#popover_form').fadeOut();
    });
});

</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts
