<div class="popover_choice select_tag">
    <legend><?php echo __('Select Tag');?></legend>
    <div style="display:none;">
        <?php
            if (isset($attributeTag)) {
                echo $this->Form->create('Attribute', array('url' => '/attributes/addTag/' . $object_id, 'style' => 'margin:0px;'));
            } else {
                echo $this->Form->create('Event', array('url' => '/events/addTag/' . $object_id, 'style' => 'margin:0px;'));
            }
            echo $this->Form->input('attribute_ids', array('style' => 'display:none;', 'label' => false));
            echo $this->Form->input('tag', array('value' => 0));
            echo $this->Form->end();
        ?>
    </div>
    <div style="text-align:right;width:100%;" class="select_tag_search">
        <input id="filterField" style="width:100%;border:0px;padding:0px;" value="<?php echo h($filterData); ?>" placeholder="<?php echo __('search tags…');?>"/>
    </div>
    <div class="popover_choice_main" id ="popover_choice_main">
        <table style="width:100%;">
        <?php foreach ($options as $k => &$option): ?>
            <tr style="border-top:1px solid black;" class="templateChoiceButton shown" id="field_<?php echo h($k); ?>">
                <?php if (isset($attributeTag)): ?>
                <td style="padding-left:10px;padding-right:10px; text-align:center;width:100%;" onClick="quickSubmitAttributeTagForm('<?php echo h($object_id);?>', '<?php echo h($k); ?>');" title="<?php echo h($expanded[$k]);?>" role="button" tabindex="0" aria-label="Attach tag <?php echo h($option); ?>"><?php echo h($option); ?></td>
                <?php else: ?>
                <td style="padding-left:10px;padding-right:10px; text-align:center;width:100%;" onClick="quickSubmitTagForm('<?php echo h($object_id);?>', '<?php echo h($k); ?>');" title="<?php echo h($expanded[$k]);?>" role="button" tabindex="0" aria-label="<?php echo __('Attach tag');?> <?php echo h($option); ?>"><?php echo h($option); ?></td>
                <?php endif; ?>
            </tr>
        <?php endforeach; ?>
        </table>
    </div>
    <div role="button" tabindex="0" aria-label="<?php echo __('Return to taxonomy selection');?>" class="popover-back useCursorPointer" onClick="getPopup('<?php echo h($object_id); if (isset($attributeTag)) echo '/true'; ?>', 'tags', 'selectTaxonomy');" title="<?php echo __('Select Taxonomy');?>"><?php echo __('Back to Taxonomy Selection');?></div>
    <div role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" class="templateChoiceButton templateChoiceButtonLast" onClick="cancelPopoverForm();"><?php echo __('Cancel');?></div>
</div>
<script type="text/javascript">
    var tags = <?php echo json_encode($options); ?>;
    $(document).ready(function() {
        resizePopoverBody();
        // Places the cursor at the end of the input before focusing
        var filterField = $("#filterField");
        var tempValue = filterField.val();
        filterField.val('');
        filterField.val(tempValue);
        filter();
        filterField.focus();
    });

    function filter() {
        var filterString =  $("#filterField").val().toLowerCase();
        $.each(tags, function(index, value) {
            if (value.toLowerCase().indexOf(filterString) == -1) {
                let element = $('#field_' + index);
                element.hide();
                element.removeClass('shown');
            } else {
                let element = $('#field_' + index);
                element.show();
                element.addClass('shown');
            }
        });
    }

    $('#filterField').keyup(filter);
    $(window).resize(function() {
        resizePopoverBody();
    });
</script>
<?php echo $this->Html->script('tag-selection-keyboard-navigation.js'); ?>