<div class="popover_choice">
    <legend><?php echo __('Select Object Attribute To Add');?></legend>
    <div class="popover_choice_main" id ="popover_choice_main">
        <table style="width:100%;">
        <?php foreach ($template['ObjectTemplateElement'] as $objectAttribute): ?>
            <tr style="border-bottom:1px solid black;" class="templateChoiceButton">
                <td role="button" tabindex="0" aria-label="<?php echo h($objectAttribute['object_relation']); ?>" title="<?php echo h($objectAttribute['object_relation']); ?>" style="padding-left:10px;padding-right:10px; text-align:center;width:100%;" onClick="fetchAddObjectAttributeForm(<?php echo h($objectId) . ', \'' . h($objectAttribute['object_relation']) . '\''; ?>)"><?php echo '<strong>' . h($objectAttribute['object_relation']) . '</strong>' . ' :: ' . h($objectAttribute['type']) . '<br>' . h($objectAttribute['description']); ?></td>
            </tr>
        <?php endforeach; ?>
        </table>
    </div>
    <div role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" title="<?php echo __('Cancel');?>" class="templateChoiceButton templateChoiceButtonLast" onClick="cancelPopoverForm();"><?php echo __('Cancel');?></div>
</div>
<script type="text/javascript">
    $(document).ready(function() {
        resizePopoverBody();
    });

    $(window).resize(function() {
        resizePopoverBody();
    });
</script>
