<div style="max-width: 1000px; max-height: 800px; overflow-y: auto; min-height: 400px; min-width: 700px;">
    <div>
        <?php echo !empty($selected_types) ? '<strong>' . __('Selected types: ') . '</strong>' : ''; ?>
        <?php foreach ($selected_types as $type): ?>
            <span class="label label-info"><?php echo h($type) ?></span>
        <?php endforeach; ?>
    </div>
<?php if (empty($potential_templates)): ?>
    <?php echo __('No matching Object.'); ?>
<?php else: ?>
    <table id="tableGroupAttributeIntoObject" class="table table-condensed table-hover">
        <thead>
            <tr>
                <th><?php echo __('Template'); ?></th>
                <th><?php echo __('Object name'); ?></th>
                <th><?php echo __('Category'); ?></th>
                <th><?php echo __('Description'); ?></th>
                <th title="<?php echo __('Compatibility or Attribute type missing from the selection'); ?>"><?php echo __('Compatibility'); ?></th>
            </tr>
        </thead>
        <tbody>
        <?php foreach ($potential_templates as $i => $potential_template): ?>
                <tr class="useCursorPointer" style="<?php echo $potential_template['ObjectTemplate']['compatibility'] === true ? '' : 'cursor: not-allowed;' ?>" data-objecttemplateid="<?php echo h($potential_template['ObjectTemplate']['id']); ?>" data-enabled="<?php echo $potential_template['ObjectTemplate']['compatibility'] === true ? 'true' : 'false'; ?>">
                    <td class="ignoreSelection">
                        <a href="<?php echo $baseurl . '/ObjectTemplates/view/' . h($potential_template['ObjectTemplate']['id']) ?>"><?php echo h($potential_template['ObjectTemplate']['id']); ?></a>
                    </td>
                    <td><?php echo h($potential_template['ObjectTemplate']['name']); ?></td>
                    <td><?php echo h($potential_template['ObjectTemplate']['meta-category']); ?></td>
                    <?php
                        $v = h($potential_template['ObjectTemplate']['description']);
                        $v = strlen($v) > 100 ? mb_substr($v, 0, 100) . '&hellip;' : $v;
                    ?>
                    <td style="max-width: 500px;" title="<?php echo h($potential_template['ObjectTemplate']['description']); ?>">
                        <?php echo $v; ?>
                    </td>
                    <?php if ($potential_template['ObjectTemplate']['compatibility'] === true): ?>
                        <td>
                            <i class="fa fa-check" style="font-size: medium;" title="<?php echo __('This Object is compatible for the merge'); ?>"></i>
                            <?php if (!empty($potential_template['ObjectTemplate']['invalidTypes'])): ?>
                                <?php foreach ($potential_template['ObjectTemplate']['invalidTypes'] as $type): ?>
                                    <span class="label label-warning" title="<?php echo __('This Attribute type cannot be part of this Object template. If you merge the selected Attributes into this object, all Attribute having this type will be ignored.'); ?>"><?php echo h($type); ?></span>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </td>
                    <?php else: ?>
                        <td style="max-width: 500px;">
                            <?php foreach ($potential_template['ObjectTemplate']['compatibility'] as $type): ?>
                                <span class="label label-important" title="<?php echo __('This Attribute type is missing from the selection. Add it to the selection to be able to merge the selected Attributes into this Object.'); ?>"><?php echo h($type); ?></span>
                            <?php endforeach; ?>
                            <?php foreach ($potential_template['ObjectTemplate']['invalidTypesMultiple'] as $type): ?>
                                <span class="label" title="<?php echo __('This Attribute type is not allowed to be present multiple time in this Object. Consider only picking one.'); ?>"><?php echo h($type); ?></span>
                            <?php endforeach; ?>
                        </td>
                    <?php endif; ?>
                </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <div id="resultPreview" class="hidden" style="height: calc(100% - 20px);"></div>
<?php endif; ?>
</div>

<script>
    $('#tableGroupAttributeIntoObject > tbody > tr[data-enabled="true"] > td:not(.ignoreSelection)').click(function() {
        var object_template_id = $(this).parent().data('objecttemplateid');
        if (object_template_id !== undefined) {
            var $parentDIV = $('#tableGroupAttributeIntoObject').parent();
            var bb = $parentDIV[0].getBoundingClientRect();
            $parentDIV.css({height: bb.height, width: bb.width});
            $('#tableGroupAttributeIntoObject').toggle('slide');
            $('#resultPreview').show().html('<div style="align-items: center; justify-content: center; display: flex; height: 100%; width: 100%"><i class="fas fa-spinner fa-spin" style="font-size: xx-large;"></i></div>');
            $.get('<?php echo $baseurl . '/objects/groupAttributesIntoObject/' . h($event_id) . '/' ?>' + object_template_id + '/' + getSelected(), function(data) {
                $('#resultPreview').html(data);
            });
        }
    });

    function showObjectProposition() {
        $('#resultPreview').html('');
        $('#tableGroupAttributeIntoObject').toggle('slide', {
            direction: 'left',
        });
        $('#resultPreview').hide();
    }
</script>
