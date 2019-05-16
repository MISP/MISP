<div style="max-width: 1000px; max-height: 800px; overflow-y: auto;">
    <table id="tableGroupAttributeIntoObject" class="table table-condensed table-hover">
        <thead>
            <tr>
                <th><?php echo __('Template'); ?></th>
                <th><?php echo __('Object name'); ?></th>
                <th><?php echo __('Category'); ?></th>
                <th><?php echo __('Description'); ?></th>
                <th title="<?php echo __('Compatiblity or Attribute type missing from the selection'); ?>"><?php echo __('Compatiblity'); ?></th>
            </tr>
        </thead>
        <tbody>
        <?php foreach ($potential_templates as $i => $potential_template): ?>
                <tr class="useCursorPointer" data-objecttemplateid="<?php echo h($potential_template['ObjectTemplate']['id']); ?>">
                    <td class="ignoreSelection">
                        <a href="<?php echo $baseurl . '/ObjectTemplates/view/' . h($potential_template['ObjectTemplate']['id']) ?>"><?php echo h($potential_template['ObjectTemplate']['id']); ?></a>
                    </td>
                    <td><?php echo h($potential_template['ObjectTemplate']['name']); ?></td>
                    <td><?php echo h($potential_template['ObjectTemplate']['meta-category']); ?></td>
                    <?php
                        $v = h($potential_template['ObjectTemplate']['description']);
                        $v = strlen($v) > 100 ? substr($v, 0, 100) . '...' : $v;
                    ?>
                    <td style="max-width: 500px;" title="<?php echo h($potential_template['ObjectTemplate']['description']); ?>">
                        <?php echo $v; ?>
                    </td>
                    <?php if ($potential_template['ObjectTemplate']['compatibility'] === true): ?>
                        <td><i class="fa fa-check"></i></td>
                    <?php else: ?>
                        <td style="max-width: 500px;">
                            <?php foreach ($potential_template['ObjectTemplate']['compatibility'] as $type): ?>
                                <span class="label label-important" title="<?php echo __('This Attribute type is missing from the selection. Add it to the selection to be able to merge the selected Attributes into this Object.'); ?>"><?php echo h($type); ?></span>
                            <?php endforeach; ?>
                        </td>
                    <?php endif; ?>
                </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <div id="resultPreview" style="height: 100%;"></div>
</div>

<script>
    $('#tableGroupAttributeIntoObject > tbody > tr > td:not(.ignoreSelection)').click(function() {
        var object_template_id = $(this).parent().data('objecttemplateid');
        if (object_template_id !== undefined) {
            var $parentDIV = $('#tableGroupAttributeIntoObject').parent();
            var bb = $parentDIV[0].getBoundingClientRect();
            $parentDIV.css({height: bb.height, width: bb.width});
            $('#tableGroupAttributeIntoObject').toggle('slide');
            $('#resultPreview').html('<div style="align-items: center; justify-content: center; display: flex; height: 100%; width: 100%"><i class="fas fa-spinner fa-spin" style="font-size: xx-large;"></i></div>');
            $.get('<?php echo $baseurl . '/objects/mergeObjectsFromAttributes/' . h($event_id) . '/' ?>' + object_template_id + '/' + getSelected(), function(data) {
                $('#resultPreview').html(data);
            });
        }
    });

    function showObjectProposition() {
        $('#resultPreview').html('');
        $('#tableGroupAttributeIntoObject').toggle('slide', {
            direction: 'left',
        });
    }
</script>
