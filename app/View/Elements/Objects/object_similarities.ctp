<?php
    if ($object['Object']['template_version'] < $template['ObjectTemplate']['version']) {
        $temp_comparison = 'below';
    } else if ($object['Object']['template_version'] > $template['ObjectTemplate']['version']) {
        $temp_comparison = 'above';
    } else {
        $temp_comparison = 'equal';
    }
?>
<div style="border: 1px solid #3465a4 ; border-radius: 5px; margin-top: 15px; display: inline-block; vertical-align: top; float: unset; overflow-x: auto; <?php echo $temp_comparison == 'above' ? 'filter: grayscale(60%);' : ''; ?>" class="span5 similarObjectPanel">
    <?php
    if ($temp_comparison == 'below') {
        $btn_style = 'btn-warning';
        $temp_text = __('Update template and merge');
    } else if ($temp_comparison == 'above') {
        $btn_style = 'btn-danger';
        $temp_text = __('Can\'t merge due to template version');
    } else {
        $temp_text = __('Merge');
        $btn_style = 'btn-success';
    }
    ?>
    <div class="blueElement" style="padding: 4px 5px;">
        <div style="text-align: center;">
            <input type="button" class="btn <?php echo $btn_style; ?>" onclick="<?php echo h($merge_button_functionname); ?>(this)" data-objectid="<?php echo h($object['Object']['id']) ?>" data-updatetemplate="<?php echo $temp_comparison == 'below' ? 'true' : 'false'; ?>" value="<?php echo $temp_text; ?>" <?php echo $temp_comparison == 'above' ? 'disabled' : ''; ?>></input>
            <span class="badge badge-inverse" style="float: right;" title="<?php echo __('Similarity amount') ?>">
                <?php echo number_format(intval($similar_object_similarity_amount[$object['Object']['id']]) / count($data['Attribute']), 2)*100 . '%'; ?>
            </span>
        </div>
        <div>
            <span class="bold"><?php echo __('ID') . ':'; ?></span>
            <a href="<?php echo $baseurl . '/objects/edit/' . h($object['Object']['id']); ?>" style="color: white;"><?php echo h($object['Object']['id']); ?></a>
        </div>
        <div>
            <span class="bold"><?php echo __('Name') . ':'; ?></span>
            <span><?php echo h($object['Object']['name']); ?></span>
        </div>
        <div>
            <span class="bold"><?php echo __('Description') . ':'; ?></span>
            <span><?php echo h($object['Object']['description']); ?></span><br>
        </div>
        <div>
            <span class="bold"><?php echo __('Distribution') . ':'; ?></span>
            <span><?php echo h($object['Object']['distribution']); ?></span>
        </div>
        <?php
            $temp_style = '';
            if ($temp_comparison == 'below') {
                $temp_style .= 'background-color: #fcf8e3; color: black; padding: 2px;';
            } else if ($temp_comparison == 'above') {
                $temp_style .= 'background-color: #bd362f; color: white; padding: 2px;';
            }
        ?>
        <div style="<?php echo $temp_style ?> border-radius: 3px;" data-templatecomparison="<?php echo $temp_comparison; ?>">
            <span class="bold"><?php echo __('Template version') . ':'; ?></span>
            <span><?php echo h($object['Object']['template_version']); ?></span>
        </div>
    </div>
    <?php $flattened_ids_in_similar_object = array(); ?>
    <table class="table table-striped table-condensed" style="margin-bottom: 0px;">
        <tbody>
            <?php foreach ($object['Attribute'] as $attribute): ?>
                <?php
                    $simple_flattened_similar_attribute = h($attribute['object_relation']) . '.' . h($attribute['type']) . '.' .h($attribute['value']);
                    $simple_flattened_similar_attribute_noval = h($attribute['object_relation']) . '.' . h($attribute['type']);
                    $flattened_ids_in_similar_object[$simple_flattened_similar_attribute_noval] = $attribute['id'];
                    $classname = '';
                    $to_highlight = '';
                    $title = '';
                    if (
                        isset($simple_flattened_attribute_noval[$simple_flattened_similar_attribute_noval])
                        && !isset($simple_flattened_attribute[$simple_flattened_similar_attribute])
                        && isset($multiple_attribute_allowed[$attribute['object_relation'] . ':' . $attribute['type']])
                    ) { // Multiple allowed
                        $classname = 'warning';
                        $title = __('This attribute is also contained by the revised object. However, multiple instance is allowed.');
                    } else if (
                        isset($simple_flattened_attribute_noval[$simple_flattened_similar_attribute_noval])
                        && !isset($simple_flattened_attribute[$simple_flattened_similar_attribute])
                    ) { // Not overridable attribute
                        $classname = 'error';
                        $title = __('This attribute is conflicting, manual merge required.');
                        $to_highlight = $simple_flattened_similar_attribute_noval;
                    } else if (
                        !isset($simple_flattened_attribute[$simple_flattened_similar_attribute])
                    ) { // Attribute not present in the revised object
                        $classname = 'info';
                        $title = __('This attribute is contain only by this similar object. It will remain untouched.');
                    } else { // Attributes are basically the same
                        $classname = '';
                        $title = __('This attribute has the same value as the one in the revised object.');
                    }
                ?>
                <tr class="<?php echo $classname ?>" data-tohighlight="<?php echo h($to_highlight); ?>" title="<?php echo $title; ?>">
                    <td style="white-space: nowrap;"><?php echo h($attribute['object_relation']); ?></td>
                    <td><?php echo h($attribute['category']); ?></td>
                    <td><?php echo h($attribute['type']); ?></td>
                    <td><?php echo h($attribute['value']); ?></td>
                </tr>
            <?php endforeach; ?>
            <?php $attribute_ids_to_inject = array_values(array_diff_key($simple_flattened_attribute_noval, $flattened_ids_in_similar_object)); ?>
            <?php if (!empty($attribute_ids_to_inject)): ?>
                <?php foreach ($attribute_ids_to_inject as $i => $attribute_id): ?>
                    <?php $attribute = $data['Attribute'][$attribute_id]; ?>
                    <tr class="success" title="<?php echo __('This attribute will be added to this similar object after the merge.'); ?>" style="<?php echo $i == 0 ? 'border-top: 2px dashed #3465a4' : ''; ?>">
                        <td style="white-space: nowrap;"><?php echo h($attribute['object_relation']); ?></td>
                        <td><?php echo h($attribute['category']); ?></td>
                        <td><?php echo h($attribute['type']); ?></td>
                        <td><?php echo h($attribute['value']); ?></td>
                    </tr>
                <?php endforeach; ?>
            <?php endif; ?>
        </tbody>
    </table>
</div>
