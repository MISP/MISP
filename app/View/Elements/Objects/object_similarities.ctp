<?php
/*
    View that can be used to concisely display an object and potentially highlight differences/similarities with another one

    Required  Args:
        - object => The object to be drawed

    Optional Args:
        - template => The template used to compare the object with

        - attribute_fields => The fields to be displayed.
            Default: [`object_relation`, `category`, `type`, `value`]

        - meta_fields => The fields to be displayed from the object meta.
            Default: [`id`, `name`, `description`, `distribution`, `template_version`]

        - similar_object_similarity_amount => The amount of attributes both contained in `object` and the object to compare to

        - simple_flattened_attribute => array containing the aggregate of multiple fields used for the comparison. Has the format:
                array(
                    'object_relation1.type1.val1' => attribute_id1,
                    'object_relation2.type2.val2' => attribute_id2
                )

        - simple_flattened_attribute_noval => array containing the aggregate of multiple fields used for the comparison without the value. Has the format:
                array(
                    'object_relation1.type1' => attribute_id1,
                    'object_relation2.type2' => attribute_id2
                )

        - merge_button_functionname => If provided, draw a merge button and link the onClick event with the function name

        - target_comparison_object => Will be used to compute `simple_flattened_attribute` and `simple_flattened_attribute_noval` only if they are not provided.
*/

if (!isset($attribute_fields)) {
    $attribute_fields = array('object_relation', 'category', 'type', 'value');
}
if (!isset($meta_fields)) {
    $meta_fields = array('id', 'name', 'description', 'distribution', 'template_version');
}

$flag_comparison_enabled = true;
if (!isset($simple_flattened_attribute_noval) || !isset($simple_flattened_attribute)) {
    if (!isset($simple_flattened_attribute_noval) && !isset($simple_flattened_attribute) && isset($target_comparison_object)) {
        // compute these fields from the provided target object
        $simple_flattened_attribute_noval = array();
        $simple_flattened_attribute = array();
        foreach ($target_comparison_object['Attribute'] as $id => $attribute) {
            $cur_flat = h($attribute['object_relation']) . '.' . h($attribute['type']) . '.' .h($attribute['value']);
            $cur_flat_noval = h($attribute['object_relation']) . '.' . h($attribute['type']);
            $simple_flattened_attribute[$cur_flat] = $id;
            $simple_flattened_attribute_noval[$cur_flat_noval] = $id;
        }
    } else {
        $flag_comparison_enabled = false;
    }
}
?>

<?php
    if (!isset($template) || !isset($object['Object'])) {
        $temp_comparison = 'equal';
    } else if ($object['Object']['template_version'] < $template['ObjectTemplate']['version']) {
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
        $temp_text = __('Review merge');
        $btn_style = 'btn-success';
    }
    ?>
    <?php if (isset($object['Object'])): ?>
        <div class="blueElement" style="padding: 4px 5px;">
            <div style="text-align: center; position: relative;">
                <?php if (isset($merge_button_functionname)): ?>
                    <input type="button" class="btn <?php echo $btn_style; ?>" onclick="<?php echo h($merge_button_functionname); ?>(this)" data-objectid="<?php echo h($object['Object']['id']) ?>" data-updatetemplate="<?php echo $temp_comparison == 'below' ? 'true' : 'false'; ?>" value="<?php echo $temp_text; ?>" <?php echo $temp_comparison == 'above' ? 'disabled' : ''; ?>>
                <?php endif; ?>
                <?php if (isset($similar_object_similarity_amount[$object['Object']['id']])): ?>
                    <span class="badge badge-inverse" style="position: absolute; right: 0;" title="<?php echo __('Similarity amount') ?>">
                        <?php echo number_format(intval($similar_object_similarity_amount[$object['Object']['id']]) / count($data['Attribute']), 2)*100 . '%'; ?>
                    </span>
                <?php endif; ?>
            </div>
            <?php foreach ($meta_fields as $field): ?>
                <?php if (isset($object['Object'][$field])): ?>
                    <?php switch ($field):
                        case 'id': ?>
                            <div>
                                <span class="bold"><?php echo h(Inflector::humanize($field)) . ':'; ?></span>
                                <a href="<?php echo $baseurl . '/objects/edit/' . h($object['Object'][$field]); ?>" style="color: white;"><?php echo h($object['Object'][$field]); ?></a>
                            </div>
                            <?php break; ?>
                        <?php case 'distribution': ?>
                            <div>
                                <span class="bold"><?php echo h(Inflector::humanize($field)) . ':'; ?></span>
                                <span>
                                    <?php
                                        echo h($distributionLevels[$object['Object'][$field]])
                                    ?>
                                </span>
                            </div>
                            <?php break; ?>
                        <?php case 'template_version': ?>
                            <?php
                                $temp_style = '';
                                if ($temp_comparison == 'below') {
                                    $temp_style .= 'background-color: #fcf8e3; color: black; padding: 2px;';
                                } else if ($temp_comparison == 'above') {
                                    $temp_style .= 'background-color: #bd362f; color: white; padding: 2px;';
                                }
                            ?>
                            <div style="<?php echo $temp_style ?> border-radius: 3px;" data-templatecomparison="<?php echo $temp_comparison; ?>" title="<?php echo __('The template version used by this object.'); ?>">
                                <span class="bold"><?php echo h(Inflector::humanize($field)) . ':'; ?></span>
                                <span ><?php echo h($object['Object'][$field]); ?></span>
                            </div>
                            <?php break; ?>
                        <?php default: ?>
                            <div>
                                <span class="bold"><?php echo h(Inflector::humanize($field)) . ':'; ?></span>
                                <span><?php echo h($object['Object'][$field]); ?></span>
                            </div>
                            <?php break; ?>
                    <?php endswitch; ?>
                <?php endif; ?>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
    <?php $flattened_ids_in_similar_object = array(); ?>
    <table class="table table-striped table-condensed" style="margin-bottom: 0px;">
        <tbody>
            <?php foreach ($object['Attribute'] as $attribute): ?>
                <?php
                    $to_highlight = '';
                    $classname = '';
                    $title = '';
                    if ($flag_comparison_enabled) { // Comparison enabled
                        $simple_flattened_similar_attribute = h($attribute['object_relation']) . '.' . h($attribute['type']) . '.' .h($attribute['value']);
                        $simple_flattened_similar_attribute_noval = h($attribute['object_relation']) . '.' . h($attribute['type']);
                        $flattened_ids_in_similar_object[$simple_flattened_similar_attribute_noval] = $attribute['id'];
                        if (
                            isset($simple_flattened_attribute_noval[$simple_flattened_similar_attribute_noval])
                            && !isset($simple_flattened_attribute[$simple_flattened_similar_attribute])
                            && isset($multiple_attribute_allowed[$attribute['object_relation'] . ':' . $attribute['type']])
                        ) { // Multiple allowed
                            $classname = 'warning';
                            $title = __('This attribute is also contained in the revised object. However, as multiple instantiations are allowed by the template, both attributes will be kept.');
                            $to_highlight = $simple_flattened_similar_attribute_noval;
                        } else if (
                            isset($simple_flattened_attribute_noval[$simple_flattened_similar_attribute_noval])
                            && !isset($simple_flattened_attribute[$simple_flattened_similar_attribute])
                        ) { // Not overridable attribute
                            $classname = 'error';
                            $title = __('This attribute is conflicting with the one in the revised object. Manual merge will be required.');
                            $to_highlight = $simple_flattened_similar_attribute_noval;
                        } else if (
                            !isset($simple_flattened_attribute[$simple_flattened_similar_attribute])
                        ) { // Attribute not present in the revised object
                            $classname = 'info';
                            $title = __('This attribute is only contained in this matching object. It will remain untouched.');
                        } else { // Attributes are basically the same
                            $classname = '';
                            $title = __('This attribute has the same value as the one in the revised object.');
                        }
                    }
                ?>
                <tr class="<?php echo $classname ?>" data-tohighlight="<?php echo h($to_highlight); ?>" title="<?php echo $title; ?>">
                    <?php foreach ($attribute_fields as $field): ?>
                        <?php if (isset($attribute[$field])): ?>
                            <?php if ($field == 'object_relation'): ?>
                                <td style="white-space: nowrap;"><?php echo h($attribute[$field]); ?></td>
                            <?php else: ?>
                                <td><?php echo h($attribute[$field]); ?></td>
                            <?php endif; ?>
                        <?php else: ?>
                            <td></td>
                        <?php endif; ?>
                    <?php endforeach; ?>
                </tr>
            <?php endforeach; ?>
            <?php
                if (isset($simple_flattened_attribute_noval)) {
                    $attribute_ids_to_inject = array_values(array_diff_key($simple_flattened_attribute_noval, $flattened_ids_in_similar_object));
                } else {
                    $simple_flattened_attribute_noval = array();
                }
            ?>
            <?php if (!empty($attribute_ids_to_inject)): ?>
                <?php foreach ($attribute_ids_to_inject as $i => $attribute_id): ?>
                    <?php $attribute = $data['Attribute'][$attribute_id]; ?>
                    <tr class="success" title="<?php echo __('This attribute will be added to this similar object during the merge.'); ?>" style="<?php echo $i == 0 ? 'border-top: 2px dashed #3465a4' : ''; ?>">
                        <?php foreach ($attribute_fields as $field): ?>
                            <?php if (isset($attribute[$field])): ?>
                                <?php if ($field == 'object_relation'): ?>
                                    <td style="white-space: nowrap;"><?php echo h($attribute[$field]); ?></td>
                                <?php else: ?>
                                    <td><?php echo h($attribute[$field]); ?></td>
                                <?php endif; ?>
                            <?php else: ?>
                                <td></td>
                            <?php endif; ?>
                        <?php endforeach; ?>
                    </tr>
                <?php endforeach; ?>
            <?php endif; ?>
        </tbody>
    </table>
</div>
