<div id="element_<?php echo $k; ?>">
    <div class="populate_template_div_body">
        <div class="left-inverse"><?php echo __('Field');?>:</div>
        <div class="right-inverse">
            <?php echo h($element['name']); ?>
            <?php if ($element['mandatory']): ?>
                <span class="template_mandatory">(*)</span>
            <?php endif;?>
        </div><br />
        <div class="left"><?php echo __('Description');?>:</div>
        <div class="right"><?php echo h($element['description']); ?></div><br />

        <div class="left"><?php echo __('Type');?><?php if ($element['complex']) echo 's'; ?>:</div>
        <div class="right">
        <?php
            $types = '';
            if ($element['complex']) {
                foreach ($validTypeGroups[$element['type']]['types'] as $k => $type):
                    if ($k != 0) $types .= ', ';
                    $types .= $type;
                    ?>
                        <div class="templateTypeBox"><?php echo h($type); ?></div>
                    <?php
                endforeach;
            } else {
                ?>
                    <div class="templateTypeBox"><?php echo h($element['type']); ?></div>
                <?php
            }
        ?>
        </div>
        <div>
        <?php
            if (isset($template['Template']['value_' . $element_id])) $value = $template['Template']['value_' . $element_id];
            if (isset($errors[$element_id])) $error = $errors[$element_id];
            if ($element['batch']) {
                if ($element['complex']) {
                    $placeholder = __('Describe the %s using one or several (separated by a line-break) of the following types: %s' , h($element['name']), $types);
                } else {
                    $placeholder = __('Describe the %s using one or several %s\s (separated by a line-break) ' , h($element['name']) , h($element['type']));
                }
                echo $this->Form->input('value_' . $element_id, array(
                    'type' => 'textarea',
                    'label' => false,
                    'div' => false,
                    'style' => 'width: calc(100% - 16px);',
                    'placeholder' => $placeholder,
                    'value' => $value,
                ));
            } else {
                if ($element['complex']) {
                    $placeholder = __('Describe the %s using one of the following types: %s' , h($element['name'], $types));
                } else {
                    $placeholder = __('Describe the %s using a %s' , h($element['name']) , h($element['type']));
                }
                echo $this->Form->input('value_' . $element_id, array(
                    'type' => 'text',
                    'label' => false,
                    'div' => false,
                    'style' => 'width: calc(100% - 16px);',
                    'placeholder' => $placeholder,
                    'value' => $value,
                ));
            }
        ?>
        </div>
        <div class="error-message populateTemplateErrorField" <?php if (!isset($errors[$element_id])) echo 'style="display:none;"';?>>
            <?php echo __('Error: %s', $errors[$element_id]); ?>
        </div>
    </div>
</div>
