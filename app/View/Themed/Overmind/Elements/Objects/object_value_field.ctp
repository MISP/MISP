<?php
if (empty($action)) $action = 'add';
?>
<div class="object_value_field">
<?php
if ($element['type'] === 'malware-sample' || $element['type'] === 'attachment'):
    if ($action !== 'edit' || empty($element['value'])):
        echo $this->Form->file('Attribute.' . $k . '.Attachment', [
            'class' => 'form-control form-control-sm Attribute_attachment',
        ]);
    else:
        echo '<span class="text-muted" style="font-size:.8rem;">' . h($element['value']) . '</span>';
        echo $this->Form->textarea('Attribute.' . $k . '.value', [
            'class'      => 'form-control form-control-sm Attribute_value',
            'required'   => false,
            'allowEmpty' => true,
            'value'      => $element['value'],
            'style'      => 'display:none; resize:vertical;',
            'label'      => false,
            'div'        => false,
        ]);
    endif;
elseif (empty($element['values_list']) && empty($element['sane_default'])):
    echo $this->Form->textarea('Attribute.' . $k . '.value', [
        'class'      => 'form-control form-control-sm Attribute_value',
        'required'   => false,
        'allowEmpty' => true,
        'value'      => empty($element['value']) ? '' : $element['value'],
        'rows'       => 1,
        'style'      => 'resize:vertical;',
        'label'      => false,
        'div'        => false,
    ]);
else:
    if (empty($element['values_list'])) {
        $list   = $element['sane_default'];
        $list[] = 'Enter value manually';
    } else {
        $list = $element['values_list'];
    }
    $list = array_combine($list, $list);

    $choice = '';
    if (!empty($element['value'])) {
        $choice = in_array($element['value'], $list)
            ? $element['value']
            : 'Enter value manually';
    }

    echo '<div class="value_select_with_manual_entry">';
    echo $this->Form->select(
        'Attribute.' . $k . '.value_select',
        $list,
        [
            'class'  => 'form-select form-select-sm Attribute_value_select mb-1',
            'empty'  => __('-- Select an option --'),
            'value'  => $choice,
        ]
    );
    echo $this->Form->textarea('Attribute.' . $k . '.value', [
        'class'      => 'form-control form-control-sm Attribute_value',
        'required'   => false,
        'allowEmpty' => true,
        'value'      => empty($element['value']) ? '' : $element['value'],
        'rows'       => 1,
        'style'      => 'resize:vertical;'
            . (($choice === 'Enter value manually') ? '' : ' display:none;'),
        'label'      => false,
        'div'        => false,
    ]);
    echo '</div>';
endif;
?>
</div>
