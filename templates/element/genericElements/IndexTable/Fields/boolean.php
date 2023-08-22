<?php
    $rules_raw = array();
    $typeOptions = array(
        'OR' => array(
            'colour' => 'green',
            'text' => 'allowed'
        ),
        'NOT' => array(
            'colour' => 'red',
            'text' => 'blocked'
        )
    );
    if (
        !empty($this->Hash->extract($row, $field['data_path'])[0]) &&
        !empty($field['rule_path'][0]) &&
        !empty($this->Hash->extract($row, $field['rule_path'])[0])
    ) {
        $rules = $this->Hash->extract($row, $field['rule_path'])[0];
        $rules = json_decode($rules, true);
        foreach ($rules as $rule => $rule_data) {
            if (is_array($rule_data)) {
                foreach ($rule_data as $boolean => $values) {
                    if (!empty($values)) {
                        if (is_array($values)) {
                            $values = implode(', ', $values);
                        }
                        $rules_raw[] = sprintf(
                            '<span class=\'bold\'>%s %s</span>: <span class=\'%s\'>%s</span>',
                            h(\Cake\Utility\Inflector::humanize($rule)),
                            $typeOptions[$boolean]['text'],
                            $typeOptions[$boolean]['colour'],
                            h($values)
                        );
                    }
                }
            } else if (!empty($rule_data)){
                $rules_raw[] = sprintf(
                    '<span class=\'bold\'>%s</span>: <span class=\'green\'>%s</span>',
                    h(\Cake\Utility\Inflector::humanize($rule)),
                    h($rule_data)
                );
            }
        }
        $rules_raw = implode('<br />', $rules_raw);
    }

    $value = !empty($this->Hash->extract($row, $field['data_path'])[0]);
    $iconConfig = [];
    $defaultColorMapping = [true => 'success', false => 'danger'];
    if (!empty($field['colors'])) {
        if ($field['colors'] === true) {
            $textVariant = $defaultColorMapping[$value];
        } else if (is_array($field['colors'])) {
            $textVariant = $field['colors'][$value];
        } else {
            $textVariant = 'muted';
        }
        $iconConfig['class'] = "text-{$textVariant}";
    }

    $icon = $this->Bootstrap->icon($value ? 'check' : 'times', $iconConfig);
    echo $icon;
    if (!empty($rules_raw)) {
        echo sprintf(
            ' <span data-bs-toggle="popover" title="%s" data-bs-content="%s">(%s)</span>',
            __('Filter rules'),
            $rules_raw,
            __('Rules')
        );
    }
?>
