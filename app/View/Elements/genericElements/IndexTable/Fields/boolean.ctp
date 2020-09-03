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
        !empty(Hash::extract($row, $field['data_path'])[0]) &&
        !empty($field['rule_path'][0]) &&
        !empty(Hash::extract($row, $field['rule_path'])[0])
    ) {
        $rules = Hash::extract($row, $field['rule_path'])[0];
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
                            h(Inflector::humanize($rule)),
                            $typeOptions[$boolean]['text'],
                            $typeOptions[$boolean]['colour'],
                            h($values)
                        );
                    }
                }
            } else if (!empty($rule_data)){
                $rules_raw[] = sprintf(
                    '<span class=\'bold\'>%s</span>: <span class=\'green\'>%s</span>',
                    h(Inflector::humanize($rule)),
                    h($rule_data)
                );
            }
        }
        $rules_raw = implode('<br />', $rules_raw);
    }
    echo sprintf(
        '<i class="black fa fa-%s" role="img" aria-label="%s"></i>%s',
        (!empty(Hash::extract($row, $field['data_path'])[0])) ? 'check' : 'times',
        (!empty(Hash::extract($row, $field['data_path'])[0])) ? __('Yes') : __('No'),	
        empty($rules_raw) ? '' :
        sprintf(
            ' <span data-toggle="popover" title="%s" data-content="%s">(%s)</span>',
            __('Filter rules'),
            $rules_raw,
            __('Rules')
        )
    );
?>
