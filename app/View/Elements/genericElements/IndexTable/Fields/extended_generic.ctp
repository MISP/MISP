<?php
$extendbyData = Hash::extract($row, $field['fields']['extendby_data_path']);
$extendfromData = Hash::extract($row, $field['fields']['extendfrom_data_path']);
$defaultValuePrinted = false;
if (!empty($extendfromData)) {
    echo $this->element(
        '/genericElements/IndexTable/Fields/extended_from',
        array(
            'field' => $field,
            'row' => $row,
            'column' => $column,
            'data_path' => empty($field['data_path']) ? '' : $field['data_path'],
            'k' => $k
        )
    );
    $field['parent'] = '';
    $defaultValuePrinted = true;
}

if (!empty($extendbyData)) {
    echo $this->element(
        '/genericElements/IndexTable/Fields/extended_by',
        array(
            'field' => $field,
            'row' => $row,
            'column' => $column,
            'data_path' => empty($field['data_path']) ? '' : $field['data_path'],
            'k' => $k
        )
    );
    $defaultValuePrinted = true;
}

if (!$defaultValuePrinted) {
    if (isset($field['parent'])) {
        echo h($field['parent']);
    } else {
        echo $this->element('/genericElements/IndexTable/Fields/generic_field', array(
            'row' => $row,
            'field' => $field
        ));
    }
}
?>
