<?php
if (isset($field['parent'])) {
    echo h($field['parent']);
} else {
    echo $this->element('/genericElements/IndexTable/Fields/generic_field', array(
        'row' => $row,
        'field' => $field
    ));
}

$htmlExtended = '';
$datapathLevels = $field['fields']['extend_data'];
$levelSkiped = 0;
foreach ($datapathLevels as $level => $datapathLevel) {
    $dataForLevel = Hash::extract($row, $datapathLevel['extend_root_data_path']);
    if (!empty($dataForLevel)) {
        $htmlExtended .= $this->element(
            '/genericElements/IndexTable/Fields/extended_by',
            array(
                'datapath' => $datapathLevel,
                'data' => $dataForLevel,
                'level' => $level - $levelSkiped,
                'k' => $k,
            )
        );
    } else {
        $levelSkiped++;
    }
}

if ($levelSkiped + 1 < count($datapathLevels)) { // only print if at least 2 level were displayed
    echo $htmlExtended;
}
?>
