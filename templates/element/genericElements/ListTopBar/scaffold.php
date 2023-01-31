<?php
    $groups = '';
    $hasGroupSearch = false;

    foreach ($data['children'] as $group) {
        $groups .= $this->element('/genericElements/ListTopBar/group_' . (empty($group['type']) ? 'simple' : h($group['type'])), array(
            'data' => $group,
            'tableRandomValue' => $tableRandomValue,
            'table_data' => $table_data,
        ));
        $hasGroupSearch = $hasGroupSearch || (!empty($group['type']) && $group['type'] == 'search');
    }
    $tempClass = "btn-toolbar";
    if (count($data['children']) > 1 && !$hasGroupSearch) {
        $tempClass .= ' justify-content-between';
    } else if (!empty($data['pull'])) {
        $tempClass .= ' float-' . h($data['pull']);
    }
    echo sprintf(
        '<div class="%s" role="toolbar" aria-label="Index toolbar">%s</div>',
        $tempClass,
        $groups
    );
?>
