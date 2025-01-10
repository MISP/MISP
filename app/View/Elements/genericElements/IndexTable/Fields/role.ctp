<?php
    $role = $row[$field['data_path']];
    echo sprintf(
        '<a href="%sroles/view/%s">%s</a>',
        $baseurl,
        h($role),
        h($role['name'])
    );
?>
