<?php
    $org = Hash::extract($row, $field['data_path']);
    echo sprintf(
        '<a href="%s/organisations/view/%s">%s</a>',
        $baseurl,
        h($org['id']),
        h($org['name'])
    );
?>
