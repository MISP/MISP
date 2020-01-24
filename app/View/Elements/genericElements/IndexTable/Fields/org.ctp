<?php
    $orgs = Hash::extract($row, $field['data_path']);
    if (!empty($orgs)) {
        if (!isset($orgs[0])) {
            $orgs = array($orgs);
        }
        $count = count($orgs);
        $i = 0;
        foreach ($orgs as $org) {
            $i++;
            echo sprintf(
                '<a href="%s/organisations/view/%s">%s</a>',
                $baseurl,
                empty($org['id']) ? h($org['uuid']) : h($org['id']),
                h($org['name'])
            );
            if ($i < $count) {
                echo '<br />';
            }
        }
    }
?>
