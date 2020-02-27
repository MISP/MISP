<?php
    $distributionLevel = (Hash::extract($row, $field['data_path'])[0]);
    echo sprintf(
        '<span class="%s bold">%s</span>',
        $distributionLevel == 0 ? 'red' : '',
        $distributionLevel != 4 ? $distributionLevels[$distributionLevel] :
            sprintf(
                '<a href="%s/sharing_groups/view/%s">%s</a>',
                $baseurl,
                h($row['SharingGroup']['id']),
                h($row['SharingGroup']['name'])
            )
    );

?>
