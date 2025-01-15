<?php
    $distributionLevel = ($this->Hash->extract($row, $field['data_path'])[0]);
    echo '<span class="fw-bold">';
    echo sprintf(
        '<span class="%s fw-bold">%s</span>',
        $distributionLevel == 0 ? 'text-danger' : '',
        $distributionLevel != 4 ? $distributionLevels[$distributionLevel] :
            sprintf(
                '<a href="%ssharing_groups/view/%s">%s</a>',
                $baseurl,
                h($row['SharingGroup']['id']),
                h($row['SharingGroup']['name'])
            )
    );

    echo sprintf(
        ' <it type="button" title="%s" class="%s" aria-hidden="true" style="font-size: x-small;" data-event-distribution="%s" data-event-distribution-name="%s" data-scope-id="%s"></it>',
        __('Toggle advanced sharing network viewer'),
        'fa fa-share-alt useCursorPointer distributionNetworkToggle',
        intval($distributionLevel),
        $distributionLevel == 4 ? h($event['SharingGroup']['name']) : h($shortDist[$distributionLevel]),
        $row['Event']['id']
    );
    echo '</span>';
?>
