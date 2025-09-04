<?php
    $orgs['org'] = $this->Hash->extract($row, 'Org');
    $orgs['orgc'] = $this->Hash->extract($row, 'Orgc');
    if (!isset($field['fields']['allow_picture'])) {
        $field['fields']['allow_picture'] = true;
    }
    if (!isset($field['fields']['default_org'])) {
        $field['fields']['default_org'] = '';
    }

    $html = '';
    $org_types_to_process = ['orgc'];
    if (Configure::read('MISP.showorgalternate') || $isAdmin) {
        $org_types_to_process[] = 'org';
    }
    $org_data = [];
    foreach ($org_types_to_process as $org_type) {
        $display_data = $field['fields']['allow_picture'] ? 
            $this->OrgImg->getOrgImg(array('name' => $orgs[$org_type]['name'], 'id' => $orgs[$org_type]['id'], 'size' => 24), true) : 
            h($orgs[$org_type]['name']);

        if (!empty($orgs[$org_type]['id'])) {
            if ($field['fields']['allow_picture'] && !empty($orgs[$org_type]['id'])) {
                $org_data[] = sprintf(
                    '<a href="%s">%s</a>',
                    $baseurl . '/organisations/view/' . h($orgs[$org_type]['id']),
                    $display_data
                );
            } else {
                $org_data[] = sprintf(
                    '<a href="%s/organisations/view/%s">%s</a>',
                    $baseurl,
                    empty($orgs[$org_type]['id']) ? h($orgs[$org_type]['uuid']) : h($orgs[$org_type]['id']),
                    h($orgs[$org_type]['name'])
                );
            }
        }
    }
    if (!empty($org_data)) {
        echo implode(' :: ', $org_data);
    }
?>
