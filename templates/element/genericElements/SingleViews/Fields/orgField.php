<?php
$org = Cake\Utility\Hash::get($data, $field['path']);
if (!empty($org['id']) || !empty($org['name'])) {
    if (!empty($field['allow_picture']) && !empty($org['id'])) {
        echo sprintf(
            '<a href="%s">%s</a>',
            $baseurl . '/organisations/view/' . h($org['id']),
            h($org['name'])
        );
        //echo $this->OrgImg->getOrgImg(array('name' => $org['name'], 'id' => $org['id'], 'size' => 24));
    } else {
        echo sprintf(
            '<a href="%s/organisations/view/%s">%s</a>',
            $baseurl,
            empty($org['id']) ? h($org['uuid']) : h($org['id']),
            h($org['name'])
        );
    }
} else {
    if (!empty($field['allow_picture'])) {
        echo sprintf(
            '<a href="%s">%s</a>',
            $baseurl . 'organisations/view/' . h($org['id']),
            h($org['name'])
        );
        //echo $this->OrgImg->getOrgImg(array('name' =>  $field['fields']['default_org'], 'size' => 24));
    }
}