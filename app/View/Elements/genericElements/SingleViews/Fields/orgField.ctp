<?php
$org = Hash::extract($data, $field['path']);
if (!isset($org['Organisation']) && !empty($org['id'])) {
    $org = ['Organisation' => $org];
}
echo empty($org) ? __('Unknown') : $this->OrgImg->getNameWithImg($org);
