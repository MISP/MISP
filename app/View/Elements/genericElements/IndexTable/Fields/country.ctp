<?php
$data = Hash::extract($row, $field['data_path']);
$html = '';
if (isset($data['country_code'])) {
    $html .= $this->Icon->countryFlag($data['country_code']) . '&nbsp;';
}
if ($data['nationality'] !== 'Not specified') {
    $html .= h($data['nationality']);
}
echo $html;
