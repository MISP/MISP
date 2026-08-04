<?php
$data = Hash::extract($row, $field['data_path']);
if (!empty($data['fixed'])):
    echo '<img src="' . $this->Image->base64(APP . 'files/img/orgs/MISP.png') . '" alt="' . __('MISP logo') . '" width="24" height="24" style="padding-bottom:3px" onerror="this.style.display=\'none\';"> ';
endif;

echo '<span class="bold">' . h($data['name']) . '</span>';
?>
