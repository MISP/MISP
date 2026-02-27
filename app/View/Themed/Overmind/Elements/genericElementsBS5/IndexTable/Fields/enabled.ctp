<?php
$value = Hash::get($row, $field['data_path']);

if (!empty($value)) {
    echo '<div class="d-flex align-items-center"><span class="fas fa-check-circle text-success" style="font-size: 1.5em;" title="Enabled"></span></div>';
} else {
    echo '<div class="d-flex align-items-center"><span class="fas fa-times-circle text-danger" style="font-size: 1.5em;" title="Disabled"></span></div>';
}
?>