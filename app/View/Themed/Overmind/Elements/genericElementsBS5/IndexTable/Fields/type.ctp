<?php
$type = Hash::extract($row, $field['data_path'])[0];

?>
<div class="d-flex align-items-center justify-content-center border border-dark rounded p-1">
    <p class="mb-0"><?= $type ?></p>
</div>
