<?php
$attribute = Hash::get($row, $field['data_path']);

if(!empty($attribute)){
    $ids = (int)Hash::get($attribute, 'to_ids', 0);
    $disable_correlation = (int)Hash::get($attribute, 'disable_correlation', 0);
} else {
    $ids = (int)Hash::get($row, 'to_ids', 0);
    $disable_correlation = (int)Hash::get($row, 'disable_correlation', 0);
 }


// TODO: move styles to CSS and use classes instead of inline styles
$styleBlue = "background: linear-gradient(180deg, #2e85cc 0%, #275dae 50%, #1e5384 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;";
$styleOrange = "background: linear-gradient(180deg, #f39c12 0%, #e67e22 50%, #d35400 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;";
?>

<div class="d-flex align-items-center flex-wrap gap-2">

    <?php if ($ids): ?>
        <div class="d-inline-flex align-items-center fw-bold text-nowrap" style="<?= $styleOrange ?>">
            <i class="fas fa-shield me-1"></i>
            <span> IDS </span>
        </div>
    <?php endif; ?>

    <?php if (! $disable_correlation): ?>
        <a class="d-inline-flex align-items-center fw-bold text-nowrap text-decoration-none" style="<?= $styleBlue ?>">
            <i class="fas fa-link me-1"></i>
            <span> Correlate </span>
        </a>
    <?php endif; ?>

</div>