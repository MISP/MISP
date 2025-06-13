<?php
$boostrap_variant = $params['variant'];
if ($boostrap_variant == 'danger') {
    $boostrap_variant = 'error';
}
$header = $params['toast_header'];
$body = $params['toast_body'];
?>

<div class="alert alert-<?= h($boostrap_variant); ?>" style="margin-top: 0.5em;">
    <button type="button" class="close" data-dismiss="alert">×</button>
    <h4 class="alert-heading"><?= h($header); ?></h4>
    <p><?= h($body) ?></p>
</div>