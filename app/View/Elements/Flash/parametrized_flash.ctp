<?php
$bootstrap_variant = $params['variant'];
if ($bootstrap_variant == 'danger') {
    $bootstrap_variant = 'error';
}
$header = $params['toast_header'];
$body = $params['toast_body'];
?>

<div class="alert alert-<?= h($bootstrap_variant); ?>" style="margin-top: 0.5em;">
    <button type="button" class="close" data-dismiss="alert">×</button>
    <h4 class="alert-heading"><?= h($header); ?></h4>
    <p><?= h($body) ?></p>
</div>