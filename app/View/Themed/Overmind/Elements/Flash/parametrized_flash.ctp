<?php
$bootstrap_variant = $params['variant'];
if ($bootstrap_variant == 'danger') {
    $bootstrap_variant = 'error';
}
$header = $params['toast_header'];
$body = $params['toast_body'];
?>

<div class="alert alert-<?= h($bootstrap_variant); ?> alert-dismissible fade show m-3">
    <h4 class="alert-heading"><?= h($header); ?></h4>
    <p><?= h($body) ?></p>
    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
</div>
