<?php
$name = Hash::get($row, $field['data_path']);

if (empty($name)) {
    return;
}

$token = '{{' . $name . '}}';
?>

<span class="erv-token d-inline-flex align-items-baseline font-monospace small lh-base rounded px-2 py-1" role="button" tabindex="0"
      data-erv-copy="<?= h($token) ?>"
      title="<?= h(__('Copy %s', $token)) ?>">
    <span class="erv-token-brace fw-medium">{{</span><span class="erv-token-name fw-semibold text-truncate"><?= h($name) ?></span><span class="erv-token-brace fw-medium">}}</span>
    <i class="fas fa-copy erv-token-copy ms-2" aria-hidden="true"></i>
</span>
