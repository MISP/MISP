<?php
$data = Hash::extract($row, $field['data_path']);
if (is_array($data) && count($data) === 1 && isset($data[0])) {
    $data = $data[0];
}
if (is_string($data)) {
    $decoded = json_decode($data, true);
    if ($decoded !== null) {
        $data = $decoded;
    }
}
$jsonPretty = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
$needsCollapse = strlen($jsonPretty) > 100;
$collapseId = 'json_' . uniqid();
?>
<div class="json-viewer">
    <pre id="<?= $collapseId ?>"
         class="bg-dark text-light p-3 rounded small mb-2"
         style="<?= $needsCollapse ? 'max-height: 4.5em; overflow: hidden;' : '' ?> transition: max-height 0.3s ease;"
    ><?= h($jsonPretty) ?></pre>

    <?php if ($needsCollapse): ?>
    <button
        class="btn btn-sm btn-outline-primary mb-2"
        type="button"
        onclick="
            const pre = document.getElementById('<?= $collapseId ?>');
            const expanded = pre.style.maxHeight === 'none';
            pre.style.maxHeight = expanded ? '4.5em' : 'none';
            pre.style.overflow = expanded ? 'hidden' : 'auto';
            this.textContent = expanded ? '<?= __('Show more') ?>' : '<?= __('Show less') ?>';
        ">
        <?= __('Show more') ?>
    </button>
    <?php endif; ?>
</div>