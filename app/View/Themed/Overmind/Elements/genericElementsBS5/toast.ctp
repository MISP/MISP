<?php
/**
 * One notification in the top-right stack; mispOvermind.js (initToasts)
 * arms its timer and close button. showToast() builds the same markup.
 *
 * Parameters:
 *  - kind      string  success | danger | warning | info (any Bootstrap tone)
 *  - message   string  plain text, escaped here
 *  - bodyHtml  string  already-escaped body, used instead of message
 *  - title     string  optional first line
 */
$kind = $kind ?? 'info';
if ($kind === 'error') {
    $kind = 'danger';
}
$icons = [
    'success' => 'fa-circle-check',
    'danger' => 'fa-circle-xmark',
    'warning' => 'fa-triangle-exclamation',
];
$lifetimes = ['success' => 5000, 'danger' => 0, 'warning' => 8000];
$ttl = $lifetimes[$kind] ?? 5000;
?>
<div class="ov-toast" role="<?= $kind === 'danger' ? 'alert' : 'status' ?>"
     style="--ov-tone: var(--bs-<?= h($kind) ?>);" data-ov-toast-ttl="<?= $ttl ?>">
    <span class="ov-toast-icon"><i class="fas <?= $icons[$kind] ?? 'fa-circle-info' ?>" aria-hidden="true"></i></span>
    <div class="ov-toast-body">
        <?php if (!empty($title)): ?>
            <div class="ov-toast-title"><?= h($title) ?></div>
        <?php endif; ?>
        <?= isset($bodyHtml) ? $bodyHtml : h($message ?? '') ?>
    </div>
    <button type="button" class="ov-toast-x" aria-label="<?= __('Dismiss') ?>"><i class="fas fa-xmark" aria-hidden="true"></i></button>
    <?php if ($ttl > 0): ?>
        <span class="ov-toast-timer" aria-hidden="true"></span>
    <?php endif; ?>
</div>
