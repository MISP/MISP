<?php
/*
 * An HTTP status code, toned by its class: 2xx success, 3xx info, 4xx warning,
 * 5xx danger.
 *
 * Params:
 *   $code  int   the status code
 *   $chip  bool  the response card's pill with the reason phrase, rather than
 *                the bare code a library row carries (default false)
 */
$code = (int)($code ?? 0);
$tone = [2 => 'success', 3 => 'info', 4 => 'warning', 5 => 'danger'][intdiv($code, 100)] ?? 'secondary';
?>
<?php if (empty($chip)): ?>
    <span class="fw-bold font-monospace text-<?= $tone ?>-emphasis"><?= $code ?></span>
<?php else: ?>
    <?php $reason = $this->response->httpCodes($code)[$code] ?? ''; ?>
    <span class="badge rounded-pill font-monospace bg-<?= $tone ?>-subtle text-<?= $tone ?>-emphasis border border-<?= $tone ?>-subtle px-2 py-1">
        <i class="fas fa-circle fa-2xs me-1"></i><?= $code ?> <?= h($reason) ?>
    </span>
<?php endif; ?>
