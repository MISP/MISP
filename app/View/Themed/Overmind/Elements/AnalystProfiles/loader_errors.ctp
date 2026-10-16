<?php
/**
 * What the signal loader skipped, and why.
 *
 * A file with a syntax error, a class that is not a signal, a
 * colliding id — the engine skips all three silently, so this is the
 * page where an admin finds out. `Workflow` surfaces its own loader's
 * errors the same way, and for the same reason: a drop-in that does
 * not load is indistinguishable from a drop-in nobody wrote.
 *
 * @var array $loader_errors
 */
if (empty($loader_errors)) {
    return;
}
?>
<div class="wb-note bad mb-3">
    <div class="fw-semibold mb-1">
        <?= h(sprintf(__n(
            'One file in the signal directories was skipped',
            '%s files in the signal directories were skipped',
            count($loader_errors)
        ), count($loader_errors))) ?>
    </div>
    <ul class="mb-0 ps-3">
        <?php foreach ($loader_errors as $error): ?>
            <li>
                <span class="wb-sub"><?= h($error['subject']) ?></span>
                <span class="wb-id"><?= h($error['file']) ?></span>
                &mdash; <?= h($error['reason']) ?>
            </li>
        <?php endforeach; ?>
    </ul>
    <p class="wb-sub mb-0 mt-1">
        <?= h(__('A skipped file contributes no signal. Any profile naming'
            . ' it shows it as missing.')) ?>
    </p>
</div>
