<?php
/*
 * progress.ctp — BS5 progress bar for an index cell.
 *
 * Two ways to feed it:
 *   1. $field['function']($row) returns a spec array (preferred when the bar
 *      state is derived from several row fields — e.g. Jobs):
 *        [
 *          'percent'  => int (0-100),
 *          'label'    => string (defaults to "<percent>%"),
 *          'variant'  => bootstrap colour without the bg- prefix (default 'primary'),
 *          'striped'  => bool,
 *          'animated' => bool,
 *          'refresh'  => bool  // mark the bar for client-side polling
 *        ]
 *   2. A plain percent at $field['data_path'] (0-100), with an optional static
 *      $field['variant'].
 */
if (!empty($field['function']) && is_callable($field['function'])) {
    $spec = (array)$field['function']($row);
} else {
    $spec = ['percent' => (int)Hash::get($row, $field['data_path'])];
}

$percent  = max(0, min(100, (int)($spec['percent'] ?? 0)));
$variant  = $spec['variant'] ?? ($field['variant'] ?? 'primary');
$label    = array_key_exists('label', $spec) ? $spec['label'] : ($percent . '%');
$striped  = !empty($spec['striped']);
$animated = !empty($spec['animated']);
$refresh  = !empty($spec['refresh']);

$barClass = 'progress-bar bg-' . h($variant)
    . ($striped ? ' progress-bar-striped' : '')
    . ($animated ? ' progress-bar-animated' : '');
?>
<div class="progress" role="progressbar"
     aria-valuenow="<?= $percent ?>" aria-valuemin="0" aria-valuemax="100"
     style="min-width: 8rem;"<?= $refresh ? ' data-progress-refresh="1"' : '' ?>>
    <div class="<?= $barClass ?>" style="width: <?= $percent ?>%;">
        <?= h($label) ?>
    </div>
</div>
