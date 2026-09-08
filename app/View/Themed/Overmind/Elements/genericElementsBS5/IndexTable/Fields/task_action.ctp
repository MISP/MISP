<?php
/*
 * task_action.ctp — the composite "Action" cell for the scheduled Tasks index.
 *
 * Renders, on one line: the action label inside a pill tinted + iconed by the
 * task TYPE, then (when meaningful) an arrow → the resolved target and any
 * extra qualifier chips (pull technique, feed scope). The task description is
 * printed underneath, muted.
 *
 * The task `params` column stores ids (server/feed/workflow/taxii) as a CSV;
 * they are resolved to names via $taskActionData (id => name maps set by
 * TasksController::index). Some types show no arrow at all (Periodic Summary).
 *
 * Reads $row['Task'] directly; the field only needs a data_path (Task.action)
 * for the header sort.
 */
$task        = $row['Task'] ?? [];
$type        = (string)($task['type'] ?? '');
$action      = (string)($task['action'] ?? '');
$rawParams   = trim((string)($task['params'] ?? ''));
$description = trim((string)($task['description'] ?? ''));

$maps = isset($taskActionData) ? $taskActionData : [];
$parts = ($rawParams === '') ? [] : array_map('trim', explode(',', $rawParams));


$typeStyles = [
    'Server'           => ['icon' => 'server',            'class' => 'text-bg-primary'],
    'Feed'             => ['icon' => 'rss',               'class' => 'text-bg-info'],
    'Workflow'         => ['icon' => 'diagram-project',   'class' => 'text-bg-success'],
    'TAXII'            => ['icon' => 'share-nodes',        'class' => 'text-bg-warning'],
    'Periodic Summary' => ['icon' => 'envelope',          'class' => 'text-bg-secondary'],
    'Admin'            => ['icon' => 'screwdriver-wrench', 'class' => 'text-bg-dark'],
];
$style = $typeStyles[$type] ?? ['icon' => 'bolt', 'class' => 'text-bg-secondary'];

// $target : resolved name shown after the arrow (null => no arrow).
// $extras : list of ['label' => .., 'value' => ..] qualifier chips.
$target = null;
$extras = [];

switch ($type) {
    case 'Server':
        $sid = $parts[0] ?? '';
        if ($sid === 'all') {
            $target = __('All Servers');
        } elseif ($sid !== '') {
            $target = $maps['servers'][$sid] ?? ('#' . $sid);
        }
        // Only the pull action carries a meaningful technique (full/update/…).
        if ($action === 'pull' && !empty($parts[1])) {
            $extras[] = ['label' => __('technique'), 'value' => $parts[1]];
        }
        break;

    case 'Feed':
        $fid = $parts[0] ?? '';
        if ($fid === 'all') {
            $target = __('All Feeds');
        } elseif ($fid !== '') {
            $target = $maps['feeds'][$fid] ?? ('#' . $fid);
        }
        if (!empty($parts[1])) {
            $extras[] = ['label' => __('scope'), 'value' => $parts[1]];
        }
        break;

    case 'Workflow':
        $wid = $parts[0] ?? '';
        if ($wid !== '') {
            $target = $maps['workflows'][$wid] ?? ('#' . $wid);
        }
        break;

    case 'TAXII':
        $tid = $parts[0] ?? '';
        if ($tid === 'all') {
            $target = __('All enabled TAXII servers');
        } elseif ($tid !== '') {
            $target = $maps['taxii'][$tid] ?? ('#' . $tid);
        }
        break;

    case 'Periodic Summary':
        // Action ("send") only — no arrow, no params.
        break;

    default:
        // Admin and anything else: surface raw params (if any) so nothing hides.
        if ($rawParams !== '') {
            $target = $rawParams;
        }
}
?>
<div class="task-action-cell">
    <div class="d-flex align-items-center flex-wrap gap-2">
        <span class="badge <?= h($style['class']) ?> d-inline-flex align-items-center">
            <i class="fas fa-<?= h($style['icon']) ?> me-1"></i>
            <?php if ($action !== ''): ?>
                <?= h($action) ?>
            <?php else: ?>
                <span class="fst-italic"><?= __('n/a') ?></span>
            <?php endif; ?>
        </span>

        <?php if ($target !== null): ?>
            <i class="fas fa-arrow-right-long text-secondary" aria-hidden="true"></i>
            <span class="badge rounded-pill bg-body-secondary text-body border border-secondary-subtle d-inline-flex align-items-center">
                <?= h($target) ?>
            </span>
        <?php endif; ?>

        <?php foreach ($extras as $ex): ?>
            <span class="badge rounded-pill bg-body-tertiary text-body border border-secondary-subtle d-inline-flex align-items-center">
                <span class="text-muted me-1"><?= h($ex['label']) ?>:</span><?= h($ex['value']) ?>
            </span>
        <?php endforeach; ?>
    </div>

    <?php if ($description !== ''): ?>
        <div class="text-body-secondary small mt-1"><?= h($description) ?></div>
    <?php endif; ?>
</div>
