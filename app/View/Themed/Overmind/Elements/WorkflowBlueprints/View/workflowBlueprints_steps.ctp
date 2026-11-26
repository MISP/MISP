<?php
/*
 * The blueprint's nodes read as steps: walked from the nodes nothing in the
 * blueprint feeds into, following each node's outputs. A node with several
 * outputs (an IF) shows its branches nested; a node reached a second time is
 * not repeated, the second path points at the step it joins.
 */
$blueprint = $data['WorkflowBlueprint'] ?? [];
$nodes = $blueprint['data'] ?? [];
if (is_string($nodes)) {
    $nodes = json_decode($nodes, true);
}
$nodes = is_array($nodes) ? $nodes : [];

$byId = [];
foreach ($nodes as $node) {
    if (isset($node['id'])) {
        $byId[(string)$node['id']] = $node;
    }
}

$outputsOf = function (array $node) use ($byId) {
    $outputs = [];
    foreach ((is_array($node['outputs'] ?? null) ? $node['outputs'] : []) as $name => $output) {
        $targets = [];
        foreach (($output['connections'] ?? []) as $connection) {
            if (isset($byId[(string)$connection['node']])) {
                $targets[] = (string)$connection['node'];
            }
        }
        $outputs[$name] = $targets;
    }
    ksort($outputs, SORT_NATURAL);
    return $outputs;
};

$fed = [];
foreach ($byId as $id => $node) {
    foreach ($outputsOf($node) as $targets) {
        foreach ($targets as $target) {
            $fed[$target] = true;
        }
    }
}
$entries = array_values(array_filter(array_keys($byId), function ($id) use ($fed) {
    return !isset($fed[$id]);
}));
usort($entries, function ($a, $b) use ($byId) {
    return ($byId[$a]['pos_x'] ?? 0) <=> ($byId[$b]['pos_x'] ?? 0);
});

$typeLook = [
    'trigger' => ['fas fa-flag', 'success'],
    'logic' => ['fas fa-code-branch', 'info'],
    'action' => ['fas fa-bolt', 'primary'],
];

$paramChips = function (array $params) {
    $out = '';
    foreach ($params as $key => $value) {
        $values = array_values(array_filter((array)$value, function ($item) {
            return is_scalar($item) && (string)$item !== '';
        }));
        if (empty($values)) {
            continue;
        }
        $out .= '<span class="badge rounded-pill border bg-body-tertiary text-body-emphasis fw-normal text-truncate" style="max-width:100%;"'
            . ' title="' . h($key . ': ' . implode(', ', $values)) . '">'
            . '<span class="text-body-secondary font-monospace">' . h($key) . '</span> ' . h(implode(', ', $values)) . '</span>';
    }
    return $out;
};

$steps = 0;
$numbers = [];
$renderFrom = function ($id) use (&$renderFrom, &$steps, &$numbers, $byId, $outputsOf, $typeLook, $paramChips, $baseurl) {
    $html = '';
    while ($id !== null) {
        if (isset($numbers[$id])) {
            return $html . '<div class="small text-body-secondary ps-1 py-1"><i class="fas fa-turn-up fa-rotate-90 me-1 opacity-50"></i>'
                . h(__('Continues at step %s', $numbers[$id])) . '</div>';
        }
        $numbers[$id] = ++$steps;
        $node = $byId[$id];
        $module = $node['data'] ?? [];
        list($icon, $tone) = $typeLook[$module['module_type'] ?? ''] ?? ['fas fa-puzzle-piece', 'secondary'];
        $chips = $paramChips(is_array($module['indexed_params'] ?? null) ? $module['indexed_params'] : []);
        $moduleId = (string)($module['id'] ?? '');

        $html .= '<div class="d-flex align-items-start gap-2 py-1">'
            . '<span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 bg-' . $tone . '-subtle text-' . $tone . '-emphasis position-relative"'
            . ' style="width:1.75rem;height:1.75rem;" title="' . h(ucfirst($module['module_type'] ?? '')) . '"><i class="' . $icon . '"></i></span>'
            . '<div class="min-w-0 flex-grow-1">'
            . '<div class="d-flex flex-wrap align-items-baseline gap-2 lh-sm">'
            . '<span class="small text-body-secondary">' . h($numbers[$id]) . '.</span>'
            . '<span class="fw-semibold">' . h($module['name'] ?? $node['name'] ?? $moduleId) . '</span>'
            . ($moduleId !== ''
                ? '<a class="small font-monospace text-decoration-none" href="' . h($baseurl . '/workflows/moduleView/' . $moduleId) . '" title="' . h(__('Open the module')) . '">' . h($moduleId) . '</a>'
                : '')
            . '</div>'
            . ($chips !== '' ? '<div class="d-flex flex-wrap gap-1 mt-1">' . $chips . '</div>' : '')
            . '</div></div>';

        $outputs = $outputsOf($node);
        if (count($outputs) > 1) {
            $labels = [__('Then'), __('Else')];
            $index = 0;
            foreach ($outputs as $name => $targets) {
                $label = $labels[$index] ?? __('Output %s', $index + 1);
                $html .= '<div class="ms-3 ps-3 border-start">'
                    . '<div class="small fw-semibold text-body-secondary text-uppercase pt-1" style="font-size:.7rem;">' . h($label) . '</div>';
                if (empty($targets)) {
                    $html .= '<div class="small text-body-secondary fst-italic py-1">' . h(__('Nothing happens')) . '</div>';
                }
                foreach ($targets as $target) {
                    $html .= $renderFrom($target);
                }
                $html .= '</div>';
                $index++;
            }
            return $html;
        }
        $targets = $outputs ? reset($outputs) : [];
        if (count($targets) > 1) {
            foreach ($targets as $target) {
                $html .= '<div class="ms-3 ps-3 border-start">' . $renderFrom($target) . '</div>';
            }
            return $html;
        }
        $id = $targets[0] ?? null;
    }
    return $html;
};

$body = '';
foreach ($entries as $entry) {
    $body .= $renderFrom($entry);
}
// A cycle has no entry point; list whatever was not reached.
foreach (array_keys($byId) as $id) {
    if (!isset($numbers[$id])) {
        $body .= $renderFrom($id);
    }
}
?>
<div class="card mb-3 shadow-sm">
    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-2">
            <div class="rounded-2 d-flex align-items-center justify-content-center bg-primary-subtle text-primary flex-shrink-0" style="width:36px;height:36px;">
                <i class="fas fa-list-ol"></i>
            </div>
            <div>
                <div class="fw-bold lh-1"><?= __('Steps') ?></div>
                <div class="small text-muted mt-1"><?= h(__n('%s module', '%s modules', count($byId), count($byId))) ?></div>
            </div>
        </div>
    </div>
    <div class="card-body py-2">
        <?php if (empty($byId)): ?>
            <div class="text-center text-body-secondary small py-3"><?= __('This blueprint holds no module.') ?></div>
        <?php else: ?>
            <?= $body ?>
            <details class="mt-2 small">
                <summary class="text-body-secondary"><?= __('Raw data') ?></summary>
                <pre class="bg-body-tertiary border rounded p-2 mt-1 mb-0 small overflow-auto" style="max-height:20rem;"><code><?= h(json_encode($nodes, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)) ?></code></pre>
            </details>
        <?php endif; ?>
    </div>
</div>
