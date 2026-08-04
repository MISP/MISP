<?php
/**
 * QueueList renderer (dashboard v2 — DD-38).
 *
 * A compact "one row per background-queue" renderer for the worker-health
 * widget (MispAdminWorkerWidget first; reusable by any future queue-health
 * widget). Each row is shaped:
 *
 *     [glyph] queue_name     [alive/total]  [pending_jobs]
 *
 * The two right-aligned chips are independently coloured: the workers chip
 * reflects whether the queue has the configured worker count alive, the
 * jobs chip reflects backlog pressure. A piling-up queue (jobs chip going
 * warning → danger) next to a healthy workers chip is the visual signal
 * for "workers are alive but stuck".
 *
 * Data contract — a flat list of typed rows:
 *
 *   $data = [
 *     // Optional summary header (at most one, normally first):
 *     ['type' => 'header', 'value' => '6 queues · 8 workers alive'],
 *
 *     // A queue row:
 *     ['type'  => 'queue',
 *      'queue' => 'default',          // queue identifier (BackgroundJobsTool)
 *      'name'  => 'default',          // visible label; defaults to `queue`
 *      'glyph' => 'default',          // QueueGlyph key; defaults to `queue`
 *      'alive' => 3,
 *      'total' => 4,
 *      'workers_class' => 'danger',   // info|warning|danger|success
 *      'jobs'  => 17,                 // omit → no jobs chip (e.g. scheduler)
 *      'jobs_class'  => 'info',       // info|warning|danger|success
 *      'drilldown' => '/servers/serverSettings/workers'],
 *
 *     // A full-width message (workers-unreachable / supervisor-down etc.):
 *     ['type' => 'message', 'title' => '...', 'value' => '...'],
 *   ];
 *
 * Colour decisions are made in the widget (it knows the thresholds and the
 * worker_array shape); this renderer only maps the named class to the
 * matching .misp-queue-chip-<sem> token pair (muted background + strong
 * foreground). Adding a new colour stop = adding one CSS rule, no logic
 * here changes.
 *
 * Escaping (DD-34): widget handler()s emit RAW strings — this renderer
 * h()s every interpolated scalar exactly once. Drilldown URL safety is
 * gated by DashboardURLValidator (DD-03): unsafe / off-host URLs are
 * dropped and the row renders un-linked.
 *
 * No inline styles / hardcoded colours: visuals come from the token-driven
 * .misp-queue-* rules in dashboard.default.css, so themes that only
 * redefine the --misp-dash-* tokens retone this for free. This renderer is
 * NOT its own scroll/size container — .misp-widget-body owns padding +
 * overflow (DD-31 rule).
 */
App::uses('DashboardURLValidator', 'Lib/Dashboard/Tools');
App::uses('QueueGlyph', 'Lib/Dashboard/Tools');

if (empty($data)) {
    echo '<div class="misp-queue-message"><span class="misp-queue-message-text">'
        . __('No data.') . '</span></div>';
    return;
}

$validClass = array('info', 'warning', 'danger', 'success');

echo '<div class="misp-queue-list">';
foreach ($data as $row) {
    $type = isset($row['type']) ? $row['type']
        : (isset($row['queue']) ? 'queue' : 'message');

    if ($type === 'header') {
        echo '<div class="misp-queue-header">'
            . '<span class="misp-queue-headtext">' . h($row['value'] ?? '') . '</span>'
            . '</div>';
        continue;
    }

    if ($type === 'message') {
        $title = !empty($row['title'])
            ? '<span class="misp-queue-message-title">' . h($row['title']) . '</span>'
            : '';
        $text = isset($row['value'])
            ? '<span class="misp-queue-message-text">' . h($row['value']) . '</span>'
            : '';
        echo '<div class="misp-queue-message">' . $title . $text . '</div>';
        continue;
    }

    // ---- queue row ----
    $queue = (string)($row['queue'] ?? '');
    $name  = isset($row['name']) ? (string)$row['name'] : $queue;
    $glyphName = isset($row['glyph']) ? (string)$row['glyph'] : $queue;
    $glyph = QueueGlyph::get($glyphName);

    $alive = isset($row['alive']) ? (int)$row['alive'] : 0;
    $total = isset($row['total']) ? (int)$row['total'] : 0;
    $workersClass = isset($row['workers_class']) && in_array($row['workers_class'], $validClass, true)
        ? $row['workers_class']
        : 'info';
    $workersChip = sprintf(
        '<span class="misp-queue-chip misp-queue-chip-%s" title="%s">[%d/%d]</span>',
        h($workersClass),
        h(__('Workers alive / total')),
        $alive,
        $total
    );

    $jobsChip = '';
    if (array_key_exists('jobs', $row) && $row['jobs'] !== null && $row['jobs'] !== '') {
        $jobs = (int)$row['jobs'];
        $jobsClass = isset($row['jobs_class']) && in_array($row['jobs_class'], $validClass, true)
            ? $row['jobs_class']
            : 'info';
        $jobsChip = sprintf(
            '<span class="misp-queue-chip misp-queue-chip-%s" title="%s">%s</span>',
            h($jobsClass),
            h(__('Pending jobs')),
            number_format($jobs)
        );
    }

    $label = '<span class="misp-queue-label">'
        . ($glyph !== '' ? '<span class="misp-queue-glyph">' . $glyph . '</span>' : '')
        . '<span class="misp-queue-name">' . h($name) . '</span>'
        . '</span>';

    $inner = $label . '<span class="misp-queue-chips">' . $workersChip . $jobsChip . '</span>';

    $href = null;
    if (!empty($row['drilldown'])) {
        $href = DashboardURLValidator::validate($row['drilldown']);
    }
    if ($href !== null) {
        echo sprintf('<a class="misp-queue-row" href="%s">%s</a>', h($href), $inner);
    } else {
        echo sprintf('<div class="misp-queue-row">%s</div>', $inner);
    }
}
echo '</div>';
