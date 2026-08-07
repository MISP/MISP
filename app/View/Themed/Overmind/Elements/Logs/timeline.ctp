<?php
/*
 * Shared day-grouped timeline for the log indexes (audit / application).
 *
 * Expected variables:
 *  - $entries : list of normalised entries, each:
 *      [
 *        'created'      => 'Y-m-d H:i:s',
 *        'action'       => 'edit',            // key into the meta map below
 *        'action_label' => __('Edit'),        // human label (fallback: action)
 *        'title'        => 'APT29 campaign',  // main line (plain text)
 *        'model'        => 'Event',           // optional uppercase eyebrow
 *        'model_link'   => 'https://…',       // optional link wrapping the title
 *        'user'         => 'alice@acme.tld',  // optional
 *        'user_link'    => 'https://…',       // optional
 *        'org'          => 'CIRCL',           // optional
 *        'request_badge'=> ['label'=>'API','icon'=>'fas fa-cogs','title'=>'…'], // optional
 *        'change_html'  => '<div>…</div>',    // optional pre-rendered diff
 *      ]
 *  - $title      : card title
 *  - $icon       : icon class for the header
 *  - $empty_text : text shown when there are no entries
 */

$entries    = $entries ?? [];
$title      = $title ?? __('History');
$icon       = $icon ?? 'fas fa-history';
$empty_text = $empty_text ?? __('No entries found.');
$uid        = 'tl-' . dechex(mt_rand());

// action → colour/icon metadata (superset of audit + application log actions)
$meta = [
    'add'                 => ['color' => '#198754', 'bg' => '#d1e7dd', 'icon' => 'fas fa-plus-circle'],
    'edit'                => ['color' => '#0d6efd', 'bg' => '#cfe2ff', 'icon' => 'fas fa-pencil-alt'],
    'soft_delete'         => ['color' => '#fd7e14', 'bg' => '#ffe5cc', 'icon' => 'fas fa-trash-restore'],
    'delete'              => ['color' => '#dc3545', 'bg' => '#f8d7da', 'icon' => 'fas fa-trash-alt'],
    'undelete'            => ['color' => '#20c997', 'bg' => '#d2f4ea', 'icon' => 'fas fa-trash-restore'],
    'tag'                 => ['color' => '#6f42c1', 'bg' => '#e8d5f5', 'icon' => 'fas fa-tag'],
    'tag_local'           => ['color' => '#6f42c1', 'bg' => '#e8d5f5', 'icon' => 'fas fa-tag'],
    'remove_tag'          => ['color' => '#d63384', 'bg' => '#fad8e8', 'icon' => 'fas fa-tag'],
    'remove_local_tag'    => ['color' => '#d63384', 'bg' => '#fad8e8', 'icon' => 'fas fa-tag'],
    'galaxy'              => ['color' => '#6610f2', 'bg' => '#e0d0fd', 'icon' => 'fas fa-atom'],
    'galaxy_local'        => ['color' => '#6610f2', 'bg' => '#e0d0fd', 'icon' => 'fas fa-atom'],
    'remove_galaxy'       => ['color' => '#c2185b', 'bg' => '#fce3f0', 'icon' => 'fas fa-atom'],
    'remove_local_galaxy' => ['color' => '#c2185b', 'bg' => '#fce3f0', 'icon' => 'fas fa-atom'],
    'publish'             => ['color' => '#0284c7', 'bg' => '#e0f2fe', 'icon' => 'fas fa-paper-plane'],
    'publish_sightings'   => ['color' => '#0891b2', 'bg' => '#cffafe', 'icon' => 'fas fa-eye'],
    'instantiate'         => ['color' => '#6c757d', 'bg' => '#e2e3e5', 'icon' => 'fas fa-clone'],
    // application-log flavoured actions
    'login'               => ['color' => '#198754', 'bg' => '#d1e7dd', 'icon' => 'fas fa-sign-in-alt'],
    'auth'                => ['color' => '#0d6efd', 'bg' => '#cfe2ff', 'icon' => 'fas fa-key'],
    'logout'              => ['color' => '#6c757d', 'bg' => '#e2e3e5', 'icon' => 'fas fa-sign-out-alt'],
    'auth_fail'           => ['color' => '#dc3545', 'bg' => '#f8d7da', 'icon' => 'fas fa-user-lock'],
    'auth_alert'          => ['color' => '#dc3545', 'bg' => '#f8d7da', 'icon' => 'fas fa-exclamation-triangle'],
    'error'               => ['color' => '#dc3545', 'bg' => '#f8d7da', 'icon' => 'fas fa-exclamation-circle'],
    'warning'             => ['color' => '#fd7e14', 'bg' => '#ffe5cc', 'icon' => 'fas fa-exclamation-triangle'],
    'email'               => ['color' => '#0dcaf0', 'bg' => '#cff4fc', 'icon' => 'fas fa-envelope'],
    'blocklisted'         => ['color' => '#dc3545', 'bg' => '#f8d7da', 'icon' => 'fas fa-ban'],
    'disable'             => ['color' => '#fd7e14', 'bg' => '#ffe5cc', 'icon' => 'fas fa-toggle-off'],
    'enable'              => ['color' => '#198754', 'bg' => '#d1e7dd', 'icon' => 'fas fa-toggle-on'],
    'change_pw'           => ['color' => '#6f42c1', 'bg' => '#e8d5f5', 'icon' => 'fas fa-user-shield'],
    'export'              => ['color' => '#0d6efd', 'bg' => '#cfe2ff', 'icon' => 'fas fa-file-export'],
    'upload'              => ['color' => '#0d6efd', 'bg' => '#cfe2ff', 'icon' => 'fas fa-file-upload'],
];
$fallback = ['color' => '#6c757d', 'bg' => '#e2e3e5', 'icon' => 'fas fa-circle'];

// group entries by calendar day (entries are already ordered newest-first)
$groups = [];
foreach ($entries as $e) {
    $dayKey = substr((string)($e['created'] ?? ''), 0, 10);
    $groups[$dayKey][] = $e;
}

$fmtTime = function ($ts) {
    $t = strtotime((string)$ts);
    return $t ? date('H:i', $t) : h($ts);
};
$fmtDay = function ($dayKey) {
    $t = strtotime($dayKey . ' 00:00:00');
    return $t ? date('l, F j, Y', $t) : h($dayKey);
};
?>

<div class="card shadow-sm mb-4" id="<?= h($uid) ?>">

    <!-- HEADER -->
    <div class="card-header bg-transparent p-3">
        <div class="d-flex flex-wrap align-items-center gap-2">
            <div class="rounded-2 d-flex align-items-center justify-content-center flex-shrink-0"
                 style="width:36px;height:36px;background:#e0e7ff;">
                <i class="<?= h($icon) ?>" style="color:#4f46e5;font-size:1rem;"></i>
            </div>
            <div>
                <div class="fw-bold lh-1"><?= h($title) ?></div>
                <div class="small text-muted mt-1">
                    <?= __('%s entries on this page', count($entries)) ?>
                </div>
            </div>
        </div>
    </div>

    <!-- BODY -->
    <div class="card-body p-3" id="<?= h($uid) ?>-body">
        <?php if (empty($entries)): ?>
            <div class="d-flex flex-column align-items-center justify-content-center py-5 text-muted gap-2">
                <i class="<?= h($icon) ?> fa-2x opacity-25"></i>
                <span class="small"><?= h($empty_text) ?></span>
            </div>
        <?php else: ?>
            <div class="tl">
                <?php foreach ($groups as $dayKey => $dayEntries): ?>
                    <div class="tl-group mb-2" data-day="<?= h($dayKey) ?>">
                        <div class="tl-day fw-bold text-uppercase text-muted bg-body-secondary rounded-2">
                            <?= h($fmtDay($dayKey)) ?>
                        </div>
                        <?php foreach ($dayEntries as $i => $e):
                            $m = $meta[$e['action'] ?? ''] ?? $fallback;
                            $label = $e['action_label'] ?? ($e['action'] ?? '');
                            $searchBlob = strtolower(trim(implode(' ', [
                                $e['title'] ?? '', $e['model'] ?? '', $e['action'] ?? '',
                                $label, $e['user'] ?? '', $e['org'] ?? '',
                            ])));
                            $collapseId = $uid . '-c-' . h($dayKey) . '-' . $i;
                            $collapseId = preg_replace('/[^A-Za-z0-9_-]/', '', $collapseId);
                        ?>
                            <div class="tl-entry" data-search="<?= h($searchBlob) ?>">
                                <div class="tl-dot" style="color:<?= h($m['color']) ?>;background:<?= h($m['bg']) ?>;"></div>

                                <div class="d-flex align-items-start gap-2 flex-wrap">
                                    <span class="text-muted flex-shrink-0 mt-1"
                                          style="font-size:.72rem;min-width:2.8rem;"><?= h($fmtTime($e['created'] ?? '')) ?></span>
                                    <div style = "width:8.5rem;">
                                        <span class="badge flex-shrink-0 mt-1"
                                            style="display:inline-block;text-align:left;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;background:<?= h($m['bg']) ?>;color:<?= h($m['color']) ?>;font-size:.68rem;border:1px solid <?= h($m['color']) ?>33;"
                                            title="<?= h($label) ?>">
                                            <i class="<?= h($m['icon']) ?> me-1"></i><?= h($label) ?>
                                        </span>
                                    </div>

                                    <div class="flex-fill" style="min-width:0;">
                                        <div class="small fw-medium lh-sm">
                                            <?php if (!empty($e['model'])): ?>
                                                <?php if (!empty($e['model_link'])): ?>
                                                    <a href="<?= h($e['model_link']) ?>"
                                                       class="tl-meta-link text-muted text-uppercase me-1 text-decoration-none"
                                                       style="font-size:.68rem;letter-spacing:.04em;"
                                                       title="<?= __('View item') ?>"><?= h($e['model']) ?></a>
                                                <?php else: ?>
                                                    <span class="text-muted text-uppercase me-1"
                                                          style="font-size:.68rem;letter-spacing:.04em;"><?= h($e['model']) ?></span>
                                                <?php endif; ?>
                                            <?php endif; ?>
                                            <?php if (!empty($e['model_link'])): ?>
                                                <a href="<?= h($e['model_link']) ?>" class="text-decoration-none"><?= h($e['title'] ?? '') ?></a>
                                            <?php else: ?>
                                                <?= h($e['title'] ?? '') ?>
                                            <?php endif; ?>
                                        </div>

                                        <?php if (!empty($e['user']) || !empty($e['org']) || !empty($e['request_badge'])): ?>
                                            <div class="d-flex flex-wrap gap-2 mt-1 text-muted" style="font-size:.72rem;">
                                                <?php if (!empty($e['user'])): ?>
                                                    <?php if (!empty($e['user_link'])): ?>
                                                        <a href="<?= h($e['user_link']) ?>"
                                                           class="tl-meta-link d-inline-flex align-items-center gap-1 text-reset text-decoration-none"
                                                           title="<?= __('View user') ?>">
                                                            <i class="misp-icon misp-icon-user1 misp-simple" style="font-size:.65rem;"></i><?= h($e['user']) ?>
                                                        </a>
                                                    <?php else: ?>
                                                        <span class="d-inline-flex align-items-center gap-1">
                                                            <i class="misp-icon misp-icon-user1 misp-simple" style="font-size:.65rem;"></i><?= h($e['user']) ?>
                                                        </span>
                                                    <?php endif; ?>
                                                <?php endif; ?>
                                                <?php if (!empty($e['org'])): ?>
                                                    <?php if (!empty($e['org_link'])): ?>
                                                        <a href="<?= h($e['org_link']) ?>"
                                                           class="tl-meta-link d-inline-flex align-items-center gap-1 text-reset text-decoration-none"
                                                           title="<?= __('View organisation') ?>">
                                                            <i class="misp-icon misp-icon-organisation misp-simple" style="font-size:.65rem;"></i><?= h($e['org']) ?>
                                                        </a>
                                                    <?php else: ?>
                                                        <span class="d-inline-flex align-items-center gap-1">
                                                            <i class="misp-icon misp-icon-organisation misp-simple" style="font-size:.65rem;"></i><?= h($e['org']) ?>
                                                        </span>
                                                    <?php endif; ?>
                                                <?php endif; ?>
                                                <?php if (!empty($e['request_badge'])): ?>
                                                    <span class="d-inline-flex align-items-center gap-1"
                                                          title="<?= h($e['request_badge']['title'] ?? '') ?>">
                                                        <i class="<?= h($e['request_badge']['icon'] ?? 'fas fa-cog') ?>" style="font-size:.65rem;"></i><?= h($e['request_badge']['label'] ?? '') ?>
                                                    </span>
                                                <?php endif; ?>
                                            </div>
                                        <?php endif; ?>

                                        <?php if (!empty($e['change_html'])): ?>
                                            <button type="button"
                                                    class="btn btn-link btn-sm p-0 mt-1 text-decoration-none"
                                                    style="font-size:.72rem;color:inherit;opacity:.7;"
                                                    data-bs-toggle="collapse"
                                                    data-bs-target="#<?= h($collapseId) ?>">
                                                <i class="fas fa-chevron-down me-1"></i><?= __('Show changes') ?>
                                            </button>
                                            <div id="<?= h($collapseId) ?>" class="collapse">
                                                <div class="font-monospace bg-body-secondary border rounded-2 p-2 mt-1 overflow-x-auto"
                                                     style="font-size:.75rem;line-height:1.6;">
                                                    <?= $e['change_html'] ?>
                                                </div>
                                            </div>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </div>
</div>
