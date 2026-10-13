<?php
/*
 * The REST client's library: templates, past queries and bookmarks as three
 * tabs of one panel, with a filter over all three. History and bookmarks are
 * fetched from rest_client_history/index by restOvermind.js.
 */
$templateCount = array_sum(array_map('count', $allAccessibleApis));

$tabs = [
    'templates' => [
        'label' => __('Templates'),
        'count' => $templateCount,
        'hint' => __('Click a row to load the template, ⓘ for its description.'),
    ],
    'history' => [
        'label' => __('History'),
        'count' => '…',
        'hint' => __('Click a row to replay the request.'),
    ],
    'bookmarks' => [
        'label' => __('Bookmarks'),
        'icon' => 'fas fa-star text-warning',
        'count' => '…',
        'hint' => __('Click a row to replay the saved request.'),
    ],
];
$loading = function ($text) {
    return sprintf(
        '<div class="text-center p-4 text-body-secondary"><i class="fas fa-circle-notch fa-spin mb-2"></i><div class="small">%s</div></div>',
        h($text)
    );
};
$noMatch = '<div class="d-none text-center text-body-secondary small p-4" data-rest-no-match>'
    . h(__('Nothing matches this filter.')) . '</div>';
?>
<div class="card shadow-sm rest-library" id="rest-library">
    <div class="p-2 pb-0">
        <ul class="nav nav-pills nav-fill gap-1 small" role="tablist">
            <?php foreach ($tabs as $key => $tab): ?>
                <li class="nav-item" role="presentation">
                    <button type="button" role="tab"
                            class="nav-link py-1 px-2 d-flex align-items-center justify-content-center gap-2<?= $key === 'templates' ? ' active' : '' ?>"
                            id="rest-library-tab-<?= $key ?>"
                            data-bs-toggle="pill" data-bs-target="#rest-library-<?= $key ?>"
                            aria-controls="rest-library-<?= $key ?>"
                            aria-selected="<?= $key === 'templates' ? 'true' : 'false' ?>"
                            data-rest-library-tab="<?= $key ?>"
                            data-rest-hint="<?= h($tab['hint']) ?>"
                            <?php if (!empty($tab['icon'])): ?>title="<?= h($tab['label']) ?>" aria-label="<?= h($tab['label']) ?>"<?php endif; ?>>
                        <?php if (!empty($tab['icon'])): ?>
                            <i class="<?= h($tab['icon']) ?>"></i>
                        <?php else: ?>
                            <?= h($tab['label']) ?>
                        <?php endif; ?>
                        <span class="badge rounded-pill bg-body-secondary text-body-secondary" data-rest-count="<?= $key ?>"><?= h($tab['count']) ?></span>
                    </button>
                </li>
            <?php endforeach; ?>
        </ul>
    </div>

    <div class="p-2">
        <div class="input-group input-group-sm">
            <span class="input-group-text bg-body-tertiary"><i class="fas fa-magnifying-glass"></i></span>
            <input type="search" class="form-control" id="rest-library-filter" autocomplete="off"
                   placeholder="<?= __('Filter by path or name') ?>" aria-label="<?= __('Filter the library') ?>">
            <span class="input-group-text bg-body-tertiary" title="<?= __('Press / to filter') ?>"><kbd class="small">/</kbd></span>
        </div>
    </div>

    <div class="tab-content overflow-auto px-2 pb-2 rest-library-body">
        <div class="tab-pane fade show active" id="rest-library-templates" role="tabpanel" aria-labelledby="rest-library-tab-templates">
            <?= $this->element('Api/View/templates', ['allAccessibleApis' => $allAccessibleApis]) ?>
            <?= $noMatch ?>
        </div>
        <div class="tab-pane fade" id="rest-library-history" role="tabpanel" aria-labelledby="rest-library-tab-history">
            <div id="history-container" class="d-flex flex-column gap-1"><?= $loading(__('Loading history…')) ?></div>
            <?= $noMatch ?>
        </div>
        <div class="tab-pane fade" id="rest-library-bookmarks" role="tabpanel" aria-labelledby="rest-library-tab-bookmarks">
            <div id="bookmarks-container" class="d-flex flex-column gap-1"><?= $loading(__('Loading bookmarks…')) ?></div>
            <?= $noMatch ?>
        </div>
    </div>

    <div class="card-footer bg-body small text-body-tertiary py-2" id="rest-library-hint"><?= h($tabs['templates']['hint']) ?></div>
</div>
