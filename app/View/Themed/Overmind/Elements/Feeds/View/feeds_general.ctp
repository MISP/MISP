<?php
$feed = $data['Feed'] ?? [];

$labelClass = 'text-body-secondary text-uppercase fw-bold';
$labelStyle = 'font-size:.7rem;';
$tileStyle = 'width:1.75rem;height:1.75rem;';

$formats = [
    'misp' => ['MISP', 'misp-icon misp-icon-event misp-simple'],
    'freetext' => [__('Freetext'), 'fas fa-align-left'],
    'csv' => ['CSV', 'fas fa-table'],
];
$sources = [
    'network' => [__('Network'), 'fas fa-globe'],
    'local' => [__('Local file'), 'fas fa-hard-drive'],
];
$format = $formats[$feed['source_format'] ?? ''] ?? [(string)($feed['source_format'] ?? ''), 'fas fa-file'];
$source = $sources[$feed['input_source'] ?? ''] ?? [(string)($feed['input_source'] ?? ''), 'fas fa-question'];
$url = (string)($feed['url'] ?? '');
$isLink = preg_match('/^https?:\/\//i', $url);

$cachingEnabled = !empty($feed['caching_enabled']);
$cachedElements = (int)($feed['cached_elements'] ?? 0);
$coverage = (float)rtrim((string)($feed['coverage_by_other_feeds'] ?? '0'), '%');
$cachedAt = !empty($cacheTimestamp) ? (int)$cacheTimestamp : null;

$flags = [
    [
        'on' => !empty($feed['enabled']),
        'colour' => 'success',
        'icon' => 'fas fa-circle-play',
        'label' => [__('Pulling'), __('Not pulling')],
        'sub' => [__('Its events are pulled into this instance'), __('Nothing is pulled from it')],
    ],
    [
        'on' => $cachingEnabled,
        'colour' => 'primary',
        'icon' => 'fas fa-bolt',
        'label' => [__('Caching'), __('Not caching')],
        'sub' => [__('Its values are correlated without importing'), __('Its values are not cached')],
    ],
];
?>
<div class="card mb-3 shadow-sm">
    <div class="card-body py-2 d-flex flex-column gap-3">

        <div>
            <div class="d-flex align-items-center justify-content-between flex-wrap gap-2 mb-1">
                <span class="<?= $labelClass ?>" style="<?= $labelStyle ?>">
                    <i class="fas fa-rss text-primary me-1"></i><?= __('Source') ?>
                </span>
                <span class="d-flex flex-wrap align-items-center gap-1">
                    <span class="badge rounded-pill border bg-body-tertiary text-body-emphasis fw-normal" title="<?= h(__('Source format')) ?>">
                        <i class="<?= h($format[1]) ?> me-1 opacity-50"></i><?= h($format[0]) ?>
                    </span>
                    <span class="badge rounded-pill border bg-body-tertiary text-body-emphasis fw-normal" title="<?= h(__('Input source')) ?>">
                        <i class="<?= h($source[1]) ?> me-1 opacity-50"></i><?= h($source[0]) ?>
                    </span>
                    <?php if (!empty($feed['default'])): ?>
                        <span class="badge rounded-pill bg-primary-subtle text-primary-emphasis border border-primary-subtle" title="<?= h(__('Shipped with MISP')) ?>">
                            <i class="fas fa-box me-1"></i><?= __('Default feed') ?>
                        </span>
                    <?php endif; ?>
                </span>
            </div>
            <?php if ($url === ''): ?>
                <span class="text-body-secondary fst-italic small"><?= __('No URL') ?></span>
            <?php else: ?>
                <div class="d-flex align-items-stretch border rounded-pill bg-body-tertiary font-monospace overflow-hidden lh-base mw-100" style="width:fit-content;">
                    <?php if ($isLink): ?>
                        <a class="d-inline-flex align-items-center gap-1 px-2 text-truncate text-decoration-none small"
                           href="<?= h($url) ?>" rel="noreferrer noopener" target="_blank" title="<?= h($url) ?>">
                            <i class="fas fa-arrow-up-right-from-square opacity-50"></i><span class="text-truncate"><?= h($url) ?></span>
                        </a>
                    <?php else: ?>
                        <span class="d-inline-flex align-items-center gap-1 px-2 text-truncate small text-body-emphasis" title="<?= h($url) ?>">
                            <i class="fas fa-file opacity-50"></i><span class="text-truncate"><?= h($url) ?></span>
                        </span>
                    <?php endif; ?>
                    <span class="vr my-1"></span>
                    <button type="button" class="ov-copy-target focus-ring d-inline-flex align-items-center border-0 bg-transparent text-body-secondary px-2 mb-0"
                            title="<?= h(__('Copy the URL')) ?>" aria-label="<?= h(__('Copy the URL')) ?>"
                            data-copy-value="<?= h($url) ?>" data-copy-msg="<?= h(__('URL copied to clipboard')) ?>"
                            onclick="copyValueToClipboard(this.dataset.copyValue, this.dataset.copyMsg)">
                        <i class="fas fa-copy fa-xs opacity-100 text-body-emphasis"></i>
                    </button>
                </div>
            <?php endif; ?>
            <?php if (!empty($feed['headers'])): ?>
                <div class="small text-body-secondary mt-1" title="<?= h(__('This feed is pulled with custom HTTP headers. Their values are never displayed.')) ?>">
                    <i class="fas fa-lock me-1 opacity-50"></i><?= __('Pulled with custom HTTP headers') ?>
                </div>
            <?php endif; ?>
        </div>

        <div>
            <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Status') ?></div>
            <div class="d-flex flex-wrap row-gap-2 column-gap-3">
                <?php foreach ($flags as $flag): ?>
                    <?php $state = $flag['on'] ? 0 : 1; ?>
                    <div class="d-flex align-items-center gap-2 min-w-0<?= $flag['on'] ? '' : ' opacity-75' ?>" style="flex:1 1 13rem;">
                        <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 <?= $flag['on']
                            ? 'bg-' . $flag['colour'] . '-subtle text-' . $flag['colour'] . '-emphasis'
                            : 'bg-body-secondary text-body-secondary' ?>"
                              style="<?= $tileStyle ?>">
                            <i class="<?= h($flag['icon']) ?>"></i>
                        </span>
                        <div class="min-w-0">
                            <div class="fw-semibold lh-sm<?= $flag['on'] ? '' : ' text-body-secondary' ?>"><?= h($flag['label'][$state]) ?></div>
                            <div class="small text-body-secondary text-truncate" title="<?= h($flag['sub'][$state]) ?>"><?= h($flag['sub'][$state]) ?></div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>

        <?php if ($cachingEnabled || $cachedElements > 0): ?>
            <div>
                <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Cache') ?></div>
                <div class="d-flex flex-wrap row-gap-2 column-gap-3">
                    <div class="d-flex align-items-center gap-2 min-w-0" style="flex:1 1 13rem;">
                        <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 <?= $cachedElements > 0 ? 'bg-primary-subtle text-primary-emphasis' : 'bg-body-secondary text-body-secondary' ?>"
                              style="<?= $tileStyle ?>">
                            <i class="fas fa-database"></i>
                        </span>
                        <div class="min-w-0">
                            <div class="fw-semibold lh-sm">
                                <?= h(__n('%s cached value', '%s cached values', $cachedElements, number_format($cachedElements, 0, ',', ' '))) ?>
                            </div>
                            <div class="small text-body-secondary text-truncate">
                                <?php if ($cachedAt): ?>
                                    <?= __('Last cached') ?> <?= $this->Time->time($cachedAt) ?>
                                <?php else: ?>
                                    <?= __('Not cached yet') ?>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                    <<?= $cachingEnabled ? 'a href="#tab-coverage" data-feed-tab="coverage" title="' . h(__('Open the coverage tool')) . '"' : 'div' ?>
                        class="d-flex align-items-center gap-2 min-w-0 text-decoration-none link-body-emphasis" style="flex:1 1 13rem;">
                        <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 bg-info-subtle text-info-emphasis"
                              style="<?= $tileStyle ?>">
                            <i class="fas fa-layer-group"></i>
                        </span>
                        <div class="min-w-0 flex-grow-1">
                            <div class="fw-semibold lh-sm"><?= __('%s%% covered elsewhere', h(rtrim(rtrim(number_format($coverage, 2, '.', ''), '0'), '.'))) ?></div>
                            <div class="progress mt-1" style="height:.3rem;" role="progressbar"
                                 aria-valuenow="<?= h($coverage) ?>" aria-valuemin="0" aria-valuemax="100"
                                 aria-label="<?= h(__('Share of the cached values seen in other feeds')) ?>">
                                <div class="progress-bar bg-info" style="width:<?= h(min(100, $coverage)) ?>%;"></div>
                            </div>
                        </div>
                    </<?= $cachingEnabled ? 'a' : 'div' ?>>
                </div>
            </div>
        <?php endif; ?>

        <div>
            <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Tags applied to pulled events') ?></div>
            <?php if (!empty($data['Tag']['id'])): ?>
                <?= $this->element('genericElementsBS5/Badges/tag', [
                    'tag' => $data['Tag'],
                    'local' => false,
                    'hiddenClass' => null,
                    'showFavourite' => false,
                ]) ?>
            <?php elseif (!empty($tagCollection['TagCollection']['id'])): ?>
                <div class="d-inline-flex flex-wrap align-items-center">
                    <a class="badge bg-body border text-body-emphasis me-1 mb-1"
                       href="<?= h($baseurl . '/tag_collections/view/' . $tagCollection['TagCollection']['id']) ?>"
                       title="<?= h(__('Tag Collection')) ?>">
                        <i class="fas fa-layer-group me-1"></i><?= h($tagCollection['TagCollection']['name']) ?>
                    </a>
                    <?php foreach (Hash::extract($tagCollection, 'TagCollectionTag.{n}.Tag') as $collectionTag): ?>
                        <?= $this->element('genericElementsBS5/Badges/tag', [
                            'tag' => $collectionTag,
                            'local' => false,
                            'hiddenClass' => null,
                            'showFavourite' => false,
                        ]) ?>
                    <?php endforeach; ?>
                </div>
            <?php else: ?>
                <span class="text-body-secondary fst-italic small"><?= __('None') ?></span>
            <?php endif; ?>
        </div>

    </div>
</div>

<script>
(function () {
    document.querySelectorAll('[data-feed-tab]:not([data-feed-tab-bound])').forEach(function (link) {
        link.setAttribute('data-feed-tab-bound', '');
        link.addEventListener('click', function (event) {
            var tab = document.querySelector('.nav-link[href="#tab-' + link.dataset.feedTab + '"]');
            if (tab && window.bootstrap) {
                event.preventDefault();
                bootstrap.Tab.getOrCreateInstance(tab).show();
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }
        });
    });
})();
</script>
