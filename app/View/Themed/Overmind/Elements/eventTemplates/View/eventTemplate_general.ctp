<?php
$tpl = $data['EventTemplate'] ?? [];
$definition = is_array($tpl['definition'] ?? null) ? $tpl['definition'] : [];
$libraryMetadata = is_array($definition['library_metadata'] ?? null) ? $definition['library_metadata'] : [];
$shape = $templateShape ?? ['sections' => 0, 'fields' => 0, 'mandatory' => 0, 'dependencies' => 0];

$labelClass = 'text-body-secondary text-uppercase fw-bold';
$labelStyle = 'font-size:.7rem;';
$tileStyle = 'width:1.75rem;height:1.75rem;';

$flags = [
    [
        'on' => (int)($tpl['active'] ?? 0) === 1,
        'colour' => 'success',
        'icon' => 'fas fa-power-off',
        'label' => [__('Active'), __('Inactive')],
        'sub' => [__('Offered when creating an event'), __('Not offered when creating an event')],
    ],
    [
        'on' => !empty($tpl['misp_default']),
        'colour' => 'info',
        'icon' => 'fas fa-cube',
        'label' => [__('Library-managed'), __('Custom')],
        'sub' => [__('An update from the library overwrites local edits'), __('Created on this instance')],
    ],
    [
        'on' => !empty($tpl['exposed']),
        'colour' => 'warning',
        'icon' => 'fas fa-globe',
        'label' => [__('Exposed to Draugnet'), __('Not exposed')],
        'sub' => [__('Offered to anonymous community reporters'), __('Not offered to Draugnet reporters')],
    ],
];

$shapeTiles = [
    ['fas fa-list-check', 'structure', __n('%s field', '%s fields', $shape['fields'], $shape['fields']),
        __n('%s mandatory', '%s mandatory', $shape['mandatory'], $shape['mandatory'])],
    ['fas fa-layer-group', 'structure', __n('%s section', '%s sections', $shape['sections'], $shape['sections']),
        __('Groups the form into steps')],
    ['misp-icon misp-icon-object misp-simple', 'dependencies', __n('%s object template', '%s object templates', $shape['dependencies'], $shape['dependencies']),
        __('Needed to build the event')],
];
?>
<div class="card mb-3 shadow-sm" data-tour="event-template-general">
    <div class="card-body py-2 d-flex flex-column gap-3">

        <div>
            <div class="d-flex align-items-center justify-content-between flex-wrap gap-2 mb-1">
                <span class="<?= $labelClass ?>" style="<?= $labelStyle ?>">
                    <i class="fas fa-file-lines text-primary me-1"></i><?= __('Event template') ?>
                </span>
                <span class="d-flex flex-wrap align-items-center gap-1">
                    <?php if (!empty($definition['schema_version'])): ?>
                        <span class="badge rounded-pill border bg-body-tertiary text-body-secondary fw-normal" title="<?= h(__('Schema version')) ?>">
                            <i class="fas fa-code me-1 opacity-50"></i><?= h(__('Schema %s', $definition['schema_version'])) ?>
                        </span>
                    <?php endif; ?>
                    <span class="badge rounded-pill bg-primary-subtle text-primary-emphasis border border-primary-subtle">
                        v<?= h((int)($tpl['version'] ?? 0)) ?>
                    </span>
                </span>
            </div>
            <?php if (trim($tpl['description'] ?? '') !== ''): ?>
                <div class="border-start border-3 border-primary bg-primary-subtle bg-opacity-25 rounded-end px-3 py-2 text-break">
                    <?= nl2br(h($tpl['description'])) ?>
                </div>
            <?php else: ?>
                <span class="text-body-secondary fst-italic small"><?= __('No description') ?></span>
            <?php endif; ?>
        </div>

        <div>
            <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Status') ?></div>
            <div class="row row-cols-1 row-cols-md-3 g-2">
                <?php foreach ($flags as $flag): ?>
                    <?php $state = $flag['on'] ? 0 : 1; ?>
                    <div class="col">
                        <div class="d-flex align-items-center gap-2 min-w-0<?= $flag['on'] ? '' : ' opacity-75' ?>">
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
                    </div>
                <?php endforeach; ?>
            </div>
        </div>

        <div>
            <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('What the reporter fills in') ?></div>
            <div class="row row-cols-1 row-cols-md-3 g-2">
                <?php foreach ($shapeTiles as $shapeTile): ?>
                    <div class="col">
                        <a href="#tab-<?= h($shapeTile[1]) ?>" data-tpl-tab="<?= h($shapeTile[1]) ?>"
                           class="d-flex align-items-center gap-2 min-w-0 text-decoration-none link-body-emphasis">
                            <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 bg-primary-subtle text-primary-emphasis"
                                  style="<?= $tileStyle ?>"><i class="<?= h($shapeTile[0]) ?>"></i></span>
                            <div class="min-w-0">
                                <div class="fw-semibold lh-sm text-truncate"><?= h($shapeTile[2]) ?></div>
                                <div class="small text-body-secondary text-truncate"><?= h($shapeTile[3]) ?></div>
                            </div>
                        </a>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>

        <?php if (!empty($libraryMetadata)): ?>
            <div>
                <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('From the library') ?></div>
                <div class="d-flex flex-wrap align-items-center gap-1">
                    <?php foreach (($libraryMetadata['authors'] ?? []) as $author): ?>
                        <span class="badge rounded-pill border bg-body-tertiary text-body-emphasis fw-normal"
                              title="<?= h(__('Author')) ?><?= !empty($author['contact']) ? ' · ' . h($author['contact']) : '' ?>">
                            <i class="fas fa-user-pen me-1 opacity-50"></i><?= h($author['name'] ?? '') ?>
                        </span>
                    <?php endforeach; ?>
                    <?php if (!empty($libraryMetadata['compatible_misp_version'])): ?>
                        <span class="badge rounded-pill border bg-body-tertiary text-body-emphasis fw-normal" title="<?= h(__('Minimum MISP version')) ?>">
                            <i class="fas fa-code-branch me-1 opacity-50"></i><?= h(__('MISP %s+', $libraryMetadata['compatible_misp_version'])) ?>
                        </span>
                    <?php endif; ?>
                    <?php foreach (($libraryMetadata['tags'] ?? []) as $keyword): ?>
                        <span class="badge rounded-pill border bg-body text-body-secondary fw-normal">
                            <i class="fas fa-hashtag me-1 opacity-50"></i><?= h($keyword) ?>
                        </span>
                    <?php endforeach; ?>
                </div>
            </div>
        <?php endif; ?>

    </div>
</div>

<script>
(function () {
    document.querySelectorAll('[data-tpl-tab]:not([data-tpl-bound])').forEach(function (link) {
        link.setAttribute('data-tpl-bound', '');
        link.addEventListener('click', function (event) {
            var tab = document.querySelector('.nav-link[href="#tab-' + link.dataset.tplTab + '"]');
            if (tab && window.bootstrap) {
                event.preventDefault();
                bootstrap.Tab.getOrCreateInstance(tab).show();
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }
        });
    });
})();
</script>
