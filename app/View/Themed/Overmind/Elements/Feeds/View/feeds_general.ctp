<?php
$feed = $data['Feed'] ?? [];

$formatLabels = [
    'misp' => 'MISP',
    'freetext' => __('Freetext'),
    'csv' => 'CSV',
];
$sourceLabels = [
    'network' => ['label' => __('Network'), 'icon' => 'globe'],
    'local' => ['label' => __('Local file'), 'icon' => 'hard-drive'],
];
$inputSource = $sourceLabels[$feed['input_source'] ?? ''] ?? null;

$distribution = $feed['distribution'] ?? null;
$isSharingGroup = (int)$distribution === 4;
?>
<div class="card mb-3 shadow-sm">
    <div class="card-body p-4">

        <!-- NAME -->
        <div class="mb-4">
            <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Name') ?></div>
            <div class="fw-semibold fs-5 d-flex align-items-center flex-wrap gap-2">
                <?= h($feed['name'] ?? '') ?>
                <?php if (!empty($feed['default'])): ?>
                    <span class="badge text-bg-light border" title="<?= h(__('Shipped with MISP')) ?>">
                        <i class="fas fa-box me-1"></i><?= __('Default feed') ?>
                    </span>
                <?php endif; ?>
            </div>
        </div>

        <!-- URL -->
        <div class="mb-4">
            <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('URL') ?></div>
            <?php if (!empty($feed['url'])): ?>
                <?= $this->element('genericElementsBS5/Badges/links', [
                    'links' => [$feed['url']],
                    'object' => $feed,
                ]) ?>
            <?php else: ?>
                <div class="text-muted">&mdash;</div>
            <?php endif; ?>
        </div>

        <!-- CUSTOM HEADERS (site admins only — the controller masks the values) -->
        <?php if (!empty($feed['headers'])): ?>
        <div class="mb-4">
            <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('HTTP headers') ?></div>
            <span class="badge bg-secondary-subtle text-secondary-emphasis d-inline-flex align-items-center gap-1"
                  title="<?= h(__('This feed is pulled with custom HTTP headers. Their values are never displayed.')) ?>">
                <i class="fas fa-lock"></i><?= __('Custom headers set') ?>
            </span>
        </div>
        <?php endif; ?>

        <!-- META GRID -->
        <div class="row g-3">

            <!-- ID -->
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1">ID</div>
                <div class="bg-light rounded px-2 py-1 border"><?= h($feed['id'] ?? '') ?></div>
            </div>

            <!-- PROVIDER -->
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Provider') ?></div>
                <div class="bg-light rounded px-2 py-1 border text-truncate">
                    <?= !empty($feed['provider']) ? h($feed['provider']) : '<span class="text-muted">&mdash;</span>' ?>
                </div>
            </div>

            <!-- SOURCE FORMAT -->
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Source format') ?></div>
                <div class="py-1">
                    <?php if (!empty($feed['source_format'])): ?>
                        <?= $this->element('genericElementsBS5/Badges/format', [
                            'formatName' => $formatLabels[$feed['source_format']] ?? $feed['source_format'],
                            'hiddenClass' => '',
                        ]) ?>
                    <?php else: ?>
                        <span class="text-muted">&mdash;</span>
                    <?php endif; ?>
                </div>
            </div>

            <!-- INPUT SOURCE -->
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Input source') ?></div>
                <div class="bg-light rounded px-2 py-1 border d-flex align-items-center gap-2">
                    <i class="fas fa-<?= h($inputSource['icon'] ?? 'question') ?> text-muted"></i>
                    <?= h($inputSource['label'] ?? ($feed['input_source'] ?? '—')) ?>
                </div>
            </div>

            <!-- CREATOR ORG -->
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Creator org') ?></div>
                <?php if (!empty($data['Orgc']['id'])): ?>
                    <?= $this->element('genericElementsBS5/IndexTable/Fields/organisation', [
                        'row' => $data,
                        'field' => ['data_path' => 'Orgc'],
                    ]) ?>
                <?php else: ?>
                    <div class="bg-light rounded px-2 py-1 border text-muted"><?= __('None') ?></div>
                <?php endif; ?>
            </div>

            <!-- DISTRIBUTION -->
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Distribution') ?></div>
                <div class="py-1">
                    <?php if ($distribution !== null && $distribution !== ''): ?>
                        <?= $this->element('genericElementsBS5/Badges/distribution', [
                            'distribution' => (int)$distribution,
                            'full' => true,
                        ]) ?>
                    <?php else: ?>
                        <span class="text-muted">&mdash;</span>
                    <?php endif; ?>
                </div>
            </div>

            <!-- SHARING GROUP (only meaningful at distribution level 4) -->
            <?php if ($isSharingGroup): ?>
            <div class="col-md-6">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Sharing group') ?></div>
                <?php if (!empty($data['SharingGroup']['id'])): ?>
                    <div class="bg-light rounded px-2 py-1 border text-truncate">
                        <a href="<?= h($baseurl . '/sharing_groups/view/' . $data['SharingGroup']['id']) ?>"
                           class="text-decoration-none fw-semibold">
                            <?= h($data['SharingGroup']['name']) ?>
                        </a>
                    </div>
                <?php else: ?>
                    <div class="bg-light rounded px-2 py-1 border text-danger">
                        <?= __('Distribution is set to sharing group, but none is selected.') ?>
                    </div>
                <?php endif; ?>
            </div>
            <?php endif; ?>

        </div>

        <!-- TAGGING: a feed tags its events either with one tag or a collection -->
        <div class="mt-4">
            <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Tags applied to pulled events') ?></div>
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
                <div class="text-muted"><?= __('None') ?></div>
            <?php endif; ?>
        </div>

    </div>
</div>
