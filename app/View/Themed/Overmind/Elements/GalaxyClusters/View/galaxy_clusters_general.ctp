<?php
$galaxyName = $data['Galaxy']['name'] ?? $data['Galaxy']['type'] ?? '';
$iconName = $data['Galaxy']['icon'] ?? '';
$iconClass = !empty($iconName) ? $this->FontAwesome->getClass($iconName) : 'fas fa-diagram-project';
$palette = $this->GalaxyColour->palette($galaxyName);

$authors = !empty($data['authors']) ? (is_array($data['authors']) ? implode(', ', $data['authors']) : $data['authors']) : '';
$isDefault = !empty($data['default']);

$sourceHtml = '';
if (!empty($data['source'])) {
    $sourceHtml = filter_var($data['source'], FILTER_VALIDATE_URL)
        ? '<a href="' . h($data['source']) . '" rel="noreferrer noopener" target="_blank">' . h($data['source']) . '</a>'
        : h($data['source']);
}
?>

<div class="card mb-3 shadow-sm">
    <div class="card-body">

        <!-- TITLE -->
        <div class="d-flex align-items-center gap-3 mb-4">
            <span class="d-inline-flex align-items-center justify-content-center rounded-3 shadow-sm flex-shrink-0"
                  style="width:3rem;height:3rem;background:<?= $palette['tintBg'] ?>;color:<?= $palette['tintIcon'] ?>;">
                <i class="<?= h($iconClass) ?> fa-lg"></i>
            </span>
            <div>
                <div class="fw-bold fs-4 lh-1"><?= h($data['value'] ?? '') ?></div>
                <a class="text-muted text-decoration-none small mt-1" href="<?= $baseurl ?>/galaxies/view/<?= h($data['Galaxy']['id'] ?? '') ?>">
                    <i class="fas fa-shapes me-1 opacity-50"></i><?= h($galaxyName) ?>
                </a>
            </div>
        </div>

        <!-- DESCRIPTION -->
        <?php if (!empty($data['description'])): ?>
            <div class="mb-4">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Description') ?></div>
                <div class="bg-light border rounded p-3"><?= nl2br(h($data['description'])) ?></div>
            </div>
        <?php endif; ?>

        <!-- META GRID -->
        <div class="row g-3">

            <!-- ID -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    ID
                </div>

                <div class="d-flex align-items-center gap-2">
                    <div class="bg-light rounded px-2 py-1">
                        <?= h($data['id'] ?? '') ?>
                    </div>
                </div>
            </div>

            <!-- UUID -->
            <div class="col-md-5">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    UUID
                </div>

                <div class="d-flex align-items-center gap-2">

                    <div class="bg-light rounded px-2 py-1" id="uuid-value">
                        <?= h($data['uuid'] ?? '') ?>
                    </div>

                    <!-- COPY BUTTON -->
                    <button
                        class="text-muted border-0 bg-white"
                        onclick="copyToClipboard(this, '<?= h(h($data['uuid'] ?? '')) ?>')"
                        data-bs-toggle="tooltip"
                        title="<?= __('Copy UUID') ?>"
                        aria-label="<?= __('Copy UUID') ?>">
                        <i class="fas fa-copy"></i>
                    </button>

                </div>
            </div>

            <!-- DEFAULT -->
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Default') ?>
                </div>

                <?= $this->element('genericElementsBS5/Badges/default',
                    [
                        'default' => $data['default'],
                        'full' => false
                    ]
                ); ?>
            </div>

            <!-- DISTRIBUTION -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Distribution') ?>
                </div>

                <?= $this->element('genericElementsBS5/Badges/distribution',
                    [
                        'distribution' => $data['distribution'],
                        'full' => true
                    ]
                ); ?>
            </div>

            <!-- VERSION -->
            <div class="col-md-5">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Version') ?>
                </div>

                <?= $this->element('genericElementsBS5/Badges/version',
                    [
                        'version' => $data['version'],
                    ]
                ); ?>
            </div>

            <!-- PUBLISHED -->
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Published') ?>
                </div>

                <?= $this->element('genericElementsBS5/Badges/boolean', [
                    'boolean'    => $data['published'] ?? false,
                    'full'       => true,
                    'true'       => __('Published'),
                    'false'      => __('Unpublished'),
                    'trueColor'  => 'success',
                    'falseColor' => 'warning',
                    'trueIcon'   => 'fa-upload',
                    'falseIcon'  => 'fa-warning',
                ]); ?>
            </div>

            <!-- AUTHORS -->
            <?php if ($authors !== ''): ?>
                <div class="col-md-4">
                    <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Authors') ?></div>
                    <div><?= h($authors) ?></div>
                </div>
            <?php endif; ?>

            <!-- CREATOR ORG -->
            <?php if (!empty($data['Orgc'])): ?>
            <div class="col-md-5">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Creator Org') ?>
                </div>

                <div class="d-flex align-items-center gap-2">
                    <?= $this->OrgImg->getOrgLogoV2($data['Orgc'], 24, false); ?>
                    <?= h($data['Orgc']['name'] ?? '') ?>
                </div>
            </div>
            <?php endif; ?>

            <!-- OWNER ORG -->
            <?php if (!empty($data['Org'])): ?>
                <div class="col-md-3">
                    <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Owner Org') ?></div>
                    <div class="d-flex align-items-center gap-2">
                        <?= $this->OrgImg->getOrgLogoV2($data['Org'], 24, false) ?>
                        <?= h($data['Org']['name'] ?? '') ?>
                    </div>
                </div>
            <?php endif; ?>

            <!-- SOURCE -->
            <?php if ($sourceHtml !== ''): ?>
                <div class="col-md-12">
                    <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Source') ?></div>
                    <div class="text-truncate"><?= $sourceHtml ?></div>
                </div>
            <?php endif; ?>

            <!-- SOURCE -->
            <?php if (!empty($data['tag_name'])): ?>
                <div class="col-md-6">
                    <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Connector tag') ?></div>
                    <code class="bg-light rounded px-2 py-1"><?= h($data['tag_name']) ?></code>
                </div>
            <?php endif; ?>

            <!-- USAGE -->
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Events') ?></div>
                <?php $evCount = (int)($data['tag_count'] ?? 0); ?>
                <?php if (!empty($data['tag_id']) && $evCount > 0): ?>
                    <a class="text-decoration-none" href="<?= $baseurl ?>/events/index/searchtag:<?= h($data['tag_id']) ?>">
                        <span class="badge bg-event"><?= h($evCount) ?></span>
                    </a>
                <?php else: ?>
                    <span class="badge bg-light text-dark border">0</span>
                <?php endif; ?>
            </div>

            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Attributes') ?></div>
                <?php $atCount = (int)($data['tag_att_count'] ?? 0); ?>
                <?php if (!empty($data['tag_id']) && $atCount > 0): ?>
                    <a class="text-decoration-none" href="<?= $baseurl ?>/attributes/index?tags=<?= h($data['tag_id']) ?>">
                        <span class="badge bg-attribute"><?= h($atCount) ?></span>
                    </a>
                <?php else: ?>
                    <span class="badge bg-light text-dark border">0</span>
                <?php endif; ?>
            </div>

        </div>

        <!-- FORK INFO -->
        <?php
        $parent = $data['extended_from']['GalaxyCluster'] ?? null;
        $children = $data['extended_by'] ?? [];
        ?>
        <?php if (!empty($parent) || !empty($children)): ?>
            <hr class="my-3">
            <?php if (!empty($parent)): ?>
                <div class="mb-2">
                    <span class="text-muted small text-uppercase fw-bold me-2"><?= __('Forked from') ?></span>
                    <a class="text-galaxy fw-semibold text-decoration-none"
                       href="<?= $baseurl ?>/galaxy_clusters/view/<?= h($parent['id']) ?>">
                        <i class="fas fa-code-branch me-1"></i><?= h($parent['value']) ?>
                        <span class="text-muted">(v<?= h($data['extends_version'] ?? '') ?>)</span>
                    </a>
                    <?php if (!empty($newVersionAvailable)): ?>
                        <div class="alert alert-warning py-2 mt-2 mb-0 small">
                            <i class="fas fa-triangle-exclamation me-1"></i>
                            <?= __('A new version is available.') ?>
                            <?php echo $this->Form->postLink(
                                __('Update cluster to version %s', h($parent['version'])),
                                $baseurl . '/galaxy_clusters/updateCluster/' . h($data['id']),
                                ['class' => 'alert-link']
                            ); ?>
                        </div>
                    <?php endif; ?>
                </div>
            <?php endif; ?>

            <?php if (!empty($children)): ?>
                <div>
                    <span class="text-muted small text-uppercase fw-bold me-2"><?= __('Forked by') ?></span>
                    <span class="d-inline-flex flex-wrap gap-2">
                        <?php foreach ($children as $child):
                            $cc = $child['GalaxyCluster']; ?>
                            <a class="badge fw-semibold text-decoration-none"
                               style="background:transparent;color:var(--bs-galaxy);border:1px dashed var(--bs-galaxy);"
                               href="<?= $baseurl ?>/galaxy_clusters/view/<?= h($cc['id']) ?>">
                                <i class="fas fa-code-branch me-1"></i><?= h($cc['value']) ?>
                            </a>
                        <?php endforeach; ?>
                    </span>
                </div>
            <?php endif; ?>
        <?php endif; ?>

    </div>
</div>
