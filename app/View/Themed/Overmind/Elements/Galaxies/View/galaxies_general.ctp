<?php

$iconClass = !empty($data['icon']) ? $this->FontAwesome->getClass($data['icon']) : 'fas fa-shapes';

$palette = $this->GalaxyColour->palette($data['name'] ?? '');

$killChain = '';
if (isset($data['kill_chain_order']) && !empty($data['kill_chain_order'])) {
    $killChain = json_encode($data['kill_chain_order'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
}

$formatDate = function ($value) {
    $digits = preg_replace('/\D/', '', (string)$value);
    if ($digits === '' || (int)$digits === 0) {
        return '<span class="text-muted">' . __('N/A') . '</span>';
    }
    return $this->Time->time($value);
};

$descParts = [];
$descParts[] = '<span>'
    . '<i class="fas fa-clock me-1 opacity-50"></i>'
    . $formatDate($data['created'] ?? null)
    . '</span>';
$descParts[] = '<span>'
    . '<i class="fas fa-edit me-1 opacity-50"></i>'
    . $formatDate($data['modified'] ?? null)
    . '</span>';
$headerDescription = '<span class="d-inline-flex gap-3 flex-wrap">'
    . implode('', $descParts)
    . '</span>';
$this->set('headerDescription', $headerDescription);
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
                <div class="fw-bold fs-4 lh-1"><?= h($data['name'] ?? '') ?></div>
                <?php if (!empty($data['namespace'])): ?>
                    <div class="text-muted small mt-1">
                        <i class="fas fa-folder-tree me-1 opacity-50"></i><?= h($data['namespace']) ?>
                    </div>
                <?php endif; ?>
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
            <div class="col-md-8">
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
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Version') ?>
                </div>

                <?= $this->element('genericElementsBS5/Badges/version',
                    [
                        'version' => $data['version'],
                    ]
                ); ?>
            </div>

            <!-- CREATOR ORG -->
            <?php if (!empty($data['Orgc'])): ?>
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Creator Org') ?>
                </div>

                <div class="d-flex align-items-center gap-2">
                    <?= $this->OrgImg->getOrgLogoV2($data['Orgc'], 24, false); ?>
                    <?= h($data['Orgc']['name'] ?? '') ?>
                </div>
            </div>
            <?php endif; ?>

            <!-- DEFAULT -->
            <div class="col-md-4">
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

            <!-- ENABLED -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Enabled') ?>
                </div>

                <?= $this->element('genericElementsBS5/Badges/boolean',
                    [
                        'boolean' => $data['enabled'],
                        'full' => false
                    ]
                ); ?>
            </div>

            <!-- LOCAL -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Local only') ?>
                </div>

                <?= $this->element('genericElementsBS5/Badges/boolean',
                    [
                        'boolean' => $data['local_only'],
                        'full' => false
                    ]
                ); ?>
            </div>

        </div>

        <!-- KILL CHAIN ORDER -->
        <?php if (!empty($killChain)): ?>
            <div class="mt-4">
                <button class="btn btn-sm btn-light d-flex align-items-center gap-2"
                        type="button" data-bs-toggle="collapse" data-bs-target="#galaxyKillChain">
                    <i class="fas fa-sitemap"></i> <?= __('Kill chain order') ?>
                    <i class="fas fa-chevron-down small"></i>
                </button>
                <div class="collapse mt-2" id="galaxyKillChain">
                    <pre class="bg-light border rounded p-3 mb-0"><code><?= h($killChain) ?></code></pre>
                </div>
            </div>
        <?php endif; ?>

    </div>
</div>
