<?php
$sharingGroup = $sg['SharingGroup'] ?? [];
$creator = $sg['Organisation'] ?? [];
$syncOrg = is_array($sharingGroup['sync_org'] ?? null) ? $sharingGroup['sync_org'] : [];

$labelClass = 'text-body-secondary text-uppercase fw-bold';
$labelStyle = 'font-size:.7rem;';
$tileStyle = 'width:1.75rem;height:1.75rem;';

$flags = [
    [
        'on' => !empty($sharingGroup['active']),
        'colour' => 'success',
        'icon' => 'fas fa-hand-pointer',
        'label' => [__('Selectable'), __('Not selectable')],
        'sub' => [__('Offered as a distribution'), __('Hidden from the distribution pickers')],
    ],
    [
        'on' => !empty($sharingGroup['roaming']),
        'colour' => 'info',
        'icon' => 'fas fa-street-view',
        'label' => [__('Roaming'), __('Bound to instances')],
        'sub' => [__('Follows its members to any instance'), __('Only reaches the listed instances')],
    ],
    [
        'on' => !empty($sharingGroup['local']),
        'colour' => 'primary',
        'icon' => 'fas fa-house',
        'label' => [__('Local'), __('Synchronised')],
        'sub' => [__('Created here, sync cannot change it'), __('Received from another instance')],
    ],
];

$orgRow = function (array $organisation, $role) use ($baseurl, $tileStyle) {
    if (empty($organisation['name'])) {
        return '';
    }
    return sprintf(
        '<div class="d-flex align-items-center gap-2 min-w-0" style="flex:1 1 13rem;">'
        . '<span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 border bg-body-tertiary overflow-hidden" style="%s">%s</span>'
        . '<div class="min-w-0"><a class="d-block fw-semibold lh-sm text-truncate text-decoration-none" href="%s">%s</a>'
        . '<div class="small text-body-secondary text-truncate">%s</div></div></div>',
        $tileStyle,
        $this->OrgImg->getOrgLogoV2($organisation, 20, false) ?: '<i class="fas fa-building text-body-secondary"></i>',
        h($baseurl . '/organisations/view/' . $organisation['id']),
        h($organisation['name']),
        h($role)
    );
};
?>
<div class="card mb-3 shadow-sm">
    <div class="card-body py-2 d-flex flex-column gap-3">

        <div>
            <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>">
                <i class="misp-icon misp-icon-sharing-group misp-simple text-accent me-1"></i><?= __('Sharing group') ?>
            </div>
            <?php if (trim($sharingGroup['description'] ?? '') !== ''): ?>
                <div class="border-start border-3 border-primary bg-primary-subtle bg-opacity-25 rounded-end px-3 py-2 text-break">
                    <?= nl2br(h($sharingGroup['description'])) ?>
                </div>
            <?php else: ?>
                <span class="text-body-secondary fst-italic small"><?= __('No description') ?></span>
            <?php endif; ?>
            <?php if (trim($sharingGroup['releasability'] ?? '') !== ''): ?>
                <div class="d-flex gap-2 small mt-2">
                    <span class="text-body-secondary flex-shrink-0"><i class="fas fa-scale-balanced me-1 opacity-50"></i><?= __('Releasability') ?></span>
                    <span class="text-break"><?= nl2br(h($sharingGroup['releasability'])) ?></span>
                </div>
            <?php endif; ?>
        </div>

        <div>
            <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Settings') ?></div>
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

        <div>
            <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Provenance') ?></div>
            <div class="d-flex flex-wrap row-gap-2 column-gap-3">
                <?= $orgRow($creator, __('Creator')) ?>
                <?= $orgRow($syncOrg, __('Synchronised by')) ?>
            </div>
        </div>

    </div>
</div>
