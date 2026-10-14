<?php
$collection = $data['Collection'] ?? $data;
$orgc = $collection['Orgc'] ?? [];
$org = $collection['Org'] ?? [];
$creator = $collection['User'] ?? [];
$sameOrg = !empty($orgc['id']) && (string)$orgc['id'] === (string)($org['id'] ?? '');

$distribution = $collection['distribution'] ?? null;
$isSharingGroup = (int)$distribution === 4;
$level = $this->DistributionLevel->get($distribution);
$sharingGroup = $isSharingGroup ? ($collection['SharingGroup'] ?? []) : [];

$tileStyle = 'width:2.25rem;height:2.25rem;';

$orgRow = function (array $organisation, $role, $extraHtml = '') use ($baseurl, $tileStyle) {
    if (empty($organisation['id'])) {
        return '';
    }
    return sprintf(
        '<div class="d-flex align-items-center gap-2 min-w-0">'
        . '<span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 border bg-body-tertiary overflow-hidden"'
        . ' style="%s">%s</span>'
        . '<div class="min-w-0">'
        . '<a class="d-block fw-semibold text-truncate text-decoration-none" href="%s">%s</a>'
        . '<div class="text-body-secondary small text-truncate">%s%s</div>'
        . '</div></div>',
        $tileStyle,
        $this->OrgImg->getOrgLogoV2($organisation, 26, false),
        h($baseurl . '/organisations/view/' . $organisation['id']),
        h($organisation['name'] ?? ''),
        h($role),
        $extraHtml
    );
};

$createdByHtml = '';
if (!empty($creator['email'])) {
    $createdByHtml = sprintf(
        ' &middot; <i class="fas fa-user-pen opacity-50"></i> <a class="text-decoration-none" href="%s" title="%s">%s</a>',
        h($baseurl . '/admin/users/view/' . $creator['id']),
        h(__('Created by')),
        h($creator['email'])
    );
}
?>

<div class="card mb-3 shadow-sm">
    <div class="card-body py-3 d-flex flex-column flex-md-row gap-3">

        <div class="flex-fill min-w-0">
            <div class="text-body-secondary small text-uppercase fw-bold mb-2">
                <?= __('Ownership') ?>
            </div>
            <div class="d-flex flex-column gap-2">
                <?= $orgRow($orgc, $sameOrg ? __('Creator & owner') : __('Creator'), $createdByHtml) ?>
                <?php if (!$sameOrg): ?>
                    <?= $orgRow($org, __('Owner')) ?>
                <?php endif; ?>
            </div>
        </div>

        <div class="vr d-none d-md-block"></div>
        <hr class="d-md-none my-0">

        <div class="flex-fill min-w-0">
            <div class="d-flex align-items-center justify-content-between gap-2 mb-2">
                <span class="text-body-secondary small text-uppercase fw-bold"><?= __('Distribution') ?></span>
                <?php if (isset($sharingGroup['org_count'])): ?>
                    <span class="badge rounded-pill border bg-body-tertiary text-body-secondary fw-normal">
                        <i class="fas fa-building me-1 opacity-50"></i>
                        <?= h(__n('%s organisation', '%s organisations', $sharingGroup['org_count'], $sharingGroup['org_count'])) ?>
                    </span>
                <?php endif; ?>
            </div>
            <div class="d-flex align-items-center gap-2 min-w-0">
                <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3"
                      style="<?= $tileStyle ?>background:<?= h($level['bg']) ?>;color:<?= h($level['color']) ?>;">
                    <i class="<?= h($level['icon']) ?>"></i>
                </span>
                <div class="min-w-0">
                    <div class="fw-semibold"><?= h($level['label']) ?></div>
                    <div class="small text-truncate">
                        <?php if (!empty($sharingGroup['name'])): ?>
                            <?= $this->element('genericElementsBS5/Badges/sharing_group', [
                                'sharingGroup' => $sharingGroup,
                            ]) ?>
                        <?php elseif ($isSharingGroup): ?>
                            <span class="text-body-secondary fst-italic"><?= __('Sharing group not visible to you') ?></span>
                        <?php else: ?>
                            <span class="text-body-secondary"><?= h($level['sub']) ?></span>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>

    </div>
</div>
