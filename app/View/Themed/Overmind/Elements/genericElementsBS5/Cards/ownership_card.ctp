<?php
/*
 * Who made a record, who holds it, and how far it travels: the creator and
 * owner organisations beside the distribution level.
 *
 *   $orgc          array     the creator organisation (id, name, …)
 *   $org           array     the owner; folded into the creator row when equal
 *   $user          array     the creating user, shown when it carries an email
 *   $distribution  int|null  0-5
 *   $sharingGroup  array     the sharing group at level 4 (`org_count` adds a chip)
 *   $link          bool      link the organisations, user and sharing group
 *                            (default true; false for a remote record whose
 *                            ids mean nothing here)
 *   $noOrgText     string    shown when there is neither organisation
 *   $outliers      array     what is shared more narrowly than the record,
 *                            one ['level' => 0-5, 'text' => '3 attributes',
 *                            'url' => filtered list] per row
 *
 * A detail page does not echo this itself: it passes the same keys as
 * view_layout's `ownership`, which puts the card first in the first tab.
 */
$orgc = $orgc ?? [];
$org = $org ?? [];
$user = $user ?? [];
$link = $link ?? true;
$orgKey = function (array $organisation) {
    return (string)($organisation['id'] ?? $organisation['name'] ?? '');
};
$sameOrg = empty($org) || $orgKey($orgc) === $orgKey($org);

$distribution = $distribution ?? null;
$isSharingGroup = $distribution !== null && (int)$distribution === 4;
$level = $this->DistributionLevel->get($distribution);
$sharingGroup = $isSharingGroup ? ($sharingGroup ?? []) : [];

$tileStyle = 'width:1.75rem;height:1.75rem;';
$labelClass = 'text-body-secondary text-uppercase fw-bold';
$labelStyle = 'font-size:.7rem;';

$orgRow = function (array $organisation, $role, $extraHtml = '') use ($baseurl, $tileStyle, $link) {
    if (empty($organisation['name'])) {
        return '';
    }
    $name = h($organisation['name']);
    $nameHtml = $link && !empty($organisation['id'])
        ? sprintf(
            '<a class="d-block fw-semibold text-truncate text-decoration-none lh-sm" href="%s">%s</a>',
            h($baseurl . '/organisations/view/' . $organisation['id']),
            $name
        )
        : '<span class="d-block fw-semibold text-truncate lh-sm">' . $name . '</span>';
    return sprintf(
        '<div class="d-flex align-items-center gap-2 min-w-0" style="flex:1 1 11rem;">'
        . '<span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 border bg-body-tertiary overflow-hidden"'
        . ' style="%s">%s</span>'
        . '<div class="min-w-0">%s'
        . '<div class="text-body-secondary small text-truncate">%s%s</div>'
        . '</div></div>',
        $tileStyle,
        $this->OrgImg->getOrgLogoV2($organisation, 20, false)
            ?: '<i class="fas fa-building text-body-secondary"></i>',
        $nameHtml,
        h($role),
        $extraHtml
    );
};

$createdByHtml = '';
if (!empty($user['email'])) {
    $createdByHtml = ' &middot; <i class="fas fa-user-pen opacity-50"></i> ' . ($link && !empty($user['id'])
        ? sprintf(
            '<a class="text-decoration-none" href="%s" title="%s">%s</a>',
            h($baseurl . '/admin/users/view/' . $user['id']),
            h(__('Created by')),
            h($user['email'])
        )
        : '<span title="' . h(__('Created by')) . '">' . h($user['email']) . '</span>');
}
?>

<div class="card mb-3 shadow-sm">
    <div class="card-body py-2 d-flex flex-column flex-md-row gap-2 gap-md-3">

        <div class="min-w-0 d-flex flex-column" style="flex:1 3 100%;">
            <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>">
                <?= __('Ownership') ?>
            </div>
            <div class="d-flex flex-wrap row-gap-1 column-gap-3 flex-grow-1 align-items-center align-content-center">
                <?php if (empty($orgc['name']) && empty($org['name'])): ?>
                    <span class="text-body-secondary fst-italic small"><?= h($noOrgText ?? __('No organisation set')) ?></span>
                <?php endif; ?>
                <?= $orgRow($orgc, $sameOrg ? __('Creator & owner') : __('Creator'), $createdByHtml) ?>
                <?php if (!$sameOrg): ?>
                    <?= $orgRow($org, __('Owner')) ?>
                <?php endif; ?>
            </div>
        </div>

        <div class="vr d-none d-md-block"></div>
        <hr class="d-md-none my-0">

        <div class="min-w-0" style="flex:1 2 100%;">
            <div class="d-flex align-items-center justify-content-between gap-2 mb-1">
                <span class="<?= $labelClass ?>" style="<?= $labelStyle ?>"><?= __('Distribution') ?></span>
                <?php if (isset($sharingGroup['org_count'])): ?>
                    <span class="badge rounded-pill border bg-body-tertiary text-body-secondary fw-normal">
                        <i class="fas fa-building me-1 opacity-50"></i>
                        <?= h(__n('%s organisation', '%s organisations', $sharingGroup['org_count'], $sharingGroup['org_count'])) ?>
                    </span>
                <?php endif; ?>
            </div>
            <div class="d-flex flex-wrap row-gap-1 column-gap-3">
                <div class="d-flex align-items-center gap-2 min-w-0" style="flex:1 1 11rem;">
                    <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3"
                          style="<?= $tileStyle ?>background:<?= h($level['bg']) ?>;color:<?= h($level['color']) ?>;">
                        <i class="<?= h($level['icon']) ?>"></i>
                    </span>
                    <div class="min-w-0">
                        <div class="fw-semibold lh-sm"><?= h($level['label']) ?></div>
                        <div class="small text-truncate">
                            <?php if (!empty($sharingGroup['name'])): ?>
                                <?= $this->element('genericElementsBS5/Badges/sharing_group', [
                                    'sharingGroup' => $sharingGroup,
                                    'link' => $link,
                                ]) ?>
                            <?php elseif ($isSharingGroup): ?>
                                <span class="text-body-secondary fst-italic"><?= __('Sharing group not visible to you') ?></span>
                            <?php else: ?>
                                <span class="text-body-secondary"><?= h($level['sub']) ?></span>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
                <?php if (!empty($outliers)): ?>
                    <div class="min-w-0 border-start border-2 border-warning ps-2" style="flex:1 1 11rem;">
                        <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"
                             title="<?= h(__('Shared more narrowly than this event')) ?>">
                            <i class="fas fa-lock text-warning-emphasis me-1"></i><?= __('Restricted further') ?>
                        </div>
                        <?php foreach ($outliers as $outlier): ?>
                            <?php $outlierLevel = $this->DistributionLevel->get($outlier['level']); ?>
                            <a href="<?= h($outlier['url']) ?>"
                               class="d-flex align-items-center gap-2 min-w-0 small lh-sm py-1 link-body-emphasis link-underline-opacity-0 link-underline-opacity-75-hover"
                               title="<?= h(__('Show only these')) ?>">
                                <i class="<?= h($outlierLevel['icon']) ?> fa-fw flex-shrink-0" style="color:<?= h($outlierLevel['color']) ?>;"></i>
                                <span class="fw-semibold text-nowrap"><?= h($outlier['text']) ?></span>
                                <span class="text-body-secondary text-truncate"><?= h($outlierLevel['label']) ?></span>
                                <i class="fas fa-filter fa-xs ms-auto flex-shrink-0 opacity-50"></i>
                            </a>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            </div>
        </div>

    </div>
</div>
