<?php
/*
 * Who made a record, who holds it, and how far it travels: the creator and
 * owner organisations beside the distribution level.
 *
 *   $orgc          array     the creator organisation (id, uuid, name, …); it
 *                            carries the reader's grade when `$orgGrading` is set
 *   $org           array     the owner; named as holding the record when it
 *                            differs from the creator
 *   $user          array     the creating user, shown when it carries an email
 *   $contributors  array     organisations that proposed changes, id => name
 *   $distribution  int|null  0-5
 *   $sharingGroup  array     the sharing group at level 4 (`org_count` adds a chip)
 *   $link          bool      link the organisations, user and sharing group
 *                            (default true; false for a remote record whose
 *                            ids mean nothing here)
 *   $noOrgText     string    shown when there is neither organisation
 *   $inherited     array     at level 5, what the record follows:
 *                            ['distribution', 'sharingGroup', 'label', 'url'];
 *                            the card then shows that level as the effective one
 *   $outliers      array     what is shared more narrowly than the record,
 *                            one ['level' => 0-5, 'text' => '3 attributes',
 *                            'url' => filtered list] per chip
 *   $markings      array     the marking taxonomies the reader's profile
 *                            declares (`declared`), the tags carrying them
 *                            (`present`, each with its `tag`) and the pinned
 *                            ones the record lacks (`absent`, each with its
 *                            `key`); the section shows when one is declared
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
$inheritedFrom = null;
if ($distribution !== null && (int)$distribution === 5 && !empty($inherited)) {
    $inheritedFrom = $inherited;
    $distribution = $inherited['distribution'] ?? null;
    $sharingGroup = $inherited['sharingGroup'] ?? [];
}
$isSharingGroup = $distribution !== null && (int)$distribution === 4;
$level = $this->DistributionLevel->get($distribution);
$sharingGroup = $isSharingGroup ? ($sharingGroup ?? []) : [];

$distributionMeta = [];
if ($inheritedFrom) {
    $distributionMeta[] = '<i class="fas fa-code-fork me-1 opacity-75"></i>' . (empty($inheritedFrom['url'])
        ? h($inheritedFrom['label'])
        : '<a class="text-reset" href="' . h($inheritedFrom['url']) . '">' . h($inheritedFrom['label']) . '</a>');
}
if (!empty($sharingGroup['name'])) {
    $distributionMeta[] = $link && !empty($sharingGroup['id'])
        ? '<a class="fw-semibold text-decoration-none" href="' . h($baseurl . '/sharing_groups/view/' . $sharingGroup['id']) . '">' . h($sharingGroup['name']) . '</a>'
        : '<span class="fw-semibold text-primary">' . h($sharingGroup['name']) . '</span>';
} elseif ($isSharingGroup) {
    $distributionMeta[] = '<span class="fst-italic">' . __('Sharing group not visible to you') . '</span>';
} elseif (!$inheritedFrom) {
    $distributionMeta[] = h($level['sub']);
}

$labelClass = 'text-body-secondary text-uppercase fw-bold';
$labelStyle = 'font-size:.7rem;';

$mainOrg = !empty($orgc['name']) ? $orgc : $org;
$contributors = $contributors ?? [];
$grading = $orgGrading ?? null;
$gradable = $this->OrgGrade->enabled($grading);

$orgLink = function (array $organisation, $class, $style = '') use ($baseurl, $link) {
    $style = $style === '' ? '' : ' style="' . $style . '"';
    if (!$link || empty($organisation['id'])) {
        return '<span class="' . $class . '"' . $style . '>' . h($organisation['name']) . '</span>';
    }
    return sprintf(
        '<a class="%s"%s href="%s">%s</a>',
        $class,
        $style,
        h($baseurl . '/organisations/view/' . $organisation['id']),
        h($organisation['name'])
    );
};
$avatar = function (array $organisation) {
    $logo = $this->OrgImg->getOrgLogoV2($organisation, 20, false);
    if ($logo !== '') {
        return '<span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-circle overflow-hidden bg-body"'
            . ' style="width:20px;height:20px;">' . $logo . '</span>';
    }
    $palette = $this->GalaxyColour->palette($organisation['name']);
    return sprintf(
        '<span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-circle"'
        . ' style="width:20px;height:20px;font-size:.6rem;background:%s;color:white;"><i class="fas fa-building"></i></span>',
        h($palette['solidBg'])
    );
};

$meta = [];
if (!$sameOrg && !empty($orgc['name']) && !empty($org['name'])) {
    $meta[] = __('held here by %s', $orgLink($org, 'fw-semibold text-reset'));
}
if (!empty($user['email'])) {
    $meta[] = __('created by %s', $link && !empty($user['id'])
        ? sprintf('<a class="text-reset" href="%s">%s</a>', h($baseurl . '/admin/users/view/' . $user['id']), h($user['email']))
        : h($user['email']));
}

$contributorChip = function ($id, $name) use ($avatar, $baseurl, $link) {
    $palette = $this->GalaxyColour->palette($name);
    return sprintf(
        '<%1$s class="d-inline-flex align-items-center gap-1 flex-shrink-0 rounded-pill ps-1 pe-2 text-nowrap text-decoration-none"'
        . ' style="background:%2$s;color:%3$s;"%4$s data-chip>%5$s%6$s</%1$s>',
        $link ? 'a' : 'span',
        h($palette['tintBg']),
        h($palette['badgeText']),
        $link ? ' href="' . h($baseurl . '/organisations/view/' . (int)$id) . '"' : '',
        $avatar(['id' => $id, 'name' => $name]),
        h($name)
    );
};

/*
 * One line of chips under a section's head: the chips that do not fit go
 * behind "+N" (the script at the end of the card), whose menu lists them all.
 * width:0 keeps the chips out of the column's width; min-width fills it again.
 */
$chipRow = function ($label, $description, array $chips, array $menuItems) use ($labelClass, $labelStyle) {
    $items = '';
    foreach ($menuItems as $item) {
        $items .= '<li>' . $item . '</li>';
    }
    return '<div class="d-flex align-items-center gap-1 mt-2 small" style="width:0;min-width:100%;" data-chip-row>'
        . '<span class="' . $labelClass . ' me-1 flex-shrink-0" style="' . $labelStyle . '" title="' . h($description) . '">' . h($label) . '</span>'
        . '<div class="d-flex flex-nowrap gap-1 overflow-hidden min-w-0" data-chip-strip>' . implode('', $chips) . '</div>'
        . '<div class="dropdown flex-shrink-0 d-none" data-chip-more>'
        . '<button type="button" class="btn btn-link btn-sm p-0 px-1 text-decoration-none" data-bs-toggle="dropdown" aria-expanded="false">'
        . '+<span data-chip-hidden></span></button>'
        . '<ul class="dropdown-menu"><li><h6 class="dropdown-header">' . h($label) . '</h6></li>'
        . '<li><p class="px-3 mb-1 small text-body-secondary">' . h($description) . '</p></li>' . $items . '</ul>'
        . '</div></div>';
};

$contributorRow = '';
if (!empty($contributors)) {
    $chips = [];
    $items = [];
    foreach ($contributors as $contribId => $contribName) {
        $chips[] = $contributorChip($contribId, $contribName);
        $contribAvatar = $avatar(['id' => $contribId, 'name' => $contribName]);
        $items[] = $link
            ? '<a class="dropdown-item d-flex align-items-center gap-2" href="' . h($baseurl . '/organisations/view/' . (int)$contribId) . '">'
                . $contribAvatar . h($contribName) . '</a>'
            : '<span class="dropdown-item-text d-flex align-items-center gap-2">' . $contribAvatar . h($contribName) . '</span>';
    }
    $contributorRow = $chipRow(__('Contributors'), __('Organisations that proposed changes.'), $chips, $items);
}

$outlierRow = '';
if (!empty($outliers)) {
    $chips = [];
    $items = [];
    foreach ($outliers as $outlier) {
        $outlierLevel = $this->DistributionLevel->get($outlier['level']);
        $chips[] = sprintf(
            '<a class="d-inline-flex align-items-center gap-1 flex-shrink-0 rounded-pill px-2 text-nowrap text-decoration-none"'
            . ' href="%s" title="%s" style="background:%s;color:%s;" data-chip><i class="%s"></i>%s</a>',
            h($outlier['url']),
            h($outlierLevel['label'] . ' — ' . __('Show only these')),
            h($this->DistributionLevel->themed($outlierLevel, 'bg')),
            h($this->DistributionLevel->themed($outlierLevel, 'fg')),
            h($outlierLevel['icon']),
            h($outlier['text'])
        );
        $items[] = sprintf(
            '<a class="dropdown-item d-flex align-items-center gap-2" href="%s"><i class="%s fa-fw" style="color:%s;"></i>'
            . '<span class="fw-semibold">%s</span><span class="text-body-secondary">%s</span></a>',
            h($outlier['url']),
            h($outlierLevel['icon']),
            h($this->DistributionLevel->themed($outlierLevel, 'fg')),
            h($outlier['text']),
            h($outlierLevel['label'])
        );
    }
    $outlierRow = $chipRow(__('Restricted'), __('Shared more narrowly than this record; pick one to list only those.'), $chips, $items);
}
?>

<?= $gradable ? $this->OrgGrade->config($grading) : '' ?>
<style>
    /*
     * The organisation column is as wide as its name and the held / created
     * line, never narrower than the name, and at most half the card once the
     * columns sit side by side. A name is only cut where it would squeeze the
     * distribution below 10rem and the marking below its widest tag (~6rem).
     */
    .ownership-card { container-type: inline-size; }
    @media (min-width: 768px) {
        .ownership-org { max-width: 50%; min-width: min-content; }
        .ownership-org-name { max-width: calc(100cqw - 21rem - 56px); }
        .ownership-dist { min-width: 10rem; }
    }
</style>
<div class="card mb-3 shadow-sm ownership-card" data-tour="ownership">
    <div class="card-body py-2 d-flex flex-column flex-md-row gap-2 gap-md-3">

        <div class="ownership-org" style="flex:0 0 auto;">
            <?php if (empty($mainOrg['name'])): ?>
                <span class="text-body-secondary fst-italic small"><?= h($noOrgText ?? __('No organisation set')) ?></span>
            <?php else: ?>
                <div class="d-flex align-items-center gap-3 min-w-0">
                    <span class="position-relative d-inline-flex flex-shrink-0<?= $gradable ? ' og-mark me-0' : '' ?>">
                        <span class="d-inline-flex align-items-center justify-content-center rounded-3 overflow-hidden bg-primary-subtle text-primary"
                              style="width:40px;height:40px;font-size:1.15rem;">
                            <?= $this->OrgImg->getOrgLogoV2($mainOrg, 28) ?: '<i class="misp-icon misp-icon-organisation misp-simple"></i>' ?>
                        </span>
                        <?= $this->OrgGrade->badge($mainOrg, $grading, 'large') ?>
                    </span>
                    <div class="min-w-0">
                        <?= $orgLink(
                            $mainOrg,
                            'ownership-org-name d-block text-truncate fw-bold lh-sm link-primary link-underline-opacity-0 link-underline-opacity-100-hover',
                            'font-size:1.15rem;'
                        ) ?>
                        <?php if (!empty($meta)): ?>
                            <?php // The grid lets this line widen the column without ever holding it wider than the name. ?>
                            <div class="d-grid" style="grid-template-columns:minmax(0,max-content);">
                                <div class="text-body-secondary text-truncate lh-sm" style="font-size:.74rem;"><?= implode(' &middot; ', $meta) ?></div>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
                <?= $contributorRow ?>
            <?php endif; ?>
        </div>

        <div class="vr d-none d-md-block flex-shrink-0 opacity-100" style="background-color:var(--bs-border-color);"></div>
        <hr class="d-md-none my-0">

        <div class="ownership-dist min-w-0" style="flex:1 1 0%;">
            <div class="d-flex flex-wrap align-items-start gap-2">
                <div class="d-flex align-items-center gap-3 min-w-0" style="flex:1 1 auto;">
                    <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3"
                          style="width:40px;height:40px;font-size:1.15rem;background:<?= h($this->DistributionLevel->themed($level, 'bg')) ?>;color:<?= h($this->DistributionLevel->themed($level, 'fg')) ?>;">
                        <i class="<?= h($level['icon']) ?>"></i>
                    </span>
                    <div class="min-w-0">
                        <div class="text-truncate fw-bold lh-sm" style="font-size:1.15rem;color:<?= h($this->DistributionLevel->themed($level, 'fg')) ?>;">
                            <?= h($level['label']) ?>
                        </div>
                        <div class="text-body-secondary text-truncate lh-sm" style="font-size:.74rem;" title="<?= h($level['sub']) ?>">
                            <?= implode(' &middot; ', $distributionMeta) ?>
                        </div>
                    </div>
                </div>
                <?php if (isset($sharingGroup['org_count'])): ?>
                    <span class="badge rounded-pill border bg-body-tertiary text-body-secondary fw-normal flex-shrink-0">
                        <i class="fas fa-building me-1 opacity-50"></i>
                        <?= h(__n('%s organisation', '%s organisations', $sharingGroup['org_count'], $sharingGroup['org_count'])) ?>
                    </span>
                <?php endif; ?>
            </div>
            <?= $outlierRow ?>
        </div>

        <?php if (!empty($markings['declared'])): ?>
            <div class="vr d-none d-md-block flex-shrink-0 opacity-100" style="background-color:var(--bs-border-color);"></div>
            <hr class="d-md-none my-0">

            <div style="flex:0 1 auto;">
                <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Marking') ?></div>
                <div class="d-flex flex-wrap align-items-center gap-1">
                    <?php foreach ($markings['present'] ?? [] as $item): ?>
                        <?= $this->TagChip->chip($item['tag'], [
                            'searchUrl' => '',
                            'inline' => true,
                        ]) ?>
                        <?php if (!empty($item['tag']['event_id'])): ?>
                            <?= $this->element('Events/View/extension_origin', [
                                'event_id' => $item['tag']['event_id'],
                                'compact' => true,
                                'only_foreign' => true,
                            ]) ?>
                        <?php endif; ?>
                    <?php endforeach; ?>
                    <?php foreach ($markings['absent'] ?? [] as $missing): ?>
                        <span class="d-inline-flex align-items-center gap-1 small px-2 border rounded text-body-secondary"
                              style="--bs-border-style:dashed;"
                              title="<?= h(__('Pinned by your analyst profile, not on this record')) ?>">
                            <i class="fas fa-thumbtack fa-xs"></i><?= h($missing['key']) ?>
                        </span>
                    <?php endforeach; ?>
                    <?php if (empty($markings['present']) && empty($markings['absent'])): ?>
                        <span class="text-body-secondary small"><?= __('None') ?></span>
                    <?php endif; ?>
                </div>
            </div>
        <?php endif; ?>

    </div>
</div>
<?php if ($contributorRow !== '' || $outlierRow !== ''): ?>
<script>
(function () {
    document.querySelectorAll('[data-chip-row]:not([data-chip-row-bound])').forEach(function (row) {
        row.setAttribute('data-chip-row-bound', '');
        var strip = row.querySelector('[data-chip-strip]');
        var chips = strip.querySelectorAll('[data-chip]');
        var more = row.querySelector('[data-chip-more]');
        var hiddenCount = row.querySelector('[data-chip-hidden]');
        // Keep the chips that fit on the line; the rest go behind "+N".
        var fit = function () {
            chips.forEach(function (chip) { chip.classList.remove('d-none'); });
            more.classList.add('d-none');
            if (strip.scrollWidth <= strip.clientWidth) {
                return;
            }
            more.classList.remove('d-none');
            var hidden = 0;
            for (var i = chips.length - 1; i >= 0 && strip.scrollWidth > strip.clientWidth; i--) {
                chips[i].classList.add('d-none');
                hidden++;
            }
            hiddenCount.textContent = hidden;
        };
        fit();
        if (window.ResizeObserver) {
            new ResizeObserver(fit).observe(row);
        }
    });
})();
</script>
<?php endif; ?>
