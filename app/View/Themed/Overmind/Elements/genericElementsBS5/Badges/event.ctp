<?php
/**
 * Event badge — canonical rendering for an event reference.
 *
 * Expected variables:
 * - $id   (int|string)  Event id. Required — nothing renders without it.
 * - $name (string|null) Event info / name shown as the subtitle.
 * - $url  (string|null) Link target. Falls back to the canonical
 *                       events/view2 route when omitted.
 * - $org  (array|null)  Owner organisation (id|uuid|name) for the logo/link.
 */
$id = $id ?? null;
if (empty($id)) {
    return;
}
$name = $name ?? null;
$url = !empty($url) ? $url : $baseurl . '/events/view2/' . $id;
$org = !empty($org) ? $org : [];

$orgBlock = '';
if (!empty($org)) {
    $orgId = !empty($org['id'])
        ? $org['id']
        : (!empty($org['uuid']) ? $org['uuid'] : null);
    ob_start();
    ?>
    <div class="d-inline-flex align-items-center gap-1 text-nowrap">
        <?= $this->OrgImg->getOrgLogoV2($org, 20) ?>
        <?php if (!empty($orgId)): ?>
            <a href="<?= $baseurl ?>/organisations/view/<?= h($orgId) ?>"
               class="text-decoration-none fw-semibold"
               style="font-size:.7rem; color:var(--primary);">
                <?= h($org['name'] ?? '') ?>
            </a>
        <?php else: ?>
            <span class="fw-semibold" style="font-size:.7rem; color:var(--primary);">
                <?= h($org['name'] ?? '') ?>
            </span>
        <?php endif; ?>
    </div>
    <?php
    $orgBlock = trim(ob_get_clean());
}
?>

<div class="rounded border">
    <div class="d-flex align-items-center gap-2 px-2 py-1" style="background:rgba(24,146,177,.07); border-bottom:1px solid rgba(24,146,177,.2);">
        <div class="d-flex align-items-center gap-2">
            <span class="fw-semibold text-uppercase" style="font-size:.6rem; letter-spacing:.08em; color:var(--primary);">
                <?= __('Event') ?>
            </span>
        </div>
        <a href="<?= h($url) ?>" class="d-flex align-items-center gap-1 text-decoration-none" style="font-size:.7rem; color:var(--primary);" target="_blank">
            <span class="fw-semibold"><?= sprintf('#%s', h($id)) ?></span>
            <i class="fas fa-arrow-up-right-from-square" style="font-size:.6rem;"></i>
        </a>
        <?php if ($orgBlock !== ''): ?>
            <div class="ms-auto"><?= $orgBlock ?></div>
        <?php endif; ?>
    </div>
    <div class="px-2 py-1 d-flex flex-column gap-2">
    <?php if (!empty($name)): ?>
        <span class="text-muted small"><?= h($name) ?></span>
    <?php endif; ?>
    </div>
</div>
