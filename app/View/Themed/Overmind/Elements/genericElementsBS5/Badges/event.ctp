<?php
/**
 * Event badge — canonical rendering for an event reference.
 *
 * Expected variables:
 * - $id     (int|string)  Event id. Required — nothing renders without it.
 * - $name   (string|null) Event info / name shown as the subtitle.
 * - $url    (string|null) Link target. Falls back to the canonical
 *                         events/view2 route when omitted.
 * - $org    (array|null)  Owner organisation (id|uuid|name) for the logo/link.
 * - $icon   (string|null) Font Awesome class drawn before the "Event" eyebrow —
 *                         e.g. the direction glyph of an extension relationship.
 * - $accent (array|null)  Replaces the default MISP-blue tint, for a badge that
 *                         has to carry a meaning of its own (the origin colour
 *                         of an extended view, say). Keys, all optional:
 *                           headerBg  header strip background
 *                           bodyBg    card background under the name
 *                           border    card border and header rule
 *                           text      eyebrow, id and org text colour
 */
$id = $id ?? null;
if (empty($id)) {
    return;
}
$name = $name ?? null;
$url = !empty($url) ? $url : $baseurl . '/events/view2/' . $id;
$org = !empty($org) ? $org : [];
$icon = $icon ?? null;
$accent = !empty($accent) ? $accent : [];

$headerBg = $accent['headerBg'] ?? 'rgba(24,146,177,.07)';
$bodyBg = $accent['bodyBg'] ?? 'transparent';
$borderColour = $accent['border'] ?? 'rgba(24,146,177,.2)';
$textColour = $accent['text'] ?? 'var(--primary)';

$cardStyle = sprintf(
    'background:%s;%s',
    $bodyBg,
    empty($accent) ? '' : sprintf('border-color:%s !important;', $borderColour)
);

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
               style="font-size:.7rem; color:<?= h($textColour) ?>;">
                <?= h($org['name'] ?? '') ?>
            </a>
        <?php else: ?>
            <span class="fw-semibold" style="font-size:.7rem; color:<?= h($textColour) ?>;">
                <?= h($org['name'] ?? '') ?>
            </span>
        <?php endif; ?>
    </div>
    <?php
    $orgBlock = trim(ob_get_clean());
}
?>

<div class="rounded border" style="<?= h($cardStyle) ?>">
    <div class="d-flex align-items-center gap-2 px-2 py-1" style="background:<?= h($headerBg) ?>; border-bottom:1px solid <?= h($borderColour) ?>;">
        <div class="d-flex align-items-center gap-1" style="color:<?= h($textColour) ?>;">
            <?php if (!empty($icon)): ?>
                <i class="<?= h($icon) ?>" style="font-size:.65rem;"></i>
            <?php endif; ?>
            <span class="fw-semibold text-uppercase" style="font-size:.6rem; letter-spacing:.08em;">
                <?= __('Event') ?>
            </span>
        </div>
        <a href="<?= h($url) ?>" class="d-flex align-items-center gap-1 text-decoration-none" style="font-size:.7rem; color:<?= h($textColour) ?>;" target="_blank">
            <span class="fw-semibold"><?= sprintf('#%s', h($id)) ?></span>
            <i class="fas fa-arrow-up-right-from-square" style="font-size:.6rem;"></i>
        </a>
        <?php if ($orgBlock !== ''): ?>
            <div class="ms-auto"><?= $orgBlock ?></div>
        <?php endif; ?>
    </div>
    <div class="px-2 py-1 d-flex flex-column gap-2">
    <?php if (!empty($name)): ?>
        <span class="small fw-bold"><?= h($name) ?></span>
    <?php endif; ?>
    </div>
</div>
