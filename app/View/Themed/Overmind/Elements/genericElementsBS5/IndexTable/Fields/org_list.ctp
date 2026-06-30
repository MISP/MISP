<?php
/*
 * org_list.ctp
 *
 * Renders a list of organisation logos (with a name-badge fallback when
 * no logo image is available).
 *
 * Expected:
 *  $field['data_path'] => array of org arrays, each with 'id' (or 'uuid')
 *                         and 'name'.
 */

$orgList = Hash::get($row, $field['data_path']);

if (empty($orgList)) {
    return;
}
?>

<div class="d-flex flex-wrap align-items-center gap-1">
    <?php foreach ($orgList as $org): ?>
        <?php
        $orgId = !empty($org['id'])
            ? $org['id']
            : (!empty($org['uuid']) ? $org['uuid'] : null);
        $logo = $this->OrgImg->getOrgLogoV2($org, 24);
        ?>
        <?php if (!empty($logo)): ?>
            <?= $logo ?>
        <?php else: ?>
            <a href="<?= $baseurl ?>/organisations/view/<?= h($orgId) ?>"
               class="badge bg-light text-dark border text-decoration-none"
               title="<?= h($org['name'] ?? '') ?>">
                <?= h($org['name'] ?? $orgId) ?>
            </a>
        <?php endif; ?>
    <?php endforeach; ?>
</div>
