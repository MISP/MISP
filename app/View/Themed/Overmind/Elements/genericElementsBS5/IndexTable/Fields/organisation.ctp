<?php
$orgs = Hash::extract($row, $field['data_path']);

if (!empty($orgs) && !isset($orgs[0])) {
    $orgs = [$orgs];
}

if (!empty($orgs)):
?>

<div class="d-flex flex-column gap-1">

<?php foreach ($orgs as $org): ?>

    <?php if (!empty($org['id']) && !empty($org['name'])): ?>

        <div class="d-inline-flex align-items-center gap-2 text-nowrap">

            <?php
            $logoUrl = $baseurl . '/organisations/getOrgLogo/' . h($org['id']);
            ?>

            <img src="<?= $logoUrl ?>"
                 alt="<?= h($org['name']) ?>"
                 height="24"
                 class="rounded"
                 onerror="this.style.display='none'">

            <a href="<?= $baseurl ?>/organisations/view/<?= h($org['id']) ?>"
               class="text-decoration-none fw-semibold text-primary">

                <?= h($org['name']) ?>

            </a>

        </div>

    <?php endif; ?>

<?php endforeach; ?>

</div>

<?php endif; ?>