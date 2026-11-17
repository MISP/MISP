<?php
/*
 * A list of organisations, each drawn by Badges/organisation.
 *
 * Config:
 *   $field['data_path'] array of orgs (id or uuid, name)
 */
$orgList = Hash::get($row, $field['data_path']);
if (empty($orgList)) {
    return;
}
?>
<div class="d-flex flex-wrap align-items-center column-gap-3 row-gap-1">
    <?php foreach ($orgList as $org): ?>
        <?= $this->element('genericElementsBS5/Badges/organisation', ['org' => $org]) ?>
    <?php endforeach; ?>
</div>
