<?php
/*
 * An attribute's relation inside its object: the type's chip, its colours
 * inverted.
 *
 * Expected:
 * $relation (string)
 */

$relation = isset($relation) ? (string)$relation : '';
if ($relation === '') {
    return;
}
?>

<span class="d-inline-flex align-items-center">
    <p class="om-relation mb-0" title="<?= h(__('Object relation')) ?>"><?= h($relation) ?></p>
</span>
