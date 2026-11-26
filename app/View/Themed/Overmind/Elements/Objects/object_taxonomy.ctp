<?php
/**
 * An object's tags and galaxy clusters, drawn like an attribute's.
 *
 * The slot is laid out ahead of the backend: objects carry no tags yet, so
 * both lists come back empty and each shows a dash. Once fetchPaginatedObjects
 * attaches them under the same keys an attribute uses (`ObjectTag` with a
 * nested `Tag`, and `Galaxy`), they render here as they are; the add buttons
 * go on through the `add_tag` / `add_galaxy` options of the two elements.
 *
 * Parameters:
 *   object  array  one entry of $objects
 */
$tags = trim($this->element('genericElementsBS5/IndexTable/Fields/tag_list', [
    'row' => $object,
    'field' => ['data_path' => 'ObjectTag'],
]));
$galaxies = trim($this->element('genericElementsBS5/IndexTable/Fields/galaxy', [
    'row' => $object,
    'field' => ['data_path' => 'Galaxy'],
]));
?>
<div class="ov-obj-taxonomy">
    <div class="ov-obj-taxonomy-group">
        <span class="ov-obj-taxonomy-label">
            <i class="fas fa-tags"></i><?= __('Tags') ?>
        </span>
        <?= $tags !== '' ? $tags : '<span class="ov-obj-taxonomy-empty">&mdash;</span>' ?>
    </div>
    <div class="ov-obj-taxonomy-group">
        <span class="ov-obj-taxonomy-label">
            <i class="fas fa-globe"></i><?= __('Galaxies') ?>
        </span>
        <?= $galaxies !== '' ? $galaxies : '<span class="ov-obj-taxonomy-empty">&mdash;</span>' ?>
    </div>
</div>
