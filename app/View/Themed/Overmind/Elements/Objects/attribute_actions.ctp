<?php
/**
 * The 3-dots action menu of one object attribute.
 *
 * Shared by the two renderings of the object index — the accordion's attribute
 * table and the card view — so the two can never end up offering a different
 * set of actions, or differing on which of them an ACL closes.
 *
 * The `obj-attr-actions` class is load-bearing: the script at the bottom of
 * Elements/Objects/index.ctp re-instantiates these toggles with Popper's fixed
 * strategy, so the menu escapes the .table-responsive scroll box that would
 * otherwise clip it against the next object's card.
 *
 * Parameters:
 *   attr               array  the attribute
 *   canEdit            bool   may modify the object's event
 *   enrichmentEnabled  bool   Plugin.Enrichment_services_enable
 *   cortexEnabled      bool   Plugin.Cortex_services_enable
 *
 * Read from the view: $baseurl, $me.
 */
$attrId = (int)$attr['id'];
$attrDeleted = !empty($attr['deleted']);
?>
<div class="dropdown">
    <button
        class="btn btn-sm btn-light p-1 obj-attr-actions"
        type="button"
        data-bs-toggle="dropdown"
        aria-expanded="false"
        title="<?= h(__('Attribute actions')) ?>">
        <i class="fa-solid fa-ellipsis-vertical fs-5"></i>
    </button>
    <ul class="dropdown-menu dropdown-menu-end shadow-sm">
        <li>
            <a class="dropdown-item justify-content-start"
               href="#"
               onclick="event.preventDefault(); copyValueToClipboard('<?= h($attr['uuid'] ?? '') ?>', '<?= h(__('UUID copied to clipboard')) ?>');">
                <i class="fas fa-copy me-2"></i>
                <?= __('Copy UUID') ?>
            </a>
        </li>
        <?php if (!empty($me['Role']['perm_add']) && !$attrDeleted): ?>
        <li>
            <a class="dropdown-item justify-content-start"
               href="#"
               onclick="event.preventDefault(); openModal('<?= $baseurl ?>/shadow_attributes/edit/<?= $attrId ?>');">
                <i class="fas fa-comment-dots me-2"></i>
                <?= __('Propose change') ?>
            </a>
        </li>
        <?php endif; ?>
        <?php if ($canEdit && !empty($enrichmentEnabled) && !$attrDeleted): ?>
        <li>
            <a class="dropdown-item justify-content-start"
               href="#"
               onclick="event.preventDefault(); openModal('<?= $baseurl ?>/events/queryEnrichment/<?= $attrId ?>/0/Enrichment/Attribute');">
                <i class="fas fa-wand-magic-sparkles text-enrichment me-2"></i>
                <?= __('Enrich') ?>
            </a>
        </li>
        <?php endif; ?>
        <?php if ($canEdit && !empty($cortexEnabled) && !$attrDeleted): ?>
        <li>
            <a class="dropdown-item justify-content-start"
               href="#"
               onclick="event.preventDefault(); openModal('<?= $baseurl ?>/events/queryEnrichment/<?= $attrId ?>/0/Cortex/Attribute');">
                <i class="fas fa-eye me-2"></i>
                <?= __('Enrich (Cortex)') ?>
            </a>
        </li>
        <?php endif; ?>
        <?php if ($canEdit): ?>
        <li><hr class="dropdown-divider"></li>
        <li>
            <a class="dropdown-item justify-content-start"
               href="<?= $baseurl ?>/attributes/edit/<?= $attrId ?>"
               onclick="event.preventDefault(); openModal('<?= $baseurl ?>/attributes/edit/<?= $attrId ?>');">
                <i class="fas fa-pen-to-square me-2"></i>
                <?= __('Edit') ?>
            </a>
        </li>
        <li>
            <a class="dropdown-item text-danger justify-content-start"
               href="<?= $baseurl ?>/attributes/delete/<?= $attrId ?>"
               onclick="event.preventDefault(); openModal('<?= $baseurl ?>/attributes/delete/<?= $attrId ?>', 'md');">
                <i class="fas fa-trash me-2"></i>
                <?= __('Delete') ?>
            </a>
        </li>
        <?php endif; ?>
        <?= $this->element('AnalystData/add_controls', [
            'objectType' => 'Attribute',
            'objectUuid' => $attr['uuid'] ?? '',
            'mode' => 'menu_items',
        ]) ?>
    </ul>
</div>
