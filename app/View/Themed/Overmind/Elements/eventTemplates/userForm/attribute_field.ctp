<?php
    $id = isset($element['id']) ? (string)$element['id'] : '';
    $label = isset($element['label']) ? (string)$element['label'] : $id;
    $help = isset($element['help']) ? (string)$element['help'] : '';
    $mandatory = !empty($element['mandatory']);
    $repeatable = !empty($element['repeatable']);
    $misp = isset($element['misp']) && is_array($element['misp']) ? $element['misp'] : [];
    $defaultValue = isset($misp['default_value']) ? (string)$misp['default_value'] : '';
    $typeHint = isset($misp['type']) ? (string)$misp['type'] : '';
    $categoryHint = isset($misp['category']) ? (string)$misp['category'] : '';
?>
<div class="et-field et-attribute-field mb-3"
     data-et-element-id="<?= h($id) ?>"
     data-et-element-type="attribute_field"
     data-et-mandatory="<?= $mandatory ? '1' : '0' ?>"
     data-et-repeatable="<?= $repeatable ? '1' : '0' ?>">
    <label for="et-input-<?= h($id) ?>" class="form-label fw-semibold mb-1">
        <?= h($label) ?>
        <?php if ($mandatory): ?>
            <span class="text-danger" title="<?= __('Mandatory') ?>">*</span>
        <?php endif; ?>
        <span class="text-muted small fw-normal">
            (<?= h($categoryHint . ' / ' . $typeHint) ?>)
        </span>
    </label>
    <?php if ($help !== ''): ?>
        <div class="et-help text-muted small mb-1">
            <?= $this->EventTemplateMarkdown->render($help) ?>
        </div>
    <?php endif; ?>
    <div class="et-entries">
        <div class="et-entry d-flex align-items-center gap-2 mb-1">
            <input type="text" id="et-input-<?= h($id) ?>"
                   class="form-control bg-light et-value"
                   data-et-path="<?= h($id) ?>"
                   value="<?= h($defaultValue) ?>">
            <?php if ($repeatable): ?>
                <button type="button"
                        class="btn btn-sm btn-outline-danger et-remove-entry"
                        style="display:none;"
                        title="<?= __('Remove') ?>">
                    <i class="fas fa-times"></i>
                </button>
            <?php endif; ?>
        </div>
    </div>
    <?php if ($repeatable): ?>
        <button type="button" class="btn btn-sm btn-outline-secondary et-add-entry mt-1">
            <i class="fas fa-plus me-1"></i><?= __('Add another') ?>
        </button>
    <?php endif; ?>
</div>
