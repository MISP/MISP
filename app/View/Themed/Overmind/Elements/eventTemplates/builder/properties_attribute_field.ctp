<?php
    $categories = isset($attributeCategoryDefinitions)
        ? $attributeCategoryDefinitions
        : [];
?>
<h4 class="h6 fw-semibold mb-3"><?= __('Attribute field properties') ?></h4>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1"><?= __('Stable id') ?></label>
    <input type="text" data-et-field="id"
           class="form-control form-control-sm bg-light" disabled>
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1">
        <?= __('Label') ?> <span class="text-danger">*</span>
    </label>
    <input type="text" data-et-field="label"
           class="form-control form-control-sm bg-light">
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1"><?= __('Help text (Markdown)') ?></label>
    <textarea data-et-field="help" rows="2"
              class="form-control form-control-sm bg-light"></textarea>
</div>
<div class="mb-3">
    <div class="form-check">
        <input type="checkbox" id="et-prop-attr-mandatory"
               data-et-field="mandatory" class="form-check-input">
        <label class="form-check-label small" for="et-prop-attr-mandatory">
            <?= __('Mandatory (user must fill this field)') ?>
        </label>
    </div>
    <div class="form-check">
        <input type="checkbox" id="et-prop-attr-repeatable"
               data-et-field="repeatable" class="form-check-input">
        <label class="form-check-label small" for="et-prop-attr-repeatable">
            <?= __('Repeatable (user can add multiple values)') ?>
        </label>
    </div>
</div>
<hr>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1">
        <?= __('MISP category') ?> <span class="text-danger">*</span>
    </label>
    <select data-et-field="misp.category"
            class="form-select form-select-sm bg-light">
        <option value=""><?= __('— select —') ?></option>
        <?php foreach (array_keys($categories) as $cat): ?>
            <option value="<?= h($cat) ?>"><?= h($cat) ?></option>
        <?php endforeach; ?>
    </select>
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1">
        <?= __('MISP type') ?> <span class="text-danger">*</span>
    </label>
    <select data-et-field="misp.type"
            class="form-select form-select-sm bg-light">
        <option value=""><?= __('— select a category first —') ?></option>
    </select>
    <div class="form-text small">
        <?= __('Types are filtered to the selected category.') ?>
    </div>
</div>
<div class="mb-3">
    <div class="form-check">
        <input type="checkbox" id="et-prop-attr-to-ids"
               data-et-field="misp.to_ids_default" class="form-check-input">
        <label class="form-check-label small" for="et-prop-attr-to-ids">
            <?= __('Default to_ids = true') ?>
        </label>
    </div>
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1"><?= __('Comment template') ?></label>
    <input type="text" data-et-field="misp.comment_template"
           class="form-control form-control-sm bg-light">
    <div class="form-text small">
        <?= __('Pre-filled on the attribute\'s comment field when the user submits.') ?>
    </div>
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1"><?= __('Default value') ?></label>
    <input type="text" data-et-field="misp.default_value"
           class="form-control form-control-sm bg-light">
</div>
