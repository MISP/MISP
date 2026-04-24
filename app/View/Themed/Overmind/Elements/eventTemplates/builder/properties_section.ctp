<h4 class="h6 fw-semibold mb-3"><?= __('Section properties') ?></h4>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1"><?= __('Stable id') ?></label>
    <input type="text" data-et-field="id" class="form-control form-control-sm bg-light" disabled>
    <div class="form-text small">
        <?= __('Auto-generated. Referenced by info_template {{field:…}} or object_reference endpoints.') ?>
    </div>
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1">
        <?= __('Label') ?> <span class="text-danger">*</span>
    </label>
    <input type="text" data-et-field="label" class="form-control form-control-sm bg-light">
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1"><?= __('Help text (Markdown)') ?></label>
    <textarea data-et-field="help" rows="3"
              class="form-control form-control-sm bg-light"></textarea>
</div>
