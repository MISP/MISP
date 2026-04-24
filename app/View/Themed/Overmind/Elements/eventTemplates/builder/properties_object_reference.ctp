<h4 class="h6 fw-semibold mb-3"><?= __('Object reference properties') ?></h4>
<div class="alert alert-info py-2 px-3 small mb-3">
    <?= __('Object references are not user-facing; they materialise a relationship between two object fields when the event is created.') ?>
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1"><?= __('Stable id') ?></label>
    <input type="text" data-et-field="id"
           class="form-control form-control-sm bg-light" disabled>
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1">
        <?= __('From (source object field)') ?> <span class="text-danger">*</span>
    </label>
    <select data-et-field="from" data-et-object-field-select
            class="form-select form-select-sm bg-light">
        <option value=""><?= __('— select —') ?></option>
    </select>
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1">
        <?= __('To (target object field)') ?> <span class="text-danger">*</span>
    </label>
    <select data-et-field="to" data-et-object-field-select
            class="form-select form-select-sm bg-light">
        <option value=""><?= __('— select —') ?></option>
    </select>
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1">
        <?= __('Relationship type') ?> <span class="text-danger">*</span>
    </label>
    <input type="text" data-et-field="relationship_type"
           class="form-control form-control-sm bg-light"
           placeholder="has-attachment">
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1"><?= __('Comment') ?></label>
    <input type="text" data-et-field="comment"
           class="form-control form-control-sm bg-light">
</div>
