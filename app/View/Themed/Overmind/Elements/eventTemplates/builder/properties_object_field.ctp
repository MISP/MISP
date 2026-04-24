<h4 class="h6 fw-semibold mb-3"><?= __('Object field properties') ?></h4>
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
        <input type="checkbox" id="et-prop-obj-mandatory"
               data-et-field="mandatory" class="form-check-input">
        <label class="form-check-label small" for="et-prop-obj-mandatory">
            <?= __('Mandatory') ?>
        </label>
    </div>
    <div class="form-check">
        <input type="checkbox" id="et-prop-obj-repeatable"
               data-et-field="repeatable" class="form-check-input">
        <label class="form-check-label small" for="et-prop-obj-repeatable">
            <?= __('Repeatable (user can add multiple object instances)') ?>
        </label>
    </div>
</div>
<hr>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1">
        <?= __('Object template') ?> <span class="text-danger">*</span>
    </label>
    <div class="d-flex align-items-center gap-2 flex-wrap">
        <button type="button" class="btn btn-sm btn-outline-secondary"
                data-et-open-ot-picker>
            <i class="fas fa-search me-1"></i><?= __('Choose…') ?>
        </button>
        <span class="et-ot-picker-current small fw-semibold">
            <span data-et-ot-display="name">
                <em class="text-muted"><?= __('(none selected)') ?></em>
            </span>
            <span data-et-ot-display="version" class="text-muted ms-1"></span>
            <span data-et-ot-display="meta" class="text-muted ms-1"></span>
        </span>
    </div>
    <div class="form-text small">
        <?= __('Opens a searchable list of active object templates on this instance.') ?>
    </div>
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1"><?= __('Current uuid') ?></label>
    <input type="text" data-et-field="object_template.uuid"
           class="form-control form-control-sm bg-light" readonly>
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1"><?= __('Pinned version') ?></label>
    <input type="text" data-et-field="object_template.pinned_version"
           class="form-control form-control-sm bg-light" readonly>
</div>
<hr>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1">
        <?= __('Relations to include in the user form') ?>
    </label>
    <div class="et-relations-panel">
        <div class="et-relations-empty text-muted fst-italic small py-2">
            <?= __('Pick an object template above to choose which relations the user will see.') ?>
        </div>
        <div class="et-relations-controls small mb-1" style="display:none;">
            <a href="#" data-et-relations-all><?= __('Select all') ?></a>
            <span class="text-muted mx-1">·</span>
            <a href="#" data-et-relations-none><?= __('Select none') ?></a>
            <span class="text-muted ms-2">
                <?= __('Empty selection = show all relations (object-template default).') ?>
            </span>
        </div>
        <div class="et-relations-list border rounded"
             style="display:none; max-height:260px; overflow-y:auto;"></div>
    </div>
</div>
