<h4 class="h6 fw-semibold mb-3"><?= __('File field properties') ?></h4>
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
        <input type="checkbox" id="et-prop-file-mandatory"
               data-et-field="mandatory" class="form-check-input">
        <label class="form-check-label small" for="et-prop-file-mandatory">
            <?= __('Mandatory') ?>
        </label>
    </div>
    <div class="form-check">
        <input type="checkbox" id="et-prop-file-repeatable"
               data-et-field="repeatable" class="form-check-input">
        <label class="form-check-label small" for="et-prop-file-repeatable">
            <?= __('Repeatable (user can upload multiple files)') ?>
        </label>
    </div>
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1">
        <?= __('Store uploaded files as') ?>
    </label>
    <select data-et-field="as" class="form-select form-select-sm bg-light">
        <option value="attachment">
            <?= __('attachment — general-purpose file attribute') ?>
        </option>
        <option value="malware-sample">
            <?= __('malware-sample — encrypted / quarantined sample') ?>
        </option>
    </select>
</div>
