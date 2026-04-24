<h4 class="h6 fw-semibold mb-3"><?= __('Galaxy field properties') ?></h4>
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
        <input type="checkbox" id="et-prop-gal-mandatory"
               data-et-field="mandatory" class="form-check-input">
        <label class="form-check-label small" for="et-prop-gal-mandatory">
            <?= __('Mandatory') ?>
        </label>
    </div>
    <div class="form-check">
        <input type="checkbox" id="et-prop-gal-multiple"
               data-et-field="multiple" class="form-check-input">
        <label class="form-check-label small" for="et-prop-gal-multiple">
            <?= __('Allow multiple clusters') ?>
        </label>
    </div>
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1">
        <?= __('Restrict to galaxy types') ?>
    </label>
    <div class="d-flex align-items-center gap-2 flex-wrap">
        <button type="button" class="btn btn-sm btn-outline-secondary"
                data-et-open-multipicker="galaxyTypes"
                data-et-multipicker-field="restrict_galaxy_types"
                data-et-multipicker-title="<?= __('Select galaxy types') ?>">
            <i class="fas fa-globe me-1"></i><?= __('Choose…') ?>
        </button>
        <span class="et-multipicker-summary small"
              data-et-multipicker-summary-for="restrict_galaxy_types">
            <em class="text-muted"><?= __('(any galaxy type)') ?></em>
        </span>
    </div>
    <div class="form-text small">
        <?= __('Empty list = the user can pick any galaxy cluster. Otherwise restricted to clusters from the chosen galaxy types.') ?>
    </div>
</div>
